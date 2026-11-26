use std::cell::Cell as BudgetCell;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Align, Block, Cell, Document, ImageRef, Inline, SafeUrl, Style};

/// The deepest structure (counting list items, table rows and cells as levels) that
/// serializing or deserializing a [`Document`] accepts. Deeper input fails instead of
/// recursing.
pub const WIRE_MAX_DEPTH: usize = 128;

#[derive(Serialize, Deserialize)]
enum Node {
    Paragraph {
        align: Align,
        children: u32,
    },
    Heading {
        level: u8,
        align: Align,
        children: u32,
    },
    Quote {
        children: u32,
    },
    List {
        ordered: bool,
        items: u32,
    },
    Item {
        children: u32,
    },
    Table {
        rows: u32,
    },
    Row {
        cells: u32,
    },
    Cell {
        header: bool,
        children: u32,
    },
    Preformatted(String),
    Image(ImageRef),
    Divider,
    Text {
        text: String,
        style: Style,
    },
    Link {
        href: SafeUrl,
        children: u32,
    },
    LineBreak,
}

#[derive(Serialize, Deserialize)]
struct Wire {
    version: u16,
    blocks: u32,
    #[serde(deserialize_with = "bounded_vec")]
    nodes: Vec<Node>,
}

thread_local! {
    static BUDGET: BudgetCell<Option<usize>> = const { BudgetCell::new(None) };
}

/// Runs `f` with a decode budget of `elements`: every sequence element read by
/// [`bounded_vec`] (and every node of a [`Document`](crate::Document)) on this thread takes
/// one, and decoding fails as soon as the budget is spent, before more elements are
/// allocated. Without a budget, decoding is unbounded. Budgets do not nest: the inner one
/// replaces the outer one until it ends.
///
/// A small wire element can become a much larger value in memory (a 1-byte divider becomes
/// about 120 bytes as a wire node and a block), so a size limit on the encoded input alone does
/// not bound the memory decoding takes; a budget does.
pub fn with_decode_budget<R>(elements: usize, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<usize>);
    impl Drop for Restore {
        fn drop(&mut self) {
            BUDGET.with(|b| b.set(self.0));
        }
    }
    let _restore = Restore(BUDGET.with(|b| b.replace(Some(elements))));
    f()
}

fn budget_left() -> Option<usize> {
    BUDGET.with(BudgetCell::get)
}

fn take_budget() -> bool {
    BUDGET.with(|b| match b.get() {
        None => true,
        Some(0) => false,
        Some(left) => {
            b.set(Some(left - 1));
            true
        }
    })
}

/// Deserializes a `Vec<T>` under the budget of [`with_decode_budget`]: a declared length
/// above what is left fails at once, and every element takes one from the budget. Use with
/// `#[serde(deserialize_with = "rinse_doc_model::bounded_vec")]` on every sequence a worker
/// response holds, except byte buffers (whose memory equals their encoded size).
pub fn bounded_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for Bounded<T> {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a sequence within the decode budget")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let exceeded = || A::Error::custom("decode budget exceeded");
            let hint = seq.size_hint().unwrap_or(0);
            if budget_left().is_some_and(|left| hint > left) {
                return Err(exceeded());
            }
            let mut out = Vec::with_capacity(hint.min(4_096));
            loop {
                if !take_budget() {
                    return match seq.next_element::<serde::de::IgnoredAny>()? {
                        None => Ok(out),
                        Some(_) => Err(exceeded()),
                    };
                }
                match seq.next_element()? {
                    Some(value) => out.push(value),
                    None => return Ok(out),
                }
            }
        }
    }

    deserializer.deserialize_seq(Bounded(PhantomData))
}

struct TooDeep;

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn flatten_blocks(blocks: &[Block], depth: usize, out: &mut Vec<Node>) -> Result<(), TooDeep> {
    if depth > WIRE_MAX_DEPTH {
        return Err(TooDeep);
    }
    for block in blocks {
        match block {
            Block::Paragraph { align, inlines } => {
                out.push(Node::Paragraph {
                    align: *align,
                    children: count(inlines.len()),
                });
                flatten_inlines(inlines, depth + 1, out)?;
            }
            Block::Heading {
                level,
                align,
                inlines,
            } => {
                out.push(Node::Heading {
                    level: *level,
                    align: *align,
                    children: count(inlines.len()),
                });
                flatten_inlines(inlines, depth + 1, out)?;
            }
            Block::Quote(children) => {
                out.push(Node::Quote {
                    children: count(children.len()),
                });
                flatten_blocks(children, depth + 1, out)?;
            }
            Block::List { ordered, items } => {
                out.push(Node::List {
                    ordered: *ordered,
                    items: count(items.len()),
                });
                for item in items {
                    out.push(Node::Item {
                        children: count(item.len()),
                    });
                    flatten_blocks(item, depth + 2, out)?;
                }
            }
            Block::Table { rows } => {
                out.push(Node::Table {
                    rows: count(rows.len()),
                });
                for row in rows {
                    out.push(Node::Row {
                        cells: count(row.len()),
                    });
                    for cell in row {
                        out.push(Node::Cell {
                            header: cell.header,
                            children: count(cell.blocks.len()),
                        });
                        flatten_blocks(&cell.blocks, depth + 3, out)?;
                    }
                }
            }
            Block::Preformatted(text) => out.push(Node::Preformatted(text.clone())),
            Block::Image(image) => out.push(Node::Image(image.clone())),
            Block::Divider => out.push(Node::Divider),
        }
    }
    Ok(())
}

fn flatten_inlines(inlines: &[Inline], depth: usize, out: &mut Vec<Node>) -> Result<(), TooDeep> {
    if depth > WIRE_MAX_DEPTH {
        return Err(TooDeep);
    }
    for inline in inlines {
        match inline {
            Inline::Text { text, style } => out.push(Node::Text {
                text: text.clone(),
                style: *style,
            }),
            Inline::Link { href, inlines } => {
                out.push(Node::Link {
                    href: href.clone(),
                    children: count(inlines.len()),
                });
                flatten_inlines(inlines, depth + 1, out)?;
            }
            Inline::LineBreak => out.push(Node::LineBreak),
        }
    }
    Ok(())
}

struct Reader {
    nodes: std::vec::IntoIter<Node>,
}

impl Reader {
    fn next(&mut self) -> Result<Node, TooDeep> {
        self.nodes.next().ok_or(TooDeep)
    }

    fn remaining(&self) -> usize {
        self.nodes.len()
    }

    fn blocks(&mut self, n: u32, depth: usize) -> Result<Vec<Block>, TooDeep> {
        if depth > WIRE_MAX_DEPTH || n as usize > self.remaining() {
            return Err(TooDeep);
        }
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let block = match self.next()? {
                Node::Paragraph { align, children } => Block::Paragraph {
                    align,
                    inlines: self.inlines(children, depth + 1)?,
                },
                Node::Heading {
                    level,
                    align,
                    children,
                } => Block::Heading {
                    level,
                    align,
                    inlines: self.inlines(children, depth + 1)?,
                },
                Node::Quote { children } => Block::Quote(self.blocks(children, depth + 1)?),
                Node::List { ordered, items } => {
                    if items as usize > self.remaining() {
                        return Err(TooDeep);
                    }
                    let mut list = Vec::with_capacity(items as usize);
                    for _ in 0..items {
                        let Node::Item { children } = self.next()? else {
                            return Err(TooDeep);
                        };
                        list.push(self.blocks(children, depth + 2)?);
                    }
                    Block::List {
                        ordered,
                        items: list,
                    }
                }
                Node::Table { rows } => {
                    if rows as usize > self.remaining() {
                        return Err(TooDeep);
                    }
                    let mut table = Vec::with_capacity(rows as usize);
                    for _ in 0..rows {
                        let Node::Row { cells } = self.next()? else {
                            return Err(TooDeep);
                        };
                        if cells as usize > self.remaining() {
                            return Err(TooDeep);
                        }
                        let mut row = Vec::with_capacity(cells as usize);
                        for _ in 0..cells {
                            let Node::Cell { header, children } = self.next()? else {
                                return Err(TooDeep);
                            };
                            row.push(Cell {
                                header,
                                blocks: self.blocks(children, depth + 3)?,
                            });
                        }
                        table.push(row);
                    }
                    Block::Table { rows: table }
                }
                Node::Preformatted(text) => Block::Preformatted(text),
                Node::Image(image) => Block::Image(image),
                Node::Divider => Block::Divider,
                _ => return Err(TooDeep),
            };
            out.push(block);
        }
        Ok(out)
    }

    fn inlines(&mut self, n: u32, depth: usize) -> Result<Vec<Inline>, TooDeep> {
        if depth > WIRE_MAX_DEPTH || n as usize > self.remaining() {
            return Err(TooDeep);
        }
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let inline = match self.next()? {
                Node::Text { text, style } => Inline::Text { text, style },
                Node::Link { href, children } => Inline::Link {
                    href,
                    inlines: self.inlines(children, depth + 1)?,
                },
                Node::LineBreak => Inline::LineBreak,
                _ => return Err(TooDeep),
            };
            out.push(inline);
        }
        Ok(out)
    }
}

impl Serialize for Document {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut nodes = Vec::new();
        flatten_blocks(&self.blocks, 1, &mut nodes)
            .map_err(|_| serde::ser::Error::custom("document nested too deeply"))?;
        Wire {
            version: self.version,
            blocks: count(self.blocks.len()),
            nodes,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Document {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = Wire::deserialize(deserializer)?;
        let mut reader = Reader {
            nodes: wire.nodes.into_iter(),
        };
        let malformed = || serde::de::Error::custom("malformed document structure");
        let blocks = reader.blocks(wire.blocks, 1).map_err(|_| malformed())?;
        if reader.remaining() != 0 {
            return Err(malformed());
        }
        Ok(Document {
            version: wire.version,
            blocks,
        })
    }
}
