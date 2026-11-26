use rinse_doc_model::{
    Align, Block, Cell, Document, ImageRef, Inline, Limits, SCHEMA_VERSION, SafeUrl, Style,
};

enum Kind {
    Root,
    Quote,
    Item,
    Cell { header: bool },
}

enum Frame {
    Blocks {
        kind: Kind,
        blocks: Vec<Block>,
    },
    List {
        ordered: bool,
        items: Vec<Vec<Block>>,
    },
    Table {
        rows: Vec<Vec<Cell>>,
    },
    Row {
        cells: Vec<Cell>,
    },
}

/// Builds a [`Document`] from a stream of structural events while staying inside the limits:
/// containers that would nest too deeply are flattened, and once a count limit is reached every
/// further event is ignored and [`Builder::truncated`] becomes true.
pub(crate) struct Builder {
    limits: Limits,
    frames: Vec<Frame>,
    para: Vec<Inline>,
    para_align: Align,
    heading: Option<u8>,
    link: Option<(SafeUrl, Vec<Inline>)>,
    pending_space: bool,
    blocks: usize,
    inlines: usize,
    text: usize,
    links: usize,
    images: usize,
    full: bool,
    truncated: bool,
}

impl Builder {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            limits,
            frames: vec![Frame::Blocks {
                kind: Kind::Root,
                blocks: Vec::new(),
            }],
            para: Vec::new(),
            para_align: Align::Start,
            heading: None,
            link: None,
            pending_space: false,
            blocks: 0,
            inlines: 0,
            text: 0,
            links: 0,
            images: 0,
            full: false,
            truncated: false,
        }
    }

    /// Whether no more content will be accepted.
    pub(crate) fn is_full(&self) -> bool {
        self.full
    }

    /// The number of open frames, to pass to [`Builder::close_to`] later.
    pub(crate) fn mark(&self) -> usize {
        self.frames.len()
    }

    fn stop(&mut self) {
        self.full = true;
        self.truncated = true;
    }

    fn block_depth(&self) -> usize {
        self.frames
            .iter()
            .filter(|f| matches!(f, Frame::Blocks { .. }))
            .count()
    }

    fn can_nest(&self) -> bool {
        self.block_depth() + 3 <= self.limits.depth()
    }

    fn take_block(&mut self) -> bool {
        if self.full || self.blocks >= self.limits.max_blocks {
            self.stop();
            return false;
        }
        self.blocks += 1;
        true
    }

    /// Counts a list item, table row or cell against the block limit, as validation does.
    fn take_container(&mut self) -> bool {
        if self.blocks >= self.limits.max_blocks {
            self.stop();
            return false;
        }
        self.blocks += 1;
        true
    }

    fn take_inline(&mut self) -> bool {
        if self.full || self.inlines >= self.limits.max_inlines {
            self.stop();
            return false;
        }
        self.inlines += 1;
        true
    }

    fn ensure_blocks(&mut self) {
        loop {
            match self.frames.last() {
                Some(Frame::List { .. }) => self.frames.push(Frame::Blocks {
                    kind: Kind::Item,
                    blocks: Vec::new(),
                }),
                Some(Frame::Table { .. }) => self.frames.push(Frame::Row { cells: Vec::new() }),
                Some(Frame::Row { .. }) => self.frames.push(Frame::Blocks {
                    kind: Kind::Cell { header: false },
                    blocks: Vec::new(),
                }),
                _ => return,
            }
        }
    }

    fn push_block(&mut self, block: Block) {
        self.ensure_blocks();
        if let Some(Frame::Blocks { blocks, .. }) = self.frames.last_mut() {
            blocks.push(block);
        }
    }

    /// Opens a quote and returns the mark to close it with; `None` when it would nest too deeply or the block limit is reached, in which
    /// case the content flows into the current container.
    pub(crate) fn open_quote(&mut self) -> Option<usize> {
        self.flush();
        if !self.can_nest() || !self.take_block() {
            return None;
        }
        self.ensure_blocks();
        let mark = self.frames.len();
        self.frames.push(Frame::Blocks {
            kind: Kind::Quote,
            blocks: Vec::new(),
        });
        Some(mark)
    }

    /// Opens a list; `None` when it cannot be opened.
    pub(crate) fn open_list(&mut self, ordered: bool) -> Option<usize> {
        self.flush();
        if !self.can_nest() || !self.take_block() {
            return None;
        }
        self.ensure_blocks();
        let mark = self.frames.len();
        self.frames.push(Frame::List {
            ordered,
            items: Vec::new(),
        });
        Some(mark)
    }

    /// Opens a list item inside the innermost open list; `None` when no list is open here.
    pub(crate) fn open_item(&mut self) -> Option<usize> {
        self.flush();
        let n = self.frames.len();
        let in_implicit_item = n >= 2
            && matches!(
                self.frames[n - 1],
                Frame::Blocks {
                    kind: Kind::Item,
                    ..
                }
            )
            && matches!(self.frames[n - 2], Frame::List { .. });
        if in_implicit_item {
            self.close_to(n - 1);
        }
        if !matches!(self.frames.last(), Some(Frame::List { .. })) {
            return None;
        }
        let mark = self.frames.len();
        self.frames.push(Frame::Blocks {
            kind: Kind::Item,
            blocks: Vec::new(),
        });
        Some(mark)
    }

    /// Opens a data table; `None` when it cannot be opened.
    pub(crate) fn open_table(&mut self) -> Option<usize> {
        self.flush();
        if !self.can_nest() || !self.take_block() {
            return None;
        }
        self.ensure_blocks();
        let mark = self.frames.len();
        self.frames.push(Frame::Table { rows: Vec::new() });
        Some(mark)
    }

    /// Opens a row in the innermost table; `None` when no table is open here.
    pub(crate) fn open_row(&mut self) -> Option<usize> {
        self.flush();
        let n = self.frames.len();
        if let Some(pos) = self
            .frames
            .iter()
            .rposition(|f| matches!(f, Frame::Table { .. }))
            && self.frames[pos + 1..].iter().all(|f| {
                matches!(
                    f,
                    Frame::Row { .. }
                        | Frame::Blocks {
                            kind: Kind::Cell { .. },
                            ..
                        }
                )
            })
        {
            if pos + 1 < n {
                self.close_to(pos + 1);
            }
            let mark = self.frames.len();
            self.frames.push(Frame::Row { cells: Vec::new() });
            return Some(mark);
        }
        None
    }

    /// Opens a cell in the innermost row; `None` when no table is open here.
    pub(crate) fn open_cell(&mut self, header: bool) -> Option<usize> {
        self.flush();
        if let Some(pos) = self
            .frames
            .iter()
            .rposition(|f| matches!(f, Frame::Row { .. } | Frame::Table { .. }))
            && self.frames[pos + 1..].iter().all(|f| {
                matches!(
                    f,
                    Frame::Blocks {
                        kind: Kind::Cell { .. },
                        ..
                    }
                )
            })
        {
            self.close_to(pos + 1);
            if matches!(self.frames.last(), Some(Frame::Table { .. })) {
                self.frames.push(Frame::Row { cells: Vec::new() });
            }
            let mark = self.frames.len();
            self.frames.push(Frame::Blocks {
                kind: Kind::Cell { header },
                blocks: Vec::new(),
            });
            return Some(mark);
        }
        None
    }

    /// Ends the current paragraph and closes every frame opened after `mark`.
    pub(crate) fn close_to(&mut self, mark: usize) {
        self.flush();
        let mark = mark.max(1);
        while self.frames.len() > mark {
            let Some(frame) = self.frames.pop() else {
                break;
            };
            match frame {
                Frame::Blocks {
                    kind: Kind::Quote,
                    blocks,
                } => {
                    if !blocks.is_empty() {
                        self.push_block(Block::Quote(blocks));
                    }
                }
                Frame::Blocks {
                    kind: Kind::Item,
                    blocks,
                } => match self.frames.last_mut() {
                    Some(Frame::List { .. }) => {
                        if !blocks.is_empty()
                            && self.take_container()
                            && let Some(Frame::List { items, .. }) = self.frames.last_mut()
                        {
                            items.push(blocks);
                        }
                    }
                    _ => {
                        for b in blocks {
                            self.push_block(b);
                        }
                    }
                },
                Frame::Blocks {
                    kind: Kind::Cell { header },
                    blocks,
                } => match self.frames.last_mut() {
                    Some(Frame::Row { cells }) => {
                        if cells.len() >= self.limits.max_table_cols {
                            self.truncated = true;
                        } else if self.take_container()
                            && let Some(Frame::Row { cells }) = self.frames.last_mut()
                        {
                            cells.push(Cell { header, blocks });
                        }
                    }
                    _ => {
                        for b in blocks {
                            self.push_block(b);
                        }
                    }
                },
                Frame::Blocks {
                    kind: Kind::Root, ..
                } => {}
                Frame::Row { cells } => {
                    let room = match self.frames.last() {
                        Some(Frame::Table { rows }) => {
                            Some(rows.len() < self.limits.max_table_rows)
                        }
                        _ => None,
                    };
                    match room {
                        _ if cells.is_empty() => {}
                        Some(false) => self.truncated = true,
                        Some(true) => {
                            if self.take_container()
                                && let Some(Frame::Table { rows }) = self.frames.last_mut()
                            {
                                rows.push(cells);
                            }
                        }
                        None => {}
                    }
                }
                Frame::List { ordered, items } => {
                    if !items.is_empty() {
                        self.push_block(Block::List { ordered, items });
                    }
                }
                Frame::Table { rows } => {
                    if !rows.is_empty() {
                        self.push_block(Block::Table { rows });
                    }
                }
            }
        }
    }

    /// Ends the current paragraph or heading.
    pub(crate) fn boundary(&mut self) {
        self.flush();
    }

    /// Starts a heading; the content until [`Builder::end_heading`] becomes its text.
    pub(crate) fn start_heading(&mut self, level: u8) {
        self.flush();
        self.heading = Some(level.clamp(1, 6));
    }

    /// Ends the heading started last.
    pub(crate) fn end_heading(&mut self) {
        self.flush();
        self.heading = None;
    }

    fn inline_depth_ok(&self, extra: usize) -> bool {
        self.block_depth() + extra <= self.limits.depth()
    }

    fn target(&mut self) -> &mut Vec<Inline> {
        match &mut self.link {
            Some((_, inlines)) => inlines,
            None => &mut self.para,
        }
    }

    fn has_content(&self) -> bool {
        !self.para.is_empty() || self.link.as_ref().is_some_and(|(_, i)| !i.is_empty())
    }

    fn push_text(&mut self, text: &str, style: Style, align: Align) {
        if text.is_empty() || self.full || !self.inline_depth_ok(1) {
            return;
        }
        let remaining = self.limits.max_text_bytes.saturating_sub(self.text);
        let cut = crate::text::cut(text, remaining);
        let was_cut = cut.len() < text.len();
        if !cut.is_empty() {
            if !self.has_content() {
                self.para_align = align;
            }
            let merge =
                matches!(self.target().last(), Some(Inline::Text { style: s, .. }) if *s == style);
            if merge || self.take_inline() {
                self.text += cut.len();
                if let Some(Inline::Text { text: last, .. }) = self.target().last_mut()
                    && merge
                {
                    last.push_str(cut);
                } else {
                    self.target().push(Inline::Text {
                        text: cut.to_owned(),
                        style,
                    });
                }
            }
        }
        if was_cut {
            self.stop();
        }
    }

    /// Adds text with HTML whitespace rules: every run of whitespace becomes one space, and
    /// spaces at the start and end of a paragraph are dropped. The text must already be clean.
    pub(crate) fn text(&mut self, text: &str, style: Style, align: Align) {
        let mut word = String::new();
        for c in text.chars() {
            if c.is_whitespace() {
                if !word.is_empty() {
                    self.emit_word(&word, style, align);
                    word.clear();
                }
                self.pending_space = true;
            } else {
                word.push(c);
            }
        }
        if !word.is_empty() {
            self.emit_word(&word, style, align);
        }
    }

    fn emit_word(&mut self, word: &str, style: Style, align: Align) {
        if self.pending_space && self.has_content() {
            let last_is_break = matches!(self.target().last(), Some(Inline::LineBreak));
            if !last_is_break {
                self.push_text(" ", style, align);
            }
        }
        self.pending_space = false;
        self.push_text(word, style, align);
    }

    /// Adds a line break inside the current paragraph; ignored at its start.
    pub(crate) fn line_break(&mut self) {
        self.pending_space = false;
        if !self.has_content() || !self.inline_depth_ok(1) {
            return;
        }
        if self.take_inline() {
            self.target().push(Inline::LineBreak);
        }
    }

    /// Starts a link; false when links do not fit here, in which case the text stays plain.
    pub(crate) fn start_link(&mut self, href: SafeUrl) -> bool {
        if self.link.is_some() || self.full || !self.inline_depth_ok(2) {
            return false;
        }
        self.link = Some((href, Vec::new()));
        true
    }

    /// Ends the open link, if any.
    pub(crate) fn end_link(&mut self) {
        if let Some((href, inlines)) = self.link.take() {
            self.attach_link(href, inlines);
        }
    }

    fn attach_link(&mut self, href: SafeUrl, mut inlines: Vec<Inline>) {
        while matches!(inlines.last(), Some(Inline::LineBreak)) {
            inlines.pop();
        }
        if inlines.is_empty() {
            return;
        }
        if self.full || self.links >= self.limits.max_links || !self.take_inline() {
            self.truncated = true;
            self.para.extend(inlines);
            return;
        }
        self.links += 1;
        self.para.push(Inline::Link { href, inlines });
    }

    fn flush(&mut self) {
        self.pending_space = false;
        let reopen = self.link.take().map(|(href, inlines)| {
            let keep = href.clone();
            self.attach_link(href, inlines);
            keep
        });
        let mut inlines = std::mem::take(&mut self.para);
        trim_end(&mut inlines);
        if !inlines.is_empty() {
            let block = match self.heading {
                Some(level) => Block::Heading {
                    level,
                    align: self.para_align,
                    inlines,
                },
                None => Block::Paragraph {
                    align: self.para_align,
                    inlines,
                },
            };
            if self.blocks < self.limits.max_blocks {
                self.blocks += 1;
                self.push_block(block);
            } else {
                self.stop();
            }
        }
        self.para_align = Align::Start;
        if let Some(href) = reopen {
            self.link = Some((href, Vec::new()));
        }
    }

    /// Adds a preformatted block of clean multi-line text.
    pub(crate) fn preformatted(&mut self, text: &str) {
        self.flush();
        let text = text.trim_matches('\n');
        if text.is_empty() || self.full || !self.inline_depth_ok(0) {
            return;
        }
        let remaining = self.limits.max_text_bytes.saturating_sub(self.text);
        let cut = crate::text::cut(text, remaining);
        if !cut.is_empty() && self.take_block() {
            self.text += cut.len();
            self.push_block(Block::Preformatted(cut.to_owned()));
        }
        if cut.len() < text.len() {
            self.stop();
        }
    }

    /// Whether another image fits.
    pub(crate) fn image_fits(&self) -> bool {
        !self.full && self.images < self.limits.max_images && self.blocks < self.limits.max_blocks
    }

    /// Adds an image block; its alternative text must already be clean.
    pub(crate) fn image(&mut self, mut image: ImageRef) {
        self.flush();
        if !self.image_fits() {
            self.truncated = true;
            return;
        }
        let remaining = self.limits.max_text_bytes.saturating_sub(self.text);
        image.alt = crate::text::cut(&image.alt, remaining).to_owned();
        if !self.take_block() {
            return;
        }
        self.text += image.alt.len();
        self.images += 1;
        self.push_block(Block::Image(image));
    }

    /// Adds a horizontal rule.
    pub(crate) fn divider(&mut self) {
        self.flush();
        if self.take_block() {
            self.push_block(Block::Divider);
        }
    }

    /// Closes everything and returns the document.
    pub(crate) fn finish(mut self) -> (Document, bool) {
        self.link = None;
        self.close_to(1);
        let blocks = match self.frames.pop() {
            Some(Frame::Blocks { blocks, .. }) => blocks,
            _ => Vec::new(),
        };
        (
            Document {
                version: SCHEMA_VERSION,
                blocks,
            },
            self.truncated,
        )
    }
}

fn trim_end(inlines: &mut Vec<Inline>) {
    loop {
        match inlines.last_mut() {
            Some(Inline::LineBreak) => {
                inlines.pop();
            }
            Some(Inline::Text { text, .. }) => {
                let trimmed = text.trim_end().len();
                if trimmed == 0 {
                    inlines.pop();
                } else {
                    text.truncate(trimmed);
                    return;
                }
            }
            _ => return,
        }
    }
}
