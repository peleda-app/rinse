use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use html5ever::interface::{ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::tendril::{StrTendril, TendrilSink};
use html5ever::{Attribute, ParseOpts, QualName, ns, parse_document};
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use rinse_doc_model::{Align, ImageRef, Style};

use crate::builder::Builder;
use crate::links::{self, Checked};
use crate::text::{clean_inline, clean_multiline};
use crate::{Env, style};

/// Elements deeper than this are skipped with their content.
pub(crate) const MAX_DOM_DEPTH: usize = 512;
/// Nodes visited per HTML part at most.
const MAX_NODES: usize = 400_000;
/// Nodes the HTML parser may create per message, over all parts.
pub(crate) const MAX_PARSED_NODES: usize = 400_000;
/// Bytes of one HTML part that are parsed; the rest is dropped.
pub(crate) const MAX_HTML_BYTES: usize = 4 << 20;
/// Tree depth at which parsing stops. The tree builder scans its stack of open elements on most
/// tags, so an unbounded stack costs quadratic time; the walk ignores anything below
/// [`MAX_DOM_DEPTH`] anyway.
const MAX_PARSE_DEPTH: u32 = 4_096;
/// Input fed to the parser between checks of the node budget and the stop signal.
const FEED_BYTES: usize = 256;
/// Formatting start tags (over all names) that may be open at once in the markup; parsing stops
/// before the one that would exceed it. The tree builder scans its list of active formatting
/// elements on every such tag and rebuilds the list for every new block, so an unbounded list
/// costs quadratic time.
const MAX_OPEN_FORMATTING: usize = 1_000;
const FORMATTING: [&str; 14] = [
    "a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small", "strike", "strong", "tt", "u",
];

/// The length of the prefix of `html` in which at most [`MAX_OPEN_FORMATTING`] formatting
/// elements are open, counting start and end tags per name as written (end tags without a
/// matching start tag count for nothing).
fn formatting_prefix(html: &str) -> usize {
    let bytes = html.as_bytes();
    let mut open = [0usize; FORMATTING.len()];
    let mut total = 0usize;
    let mut i = 0;
    while let Some(p) = html[i..].find('<') {
        let start = i + p;
        let mut j = start + 1;
        let end_tag = bytes.get(j) == Some(&b'/');
        if end_tag {
            j += 1;
        }
        let name_start = j;
        while j < bytes.len() && bytes[j].is_ascii_alphanumeric() && j - name_start < 8 {
            j += 1;
        }
        let terminated = bytes
            .get(j)
            .is_none_or(|b| b.is_ascii_whitespace() || *b == b'>' || *b == b'/');
        if j > name_start && terminated {
            let name = &html[name_start..j];
            if let Some(k) = FORMATTING.iter().position(|f| f.eq_ignore_ascii_case(name)) {
                if end_tag {
                    if open[k] > 0 {
                        open[k] -= 1;
                        total -= 1;
                    }
                } else if total == MAX_OPEN_FORMATTING {
                    return start;
                } else {
                    open[k] += 1;
                    total += 1;
                }
            }
        }
        i = j.max(start + 1);
    }
    html.len()
}
/// Nodes inspected when deciding whether a table holds data or layout.
const TABLE_SCAN: usize = 5_000;
const MAX_PRE_BYTES: usize = 1 << 20;
const MAX_LINK_TEXT: usize = 400;

#[derive(Clone, Copy, Default)]
struct Ctx {
    style: Style,
    align: Align,
    cell_button: bool,
}

#[derive(Default)]
struct Exit {
    mark: Option<usize>,
    heading: bool,
    pre: bool,
    link: bool,
    table: bool,
    boundary: bool,
}

enum Step {
    Enter(Handle, usize),
    Exit(Exit),
}

struct LinkState {
    checked: Checked,
    text: String,
    started: bool,
    button: bool,
    label: Option<String>,
}

const BUTTON_TEXT_GRAPHEMES: usize = 40;

#[derive(Clone, Copy, PartialEq, Eq)]
enum TableMode {
    Data,
    Layout,
}

struct Walker<'e, 'm, 'b> {
    env: &'e mut Env<'m>,
    b: &'b mut Builder,
    styles: Vec<Ctx>,
    tables: Vec<TableMode>,
    pre: usize,
    pre_buf: String,
    link: Option<LinkState>,
}

/// An `RcDom` that creates at most a budget of nodes and no element deeper than
/// [`MAX_PARSE_DEPTH`]. Once either limit is hit, new elements are created detached (so the tree
/// builder keeps working) and every change to the tree is dropped, so memory stays bounded
/// whatever the markup makes the tree builder do. Parse errors are not stored.
struct BoundedDom {
    dom: RcDom,
    left: Cell<usize>,
    over: Cell<bool>,
    depths: RefCell<HashMap<usize, u32>>,
}

fn key(handle: &Handle) -> usize {
    Rc::as_ptr(handle) as usize
}

impl BoundedDom {
    fn depth(&self, handle: &Handle) -> u32 {
        self.depths.borrow().get(&key(handle)).copied().unwrap_or(0)
    }

    /// Records the depth of a node about to be inserted; false (and frozen) when too deep.
    fn place(&self, child: &NodeOrText<Handle>, depth: u32) -> bool {
        if let NodeOrText::AppendNode(node) = child {
            if depth > MAX_PARSE_DEPTH {
                self.over.set(true);
                return false;
            }
            self.depths.borrow_mut().insert(key(node), depth);
        }
        true
    }

    fn take(&self) -> bool {
        if self.over.get() {
            return false;
        }
        match self.left.get() {
            0 => {
                self.over.set(true);
                false
            }
            n => {
                self.left.set(n - 1);
                true
            }
        }
    }

    fn frozen(&self) -> bool {
        self.over.get()
    }
}

impl TreeSink for BoundedDom {
    type Handle = Handle;
    type Output = Self;
    type ElemName<'a> = <RcDom as TreeSink>::ElemName<'a>;

    fn finish(self) -> Self {
        self
    }

    fn parse_error(&self, _msg: Cow<'static, str>) {}

    fn get_document(&self) -> Handle {
        self.dom.get_document()
    }

    fn elem_name<'a>(&'a self, target: &'a Handle) -> Self::ElemName<'a> {
        self.dom.elem_name(target)
    }

    fn create_element(&self, name: QualName, attrs: Vec<Attribute>, flags: ElementFlags) -> Handle {
        if self.take() {
            self.dom.create_element(name, attrs, flags)
        } else {
            self.dom.create_element(name, Vec::new(), flags)
        }
    }

    fn create_comment(&self, text: StrTendril) -> Handle {
        self.take();
        self.dom.create_comment(if self.frozen() {
            StrTendril::new()
        } else {
            text
        })
    }

    fn create_pi(&self, target: StrTendril, data: StrTendril) -> Handle {
        self.take();
        if self.frozen() {
            self.dom.create_pi(StrTendril::new(), StrTendril::new())
        } else {
            self.dom.create_pi(target, data)
        }
    }

    fn append(&self, parent: &Handle, child: NodeOrText<Handle>) {
        if matches!(child, NodeOrText::AppendText(_)) {
            self.take();
        }
        if !self.frozen() && self.place(&child, self.depth(parent) + 1) {
            self.dom.append(parent, child);
        }
    }

    fn append_based_on_parent_node(
        &self,
        element: &Handle,
        prev_element: &Handle,
        child: NodeOrText<Handle>,
    ) {
        if matches!(child, NodeOrText::AppendText(_)) {
            self.take();
        }
        let depth = self.depth(element).max(self.depth(prev_element) + 1);
        if !self.frozen() && self.place(&child, depth) {
            self.dom
                .append_based_on_parent_node(element, prev_element, child);
        }
    }

    fn append_doctype_to_document(
        &self,
        _name: StrTendril,
        _public_id: StrTendril,
        _system_id: StrTendril,
    ) {
    }

    fn get_template_contents(&self, target: &Handle) -> Handle {
        let contents = self.dom.get_template_contents(target);
        let depth = self.depth(target);
        self.depths.borrow_mut().insert(key(&contents), depth);
        contents
    }

    fn same_node(&self, x: &Handle, y: &Handle) -> bool {
        self.dom.same_node(x, y)
    }

    fn set_quirks_mode(&self, mode: QuirksMode) {
        self.dom.set_quirks_mode(mode);
    }

    fn append_before_sibling(&self, sibling: &Handle, new_node: NodeOrText<Handle>) {
        if matches!(new_node, NodeOrText::AppendText(_)) {
            self.take();
        }
        if !self.frozen() && self.place(&new_node, self.depth(sibling)) {
            self.dom.append_before_sibling(sibling, new_node);
        }
    }

    fn add_attrs_if_missing(&self, target: &Handle, attrs: Vec<Attribute>) {
        if !self.frozen() {
            self.dom.add_attrs_if_missing(target, attrs);
        }
    }

    fn remove_from_parent(&self, target: &Handle) {
        if !self.frozen() {
            self.dom.remove_from_parent(target);
        }
    }

    fn reparent_children(&self, node: &Handle, new_parent: &Handle) {
        if !self.frozen() {
            self.dom.reparent_children(node, new_parent);
        }
    }

    fn allow_declarative_shadow_roots(&self, _intended_parent: &Handle) -> bool {
        false
    }
}

/// Parses one HTML part, creating at most `*budget` nodes and taking them from it. Returns the
/// DOM and whether the whole part was parsed within the budget; when it was not, parsing
/// stopped within a few hundred bytes after the budget ran out (or `stop` returned true) and
/// the DOM holds what was built until then.
pub(crate) fn parse(html: &str, budget: &mut usize, stop: &dyn Fn() -> bool) -> (RcDom, bool) {
    let sink = BoundedDom {
        dom: RcDom::default(),
        left: Cell::new(*budget),
        over: Cell::new(false),
        depths: RefCell::new(HashMap::new()),
    };
    let mut parser = parse_document(sink, ParseOpts::default());
    let mut rest = html;
    while !rest.is_empty() && !parser.tokenizer.sink.sink.frozen() && !stop() {
        let chunk = crate::text::cut(rest, FEED_BYTES);
        let chunk = if chunk.is_empty() {
            &rest[..rest.chars().next().map_or(rest.len(), char::len_utf8)]
        } else {
            chunk
        };
        parser.process(StrTendril::from_slice(chunk));
        rest = &rest[chunk.len()..];
    }
    let sink = parser.finish();
    *budget = sink.left.get();
    let complete = !sink.over.get() && rest.is_empty();
    (sink.dom, complete)
}

/// Converts one HTML body part into the document, walking the DOM with an explicit stack.
/// Returns false when the part was cut (too long, or over the parser's node budget), in which
/// case it must not be used for the original HTML.
pub(crate) fn convert(html: &str, env: &mut Env<'_>, b: &mut Builder) -> bool {
    let cut = crate::text::cut(html, MAX_HTML_BYTES);
    let cut = &cut[..formatting_prefix(cut)];
    let (dom, complete) = parse(cut, &mut env.parse_budget, env.stop);
    ld_json(&dom.document, &mut env.hints.ld_json);
    let whole = complete && cut.len() == html.len();
    if !whole {
        env.findings.truncated = true;
    }
    let mark = b.mark();
    let mut walker = Walker {
        env,
        b,
        styles: vec![Ctx::default()],
        tables: Vec::new(),
        pre: 0,
        pre_buf: String::new(),
        link: None,
    };
    walker.run(dom.document.clone());
    walker.finish_link();
    if walker.pre > 0 {
        walker.flush_pre();
    }
    walker.b.close_to(mark);
    whole
}

/// Collects the text of `<script type="application/ld+json">` elements anywhere in the DOM,
/// `<head>` included, before the walk drops every script.
fn ld_json(root: &Handle, out: &mut Vec<String>) {
    let mut stack = vec![root.clone()];
    let mut visited = 0usize;
    while let Some(node) = stack.pop() {
        visited += 1;
        if visited > MAX_NODES || out.len() >= crate::facts::MAX_LD_JSON_SCRIPTS {
            return;
        }
        if let NodeData::Element { name, attrs, .. } = &node.data
            && &*name.local == "script"
        {
            let typed = attr(&attrs.borrow(), "type")
                .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/ld+json"));
            if typed {
                let mut text = String::new();
                for child in node.children.borrow().iter() {
                    if let NodeData::Text { contents } = &child.data
                        && text.len() <= crate::facts::MAX_LD_JSON_BYTES
                    {
                        text.push_str(&contents.borrow());
                    }
                }
                out.push(text);
            }
            continue;
        }
        stack.extend(node.children.borrow().iter().rev().cloned());
    }
}

fn attr(attrs: &[Attribute], name: &str) -> Option<String> {
    attrs
        .iter()
        .find(|a| &*a.name.local == name)
        .map(|a| a.value.to_string())
}

const BLOCKS: &[&str] = &[
    "p",
    "div",
    "section",
    "article",
    "header",
    "footer",
    "main",
    "nav",
    "aside",
    "center",
    "address",
    "figure",
    "figcaption",
    "dl",
    "dt",
    "dd",
    "form",
    "fieldset",
    "legend",
    "details",
    "summary",
    "caption",
    "body",
    "html",
    "hgroup",
    "tbody",
    "thead",
    "tfoot",
];

impl Walker<'_, '_, '_> {
    fn ctx(&self) -> Ctx {
        self.styles.last().copied().unwrap_or_default()
    }

    fn run(&mut self, root: Handle) {
        let mut stack = vec![Step::Enter(root, 0)];
        let mut visited = 0usize;
        while let Some(step) = stack.pop() {
            let (node, depth) = match step {
                Step::Exit(exit) => {
                    self.exit(exit);
                    continue;
                }
                Step::Enter(node, depth) => (node, depth),
            };
            visited += 1;
            if visited > MAX_NODES
                || self.b.is_full()
                || (visited.is_multiple_of(4096) && (self.env.stop)())
            {
                self.env.findings.truncated = true;
                for step in stack.into_iter().rev() {
                    if let Step::Exit(exit) = step {
                        self.exit(exit);
                    }
                }
                return;
            }
            match &node.data {
                NodeData::Document => {
                    for child in node.children.borrow().iter().rev() {
                        stack.push(Step::Enter(child.clone(), depth + 1));
                    }
                }
                NodeData::Text { contents } => self.text(&contents.borrow()),
                NodeData::Element { name, attrs, .. } => {
                    if depth > MAX_DOM_DEPTH {
                        self.env.findings.truncated = true;
                        self.env.no_original = true;
                        continue;
                    }
                    if name.ns != ns!(html) {
                        continue;
                    }
                    let attrs = attrs.borrow();
                    if let Some(exit) = self.enter(&node, &name.local, &attrs) {
                        stack.push(Step::Exit(exit));
                        for child in node.children.borrow().iter().rev() {
                            stack.push(Step::Enter(child.clone(), depth + 1));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn text(&mut self, text: &str) {
        if self.pre > 0 {
            if self.pre_buf.len() < MAX_PRE_BYTES {
                self.pre_buf.push_str(crate::text::cut(text, MAX_PRE_BYTES));
            }
            return;
        }
        let cleaned = clean_inline(text, &mut self.env.findings.body_text);
        if let Some(link) = &mut self.link
            && link.text.len() < MAX_LINK_TEXT
        {
            link.text
                .push_str(crate::text::cut(&cleaned, MAX_LINK_TEXT));
        }
        let ctx = self.ctx();
        self.b.text(&cleaned, ctx.style, ctx.align);
    }

    fn enter(&mut self, node: &Handle, tag: &str, attrs: &[Attribute]) -> Option<Exit> {
        let findings = &mut self.env.findings;
        for a in attrs {
            if a.name.local.len() > 2 && a.name.local.starts_with("on") {
                findings.scripts_removed += 1;
            }
        }
        match tag {
            "script" => {
                findings.scripts_removed += 1;
                return None;
            }
            "style" => {
                let mut css = String::new();
                for child in node.children.borrow().iter() {
                    if let NodeData::Text { contents } = &child.data {
                        css.push_str(&contents.borrow().to_ascii_lowercase());
                    }
                }
                findings.remote_references +=
                    (css.matches("url(").count() + css.matches("@import").count()).min(1000) as u32;
                return None;
            }
            "head" | "title" | "template" | "svg" | "math" | "noscript" | "canvas" | "audio"
            | "video" | "source" | "track" | "map" | "area" | "datalist" | "dialog" | "noembed"
            | "noframes" => return None,
            "iframe" | "frame" | "frameset" | "object" | "embed" | "applet" | "param"
            | "portal" | "input" | "button" | "select" | "textarea" | "option" | "optgroup"
            | "keygen" | "output" | "base" => {
                findings.active_content_removed += 1;
                return None;
            }
            "meta" => {
                if attr(attrs, "http-equiv").is_some_and(|v| v.eq_ignore_ascii_case("refresh")) {
                    findings.active_content_removed += 1;
                }
                return None;
            }
            "link" => {
                if attr(attrs, "href").is_some() {
                    findings.remote_references += 1;
                }
                return None;
            }
            "form" => findings.active_content_removed += 1,
            _ => {}
        }
        let decls = attr(attrs, "style")
            .map(|s| style::declarations(&s))
            .unwrap_or_default();
        if decls.iter().any(|(_, v)| v.contains("url(")) || attr(attrs, "background").is_some() {
            findings.remote_references += 1;
        }
        let hidden = style::hidden(&decls) || attr(attrs, "hidden").is_some();
        if tag == "img" {
            self.image(attrs, &decls, hidden);
            return None;
        }
        if hidden {
            findings.hidden_content += 1;
            return None;
        }
        let ctx = self.element_ctx(tag, attrs, &decls);
        let mut exit = Exit::default();
        match tag {
            "br" => {
                if self.pre > 0 {
                    self.pre_buf.push('\n');
                } else {
                    self.b.line_break();
                }
                return None;
            }
            "hr" => {
                self.b.divider();
                return None;
            }
            "wbr" => return None,
            "a" => {
                if self.link.is_none()
                    && let Some(href) = attr(attrs, "href")
                    && let Some(checked) = links::check(&href, self.env.limits.doc.max_url_len)
                {
                    let started = checked.href.clone().is_some_and(|h| self.b.start_link(h));
                    if checked.warnings.unsupported_scheme_removed
                        && matches!(
                            href.trim().get(..10).map(str::to_ascii_lowercase).as_deref(),
                            Some(s) if s.starts_with("javascript") || s.starts_with("vbscript")
                        )
                    {
                        self.env.findings.scripts_removed += 1;
                    }
                    let button = style::button(&decls)
                        || ctx.cell_button
                        || attr(attrs, "role")
                            .is_some_and(|r| r.trim().eq_ignore_ascii_case("button"));
                    let label = attr(attrs, "aria-label")
                        .and_then(|l| crate::facts::text(&l, 200))
                        .or_else(|| attr(attrs, "title").and_then(|l| crate::facts::text(&l, 200)));
                    self.link = Some(LinkState {
                        checked,
                        text: String::new(),
                        started,
                        button,
                        label,
                    });
                    exit.link = true;
                }
            }
            "pre" | "xmp" | "listing" | "plaintext" => {
                if self.pre == 0 {
                    self.b.boundary();
                }
                self.pre += 1;
                exit.pre = true;
            }
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                self.b.start_heading(tag.as_bytes()[1] - b'0');
                exit.heading = true;
            }
            "blockquote" => {
                exit.mark = self.b.open_quote();
                exit.boundary = true;
            }
            "ul" | "ol" | "menu" | "dir" => {
                exit.mark = self.b.open_list(tag == "ol");
                exit.boundary = true;
            }
            "li" => {
                exit.mark = self.b.open_item();
                exit.boundary = true;
            }
            "table" => {
                let mode = if data_table(node, attrs)
                    && let Some(m) = self.b.open_table()
                {
                    exit.mark = Some(m);
                    TableMode::Data
                } else {
                    TableMode::Layout
                };
                self.tables.push(mode);
                exit.table = true;
                exit.boundary = true;
            }
            "tr" => {
                if self.tables.last() == Some(&TableMode::Data) {
                    exit.mark = self.b.open_row();
                }
                exit.boundary = true;
            }
            "td" | "th" => {
                if self.tables.last() == Some(&TableMode::Data) {
                    exit.mark = self.b.open_cell(tag == "th");
                }
                exit.boundary = true;
            }
            t if BLOCKS.contains(&t) => {
                self.b.boundary();
                exit.boundary = true;
            }
            _ => {}
        }
        self.styles.push(ctx);
        Some(exit)
    }

    fn exit(&mut self, exit: Exit) {
        self.styles.pop();
        if exit.link {
            self.finish_link();
        }
        if exit.pre {
            self.pre = self.pre.saturating_sub(1);
            if self.pre == 0 {
                self.flush_pre();
            }
        }
        if exit.heading {
            self.b.end_heading();
        }
        if let Some(mark) = exit.mark {
            self.b.close_to(mark);
        }
        if exit.table {
            self.tables.pop();
        }
        if exit.boundary {
            self.b.boundary();
        }
    }

    fn finish_link(&mut self) {
        if let Some(link) = self.link.take() {
            if link.started {
                self.b.end_link();
            }
            let info = links::finish(link.checked, &link.text, &mut self.env.findings.body_text);
            if let Some(href) = &info.href {
                let short = !info.text.is_empty()
                    && !rinse_text::normalize_line(&info.text, BUTTON_TEXT_GRAPHEMES)
                        .findings
                        .truncated;
                let hints = &mut self.env.hints.links;
                if hints.len() < crate::facts::MAX_LINK_HINTS || hints.contains_key(href.as_str()) {
                    let hint = hints.entry(href.as_str().to_owned()).or_default();
                    hint.button |= link.button && short;
                    if hint.label.is_none() {
                        hint.label = link.label;
                    }
                }
            }
            self.env.links.add(info);
        }
    }

    fn flush_pre(&mut self) {
        let text = clean_multiline(
            &std::mem::take(&mut self.pre_buf),
            &mut self.env.findings.body_text,
        );
        self.b.preformatted(&text);
    }

    fn element_ctx(&self, tag: &str, attrs: &[Attribute], decls: &[(String, String)]) -> Ctx {
        let mut ctx = self.ctx();
        let s = &mut ctx.style;
        match tag {
            "b" | "strong" | "th" => s.bold = true,
            "i" | "em" | "cite" | "dfn" | "var" => s.italic = true,
            "u" | "ins" => s.underline = true,
            "s" | "strike" | "del" => s.strike = true,
            "code" | "kbd" | "samp" | "tt" => s.code = true,
            "center" => ctx.align = Align::Center,
            "font" => {
                if let Some(tone) = attr(attrs, "color").and_then(|c| style::color(&c)) {
                    s.tone = tone;
                }
            }
            _ => {}
        }
        match tag {
            "td" | "th" => {
                ctx.cell_button = style::button(decls)
                    || attr(attrs, "bgcolor").is_some_and(|c| !c.trim().is_empty())
            }
            "table" => ctx.cell_button = false,
            _ => {}
        }
        if tag != "table"
            && let Some(a) = attr(attrs, "align").and_then(|a| style::align(&a))
        {
            ctx.align = a;
        }
        let s = &mut ctx.style;
        if let Some(b) = style::get(decls, "font-weight").and_then(style::bold) {
            s.bold = b;
        }
        match style::get(decls, "font-style") {
            Some("italic" | "oblique") => s.italic = true,
            Some("normal") => s.italic = false,
            _ => {}
        }
        if let Some(d) = style::get(decls, "text-decoration-line")
            .or_else(|| style::get(decls, "text-decoration"))
        {
            if d.contains("none") {
                s.underline = false;
                s.strike = false;
            }
            if d.contains("underline") {
                s.underline = true;
            }
            if d.contains("line-through") {
                s.strike = true;
            }
        }
        if let Some(tone) = style::get(decls, "color").and_then(style::color) {
            s.tone = tone;
        }
        if let Some(a) = style::get(decls, "text-align").and_then(style::align) {
            ctx.align = a;
        }
        ctx
    }

    fn image(&mut self, attrs: &[Attribute], decls: &[(String, String)], hidden: bool) {
        let Some(src) = attr(attrs, "src") else {
            return;
        };
        let size = |name: &str| {
            attr(attrs, name)
                .and_then(|v| style::pixels(&v))
                .or_else(|| style::get(decls, name).and_then(style::pixels))
        };
        let (w, h) = (size("width"), size("height"));
        let tiny = hidden
            || w.is_some_and(|w| w <= 1.0)
            || h.is_some_and(|h| h <= 1.0)
            || (w.is_some_and(|w| w <= 2.0) && h.is_some_and(|h| h <= 2.0));
        if !self.b.image_fits() {
            self.env.findings.truncated = true;
            return;
        }
        let alt = attr(attrs, "alt").unwrap_or_default();
        let alt = clean_inline(&alt, &mut self.env.findings.body_text);
        let alt: String = alt.split_whitespace().collect::<Vec<_>>().join(" ");
        let alt = crate::text::cut(&alt, 300).to_owned();
        if let Some((id, width, height)) = self.env.resolve_image(&src, tiny) {
            self.b.image(ImageRef {
                id,
                alt,
                width,
                height,
            });
        }
    }
}

fn data_table(table: &Handle, attrs: &[Attribute]) -> bool {
    if attr(attrs, "role").is_some_and(|r| {
        let r = r.to_ascii_lowercase();
        r == "presentation" || r == "none"
    }) {
        return false;
    }
    let bordered = attr(attrs, "border").is_some_and(|b| b.trim() != "0" && !b.trim().is_empty());
    let mut has_th = false;
    let mut max_cells = 0usize;
    let mut stack: Vec<Handle> = table.children.borrow().iter().cloned().collect();
    let mut seen = 0usize;
    while let Some(node) = stack.pop() {
        seen += 1;
        if seen > TABLE_SCAN {
            return false;
        }
        if let NodeData::Element { name, .. } = &node.data {
            match &*name.local {
                "table" => return false,
                "th" => has_th = true,
                "tr" => {
                    let cells = node
                        .children
                        .borrow()
                        .iter()
                        .filter(|c| matches!(&c.data, NodeData::Element { name, .. } if &*name.local == "td" || &*name.local == "th"))
                        .count();
                    max_cells = max_cells.max(cells);
                }
                _ => {}
            }
        }
        stack.extend(node.children.borrow().iter().cloned());
    }
    has_th || (bordered && max_cells >= 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_formatting_is_capped() {
        let bomb = format!(
            "<p>{}</p>",
            (0..2000).map(|i| format!("<b c{i}>")).collect::<String>()
        );
        let n = formatting_prefix(&bomb);
        assert_eq!(bomb[..n].matches("<b ").count(), MAX_OPEN_FORMATTING);
        let honest = "<p><b>x</b> <I>y</I> <a href=x>z</a></p>".repeat(5_000);
        assert_eq!(formatting_prefix(&honest), honest.len());
        let stray = format!("{}{}", "</b>".repeat(5_000), "<b>".repeat(1_500));
        assert!(formatting_prefix(&stray) < stray.len());
    }

    #[test]
    fn node_budget_bounds_the_dom() {
        let html = format!(
            "<p>{}</p>{}",
            (0..900).map(|i| format!("<i c{i}>")).collect::<String>(),
            "<p>x</p>".repeat(2_000)
        );
        let mut budget = 50_000;
        let (_, complete) = parse(&html, &mut budget, &|| false);
        assert!(!complete);
        assert_eq!(budget, 0);
        let mut budget = 50_000;
        let (_, complete) = parse("<p>small</p>", &mut budget, &|| false);
        assert!(complete && budget > 49_000);
        let mut budget = 50_000;
        let (_, complete) = parse(&"<p>x</p>".repeat(1000), &mut budget, &|| true);
        assert!(!complete);
        for tag in ["div", "template", "ul><li"] {
            let mut budget = 400_000;
            let deep = format!("<{tag}>").repeat(MAX_PARSE_DEPTH as usize + 10);
            let (_, complete) = parse(&deep, &mut budget, &|| false);
            assert!(!complete, "{tag}");
        }
    }
}
