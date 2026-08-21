//! Proc-macro backend for the `afterglow` crate. Use `afterglow::html!`, not
//! this crate directly.

use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use quote::{format_ident, quote};

/// JSX-like templating macro producing an `afterglow::Node`.
///
/// # Syntax
///
/// - **Elements**: `<div class="card">...</div>`, self-closing `<br/>`. Tag
///   and attribute names may contain hyphens (`data-id`, `my-widget`).
/// - **Attributes**: `name="literal"`, `name={expr}` (the expression is
///   converted with `ToString` and escaped on render), or bare boolean
///   attributes like `disabled`.
/// - **Text**: string literals in child position, escaped: `<p>"a < b"</p>`.
/// - **Interpolation**: `{expr}` in child position converts the expression
///   via `afterglow::Render` (strings and numbers render as escaped text).
/// - **Async widgets**: `@{expr}` where `expr` is a future. Renders a
///   `<?marker name="N">` placeholder in the shell; the resolved value is
///   converted via `Render` (so `Result<impl Render, E: Display>` works and
///   an `Err` renders as an error slot).
/// - **Fallback form**: `@{expr} else { <span>"loading…"</span> }` renders
///   the fallback markup between `<?start name="N">` and `<?end>` until the
///   future resolves. The fallback may itself contain `@{...}` widgets.
/// - **Streamed values**: `@*{expr}` where `expr` implements
///   `IntoNodeStream` (any `Stream` whose items implement `Render`). Renders
///   the same placeholder as `@{...}`; each value is streamed as its own
///   `<template for="N">` patch as it arrives. Takes the same optional
///   `else { fallback }` form; an empty source simply leaves the fallback in
///   place. See `Node::stream` for cancellation and termination semantics.
/// - **Async attributes**: `attr=@{future}`, optionally followed by
///   `else "literal"` / `else {expr}` for the value shown until it resolves
///   (omit `else` and the attribute is simply absent until then). There is
///   no attribute-level patch in the wire format, so once `future` resolves,
///   the **whole element is replaced** — not just the attribute. See
///   `Node::element_with_pending_attributes` and the crate-level "Async
///   attributes" docs for exactly what that costs (a full DOM remount of
///   the element and its descendants) and what it doesn't (nested
///   `@{...}`/`@*{...}` holes inside such an element keep resolving
///   correctly through the swap, never re-run or duplicated).
/// - **Const interpolation**: `const { expr }` in child position splices a
///   compile-time string into the surrounding static segment via `concat!`,
///   e.g. `const { env!("CARGO_PKG_NAME") }`. The expression must be a
///   literal or a built-in literal macro (`env!`, `include_str!`,
///   `stringify!`, ...) — arbitrary `const` items are not accepted by
///   `concat!`. The value is spliced **verbatim** (no escaping; it is
///   developer-controlled), and the segment stays a single `&'static str`,
///   so fully static templates using it remain const-constructible.
///
/// # Compile-time prerendering
///
/// All static markup is rendered and escaped at macro expansion time:
/// adjacent tags, literal attribute values, and literal text collapse into
/// `&'static str` segments stored in the binary. Dynamic holes — `{expr}`,
/// `@{...}`, and elements with `attr={expr}` — are the only per-request
/// construction work. A fully static template expands to a single
/// `Node::Html(Cow::Borrowed(...))`, which is legal in const context:
///
/// ```ignore
/// const FOOTER: Node = html! { <footer>"© 2026"</footer> };
/// ```
///
/// # Example
///
/// ```ignore
/// let page = html! {
///     <main>
///         <h1>{title}</h1>
///         @{load_articles()} else { <p class="spinner">"loading…"</p> }
///     </main>
/// };
/// ```
#[proc_macro]
pub fn html(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    match Parser::new(input.into()).parse_root() {
        Ok(nodes) => generate(nodes).into(),
        Err(error) => error.to_compile_error().into(),
    }
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

enum Ast {
    Element {
        tag: String,
        attributes: Vec<Attribute>,
        children: Vec<Ast>,
    },
    Text(String),
    Interpolation(syn::Expr),
    /// `const { expr }` — a compile-time string spliced verbatim into the
    /// surrounding static segment via `concat!`.
    ConstHtml(syn::Expr),
    Pending {
        future: syn::Expr,
        fallback: Option<Vec<Ast>>,
    },
    Stream {
        source: syn::Expr,
        fallback: Option<Vec<Ast>>,
    },
}

struct Attribute {
    name: String,
    value: AttributeValue,
}

enum AttributeValue {
    Bare,
    Literal(String),
    Expression(syn::Expr),
    /// `attr=@{future}`, optionally followed by `else "literal"` /
    /// `else {expr}`. With no `else`, the attribute is simply absent from
    /// the fallback until the future resolves.
    Pending {
        future: syn::Expr,
        fallback: Option<syn::Expr>,
    },
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

struct Parser {
    tokens: Vec<TokenTree>,
    position: usize,
}

impl Parser {
    fn new(stream: TokenStream) -> Self {
        Parser {
            tokens: stream.into_iter().collect(),
            position: 0,
        }
    }

    fn peek(&self) -> Option<&TokenTree> {
        self.tokens.get(self.position)
    }

    fn peek_second(&self) -> Option<&TokenTree> {
        self.tokens.get(self.position + 1)
    }

    fn advance(&mut self) -> Option<TokenTree> {
        let token = self.tokens.get(self.position).cloned();
        if token.is_some() {
            self.position += 1;
        }
        token
    }

    fn error_here(&self, message: &str) -> syn::Error {
        let span = self
            .peek()
            .map(TokenTree::span)
            .or_else(|| self.tokens.last().map(TokenTree::span))
            .unwrap_or_else(Span::call_site);
        syn::Error::new(span, message)
    }

    fn expect_punct(&mut self, expected: char) -> syn::Result<()> {
        match self.peek() {
            Some(TokenTree::Punct(punct)) if punct.as_char() == expected => {
                self.advance();
                Ok(())
            }
            _ => Err(self.error_here(&format!("expected `{expected}`"))),
        }
    }

    fn peek_is_punct(&self, expected: char) -> bool {
        matches!(self.peek(), Some(TokenTree::Punct(punct)) if punct.as_char() == expected)
    }

    fn parse_root(mut self) -> syn::Result<Vec<Ast>> {
        let nodes = self.parse_nodes()?;
        if self.peek().is_some() {
            return Err(self.error_here("unexpected token after markup"));
        }
        Ok(nodes)
    }

    /// Parses child nodes until a closing tag (`</`) or end of input. The
    /// closing tag itself is left for the caller.
    fn parse_nodes(&mut self) -> syn::Result<Vec<Ast>> {
        let mut nodes = Vec::new();
        loop {
            match self.peek() {
                None => break,
                Some(TokenTree::Punct(punct)) if punct.as_char() == '<' => {
                    let closing = matches!(
                        self.peek_second(),
                        Some(TokenTree::Punct(second)) if second.as_char() == '/'
                    );
                    if closing {
                        break;
                    }
                    nodes.push(self.parse_element()?);
                }
                Some(TokenTree::Literal(_)) => nodes.push(self.parse_text()?),
                Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace => {
                    nodes.push(self.parse_interpolation()?);
                }
                Some(TokenTree::Punct(punct)) if punct.as_char() == '@' => {
                    let is_stream = matches!(
                        self.peek_second(),
                        Some(TokenTree::Punct(second)) if second.as_char() == '*'
                    );
                    nodes.push(if is_stream {
                        self.parse_stream()?
                    } else {
                        self.parse_pending()?
                    });
                }
                Some(TokenTree::Ident(ident)) if ident == "const" => {
                    nodes.push(self.parse_const()?);
                }
                Some(_) => {
                    return Err(self.error_here(
                        "expected an element, a quoted string, `{expr}`, `@{future}`, or `@*{stream}`",
                    ));
                }
            }
        }
        Ok(nodes)
    }

    /// Parses `name` or `name-with-dashes` (used for tags and attributes).
    fn parse_name(&mut self) -> syn::Result<(String, Span)> {
        let Some(TokenTree::Ident(ident)) = self.peek() else {
            return Err(self.error_here("expected a name"));
        };
        let span = ident.span();
        let mut name = ident.to_string();
        self.advance();

        while self.peek_is_punct('-') {
            let Some(TokenTree::Ident(ident)) = self.peek_second() else {
                return Err(self.error_here("expected a name segment after `-`"));
            };
            name.push('-');
            name.push_str(&ident.to_string());
            self.advance();
            self.advance();
        }

        Ok((name, span))
    }

    fn parse_element(&mut self) -> syn::Result<Ast> {
        self.expect_punct('<')?;
        let (tag, tag_span) = self.parse_name()?;

        let mut attributes = Vec::new();
        loop {
            match self.peek() {
                Some(TokenTree::Punct(punct)) if punct.as_char() == '/' => {
                    self.advance();
                    self.expect_punct('>')?;
                    return Ok(Ast::Element {
                        tag,
                        attributes,
                        children: Vec::new(),
                    });
                }
                Some(TokenTree::Punct(punct)) if punct.as_char() == '>' => {
                    self.advance();
                    break;
                }
                Some(TokenTree::Ident(_)) => attributes.push(self.parse_attribute()?),
                _ => return Err(self.error_here("expected an attribute name, `/>`, or `>`")),
            }
        }

        let children = self.parse_nodes()?;

        self.expect_punct('<')?;
        self.expect_punct('/')?;
        let (closing_tag, closing_span) = self.parse_name()?;
        if closing_tag != tag {
            let mut error = syn::Error::new(
                closing_span,
                format!("mismatched closing tag `</{closing_tag}>`; expected `</{tag}>`"),
            );
            error.combine(syn::Error::new(tag_span, "element opened here"));
            return Err(error);
        }
        self.expect_punct('>')?;

        Ok(Ast::Element {
            tag,
            attributes,
            children,
        })
    }

    fn parse_attribute(&mut self) -> syn::Result<Attribute> {
        let (name, _) = self.parse_name()?;

        let value = if self.peek_is_punct('=') {
            self.advance();
            if self.peek_is_punct('@') {
                self.advance();
                let future = self.parse_brace_expr("expected `{future}` after `@`")?;
                let fallback = self.parse_optional_attribute_fallback()?;
                AttributeValue::Pending { future, fallback }
            } else {
                match self.advance() {
                    Some(TokenTree::Literal(literal)) => {
                        let syn::Lit::Str(string) = syn::Lit::new(literal.clone()) else {
                            return Err(syn::Error::new(
                                literal.span(),
                                "attribute values must be string literals, `{expr}`, or `@{future}`",
                            ));
                        };
                        AttributeValue::Literal(string.value())
                    }
                    Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace => {
                        AttributeValue::Expression(syn::parse2(group.stream())?)
                    }
                    _ => {
                        return Err(self.error_here(
                            "expected a string literal, `{expr}`, or `@{future}` after `=`",
                        ));
                    }
                }
            }
        } else {
            AttributeValue::Bare
        };

        Ok(Attribute { name, value })
    }

    /// Parses an optional `else "literal"` / `else {expr}` after
    /// `attr=@{future}` — the value shown until the future resolves.
    fn parse_optional_attribute_fallback(&mut self) -> syn::Result<Option<syn::Expr>> {
        match self.peek() {
            Some(TokenTree::Ident(ident)) if ident == "else" => {
                self.advance();
                match self.advance() {
                    Some(TokenTree::Literal(literal)) => {
                        let syn::Lit::Str(string) = syn::Lit::new(literal.clone()) else {
                            return Err(syn::Error::new(
                                literal.span(),
                                "attribute fallback values must be string literals or `{expr}`",
                            ));
                        };
                        Ok(Some(syn::Expr::Lit(syn::ExprLit {
                            attrs: Vec::new(),
                            lit: syn::Lit::Str(string),
                        })))
                    }
                    Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace => {
                        Ok(Some(syn::parse2(group.stream())?))
                    }
                    _ => Err(self.error_here("expected a string literal or `{expr}` after `else`")),
                }
            }
            _ => Ok(None),
        }
    }

    fn parse_text(&mut self) -> syn::Result<Ast> {
        let Some(TokenTree::Literal(literal)) = self.advance() else {
            unreachable!("parse_text is only called when peeking a literal");
        };
        let syn::Lit::Str(string) = syn::Lit::new(literal.clone()) else {
            return Err(syn::Error::new(
                literal.span(),
                "text content must be a quoted string; interpolate other values with `{expr}`",
            ));
        };
        Ok(Ast::Text(string.value()))
    }

    fn parse_interpolation(&mut self) -> syn::Result<Ast> {
        let Some(TokenTree::Group(group)) = self.advance() else {
            unreachable!("parse_interpolation is only called when peeking a brace group");
        };
        Ok(Ast::Interpolation(syn::parse2(group.stream())?))
    }

    /// Parses `const { expr }`.
    fn parse_const(&mut self) -> syn::Result<Ast> {
        self.advance(); // the `const` keyword
        let Some(TokenTree::Group(group)) = self.peek() else {
            return Err(self.error_here("expected `{ expr }` after `const`"));
        };
        if group.delimiter() != Delimiter::Brace {
            return Err(self.error_here("expected `{ expr }` after `const`"));
        }
        let Some(TokenTree::Group(group)) = self.advance() else {
            unreachable!("peeked above");
        };
        Ok(Ast::ConstHtml(syn::parse2(group.stream())?))
    }

    /// Parses `@{future}` with an optional `else { fallback markup }`.
    fn parse_pending(&mut self) -> syn::Result<Ast> {
        self.expect_punct('@')?;
        let future = self.parse_brace_expr("expected `{future}` after `@`")?;
        let fallback = self.parse_optional_else_fallback()?;
        Ok(Ast::Pending { future, fallback })
    }

    /// Parses `@*{stream}` with an optional `else { fallback markup }`.
    fn parse_stream(&mut self) -> syn::Result<Ast> {
        self.expect_punct('@')?;
        self.expect_punct('*')?;
        let source = self.parse_brace_expr("expected `{stream}` after `@*`")?;
        let fallback = self.parse_optional_else_fallback()?;
        Ok(Ast::Stream { source, fallback })
    }

    /// Parses a `{ expr }` group, used by both `@{...}` and `@*{...}`.
    fn parse_brace_expr(&mut self, error_message: &str) -> syn::Result<syn::Expr> {
        let Some(TokenTree::Group(group)) = self.peek() else {
            return Err(self.error_here(error_message));
        };
        if group.delimiter() != Delimiter::Brace {
            return Err(self.error_here(error_message));
        }
        let Some(TokenTree::Group(group)) = self.advance() else {
            unreachable!("peeked above");
        };
        syn::parse2(group.stream())
    }

    /// Parses an optional `else { fallback markup }`, used by both `@{...}`
    /// and `@*{...}`.
    fn parse_optional_else_fallback(&mut self) -> syn::Result<Option<Vec<Ast>>> {
        match self.peek() {
            Some(TokenTree::Ident(ident)) if ident == "else" => {
                self.advance();
                let Some(TokenTree::Group(group)) = self.peek() else {
                    return Err(self.error_here("expected `{ fallback markup }` after `else`"));
                };
                if group.delimiter() != Delimiter::Brace {
                    return Err(self.error_here("expected `{ fallback markup }` after `else`"));
                }
                let Some(TokenTree::Group(group)) = self.advance() else {
                    unreachable!("peeked above");
                };
                Ok(Some(Parser::new(group.stream()).parse_root()?))
            }
            _ => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Code generation with static folding
// ---------------------------------------------------------------------------

fn generate(nodes: Vec<Ast>) -> TokenStream {
    combine_parts(fold_to_parts(nodes))
}

/// One piece of a static segment: HTML rendered at expansion time, or a
/// compile-time `const { ... }` expression spliced in via `concat!`.
enum Piece {
    Literal(String),
    Const(syn::Expr),
}

/// Accumulates one static segment between dynamic holes.
#[derive(Default)]
struct SegmentBuffer {
    pieces: Vec<Piece>,
}

impl SegmentBuffer {
    /// The literal accumulator at the end of the segment, for content the
    /// macro renders itself.
    fn literal_mut(&mut self) -> &mut String {
        if !matches!(self.pieces.last(), Some(Piece::Literal(_))) {
            self.pieces.push(Piece::Literal(String::new()));
        }
        let Some(Piece::Literal(literal)) = self.pieces.last_mut() else {
            unreachable!("pushed above");
        };
        literal
    }

    fn push_const(&mut self, expression: syn::Expr) {
        self.pieces.push(Piece::Const(expression));
    }
}

/// Folds a node list into alternating parts: pre-rendered `&'static str`
/// segments for everything static, and one expression per dynamic hole.
fn fold_to_parts(nodes: Vec<Ast>) -> Vec<TokenStream> {
    let mut buffer = SegmentBuffer::default();
    let mut parts = Vec::new();
    fold_nodes(nodes, &mut buffer, &mut parts);
    flush(&mut buffer, &mut parts);
    parts
}

fn fold_nodes(nodes: Vec<Ast>, buffer: &mut SegmentBuffer, parts: &mut Vec<TokenStream>) {
    for node in nodes {
        match node {
            Ast::Text(text) => escape_text_into(&text, buffer.literal_mut()),
            Ast::ConstHtml(expression) => buffer.push_const(expression),
            Ast::Interpolation(expression) => {
                flush(buffer, parts);
                parts.push(quote! { ::afterglow::Render::into_node(#expression) });
            }
            Ast::Pending { future, fallback } => {
                flush(buffer, parts);
                parts.push(match fallback {
                    None => quote! {
                        ::afterglow::Node::pending(async move { (#future).await })
                    },
                    Some(fallback) => {
                        let fallback = combine_parts(fold_to_parts(fallback));
                        quote! {
                            ::afterglow::Node::pending_with_fallback(
                                async move { (#future).await },
                                #fallback,
                            )
                        }
                    }
                });
            }
            Ast::Stream { source, fallback } => {
                flush(buffer, parts);
                parts.push(match fallback {
                    None => quote! {
                        ::afterglow::Node::stream(#source)
                    },
                    Some(fallback) => {
                        let fallback = combine_parts(fold_to_parts(fallback));
                        quote! {
                            ::afterglow::Node::stream_with_fallback(#source, #fallback)
                        }
                    }
                });
            }
            Ast::Element {
                tag,
                attributes,
                children,
            } => {
                let has_pending_attribute = attributes
                    .iter()
                    .any(|attribute| matches!(attribute.value, AttributeValue::Pending { .. }));

                let all_attributes_static = !has_pending_attribute
                    && attributes
                        .iter()
                        .all(|attribute| !matches!(attribute.value, AttributeValue::Expression(_)));

                if has_pending_attribute {
                    flush(buffer, parts);
                    parts.push(build_pending_attributes_element(tag, attributes, children));
                } else if all_attributes_static {
                    let out = buffer.literal_mut();
                    out.push('<');
                    out.push_str(&tag);
                    for attribute in attributes {
                        out.push(' ');
                        out.push_str(&attribute.name);
                        match attribute.value {
                            AttributeValue::Bare => {}
                            AttributeValue::Literal(value) => {
                                out.push_str("=\"");
                                escape_attribute_into(&value, out);
                                out.push('"');
                            }
                            AttributeValue::Expression(_) | AttributeValue::Pending { .. } => {
                                unreachable!("checked above")
                            }
                        }
                    }
                    out.push('>');
                    // Void elements ignore children and have no closing tag,
                    // matching the runtime renderer.
                    if !is_void_element(&tag) {
                        fold_nodes(children, buffer, parts);
                        let out = buffer.literal_mut();
                        out.push_str("</");
                        out.push_str(&tag);
                        out.push('>');
                    }
                } else {
                    // A dynamic attribute value can only be escaped at
                    // runtime, so this element keeps its structured form; its
                    // children still fold.
                    flush(buffer, parts);
                    let attributes: Vec<_> =
                        attributes.into_iter().map(attribute_tokens).collect();
                    let children = fold_to_parts(children);
                    parts.push(quote! {
                        ::afterglow::Node::element(
                            #tag,
                            ::std::vec![#(#attributes),*],
                            ::std::vec![#(#children),*],
                        )
                    });
                }
            }
        }
    }
}

fn flush(buffer: &mut SegmentBuffer, parts: &mut Vec<TokenStream>) {
    let pieces: Vec<Piece> = std::mem::take(&mut buffer.pieces)
        .into_iter()
        .filter(|piece| !matches!(piece, Piece::Literal(literal) if literal.is_empty()))
        .collect();
    if pieces.is_empty() {
        return;
    }

    // A plain segment stays a plain string literal; segments containing
    // `const { ... }` pieces go through `concat!`, which eagerly expands
    // built-in literal macros like `env!` and still yields one
    // `&'static str` — so const-constructibility is preserved either way.
    if let [Piece::Literal(segment)] = pieces.as_slice() {
        parts.push(quote! {
            ::afterglow::Node::Html(::std::borrow::Cow::Borrowed(#segment))
        });
        return;
    }

    let arguments = pieces.into_iter().map(|piece| match piece {
        Piece::Literal(literal) => quote! { #literal },
        Piece::Const(expression) => quote! { #expression },
    });
    parts.push(quote! {
        ::afterglow::Node::Html(::std::borrow::Cow::Borrowed(
            ::std::concat!(#(#arguments),*),
        ))
    });
}

fn combine_parts(mut parts: Vec<TokenStream>) -> TokenStream {
    match parts.len() {
        0 => quote! { ::afterglow::Node::Html(::std::borrow::Cow::Borrowed("")) },
        1 => parts.pop().expect("length checked above"),
        _ => quote! { ::afterglow::Node::fragment(::std::vec![#(#parts),*]) },
    }
}

/// Builds `Node::element_with_pending_attributes(...)` for an element with
/// one or more `attr=@{...}` attributes. Static/sync attribute values are
/// evaluated once for the immediate fallback and again inside the future
/// for the eventual swap (same accepted tradeoff as children in a whole
/// element replace: cheap/pure expressions are fine, expressions that move
/// a non-`Clone` capture won't compile — write the value into a local
/// beforehand in that case). A `Pending` attribute's future is awaited
/// exactly once; its resolved value feeds only the swap.
fn build_pending_attributes_element(
    tag: String,
    attributes: Vec<Attribute>,
    children: Vec<Ast>,
) -> TokenStream {
    let mut fallback_tokens = Vec::new();
    let mut await_statements = Vec::new();
    let mut resolved_tokens = Vec::new();

    for (index, attribute) in attributes.into_iter().enumerate() {
        let name = attribute.name;
        match attribute.value {
            AttributeValue::Pending { future, fallback } => {
                if let Some(fallback) = fallback {
                    fallback_tokens.push(quote! {
                        (::std::borrow::Cow::Borrowed(#name), ::std::option::Option::Some(
                            ::std::string::ToString::to_string(&(#fallback)),
                        ))
                    });
                }
                let binding = format_ident!("__afterglow_attr_{index}");
                await_statements.push(quote! { let #binding = (#future).await; });
                resolved_tokens.push(quote! {
                    (::std::borrow::Cow::Borrowed(#name), ::std::option::Option::Some(
                        ::std::string::ToString::to_string(&#binding),
                    ))
                });
            }
            value => {
                let tokens = attribute_tokens(Attribute { name, value });
                fallback_tokens.push(tokens.clone());
                resolved_tokens.push(tokens);
            }
        }
    }

    let children = fold_to_parts(children);

    quote! {
        ::afterglow::Node::element_with_pending_attributes(
            #tag,
            async move {
                #(#await_statements)*
                ::std::vec![#(#resolved_tokens),*]
            },
            ::std::vec![#(#fallback_tokens),*],
            ::std::vec![#(#children),*],
        )
    }
}

fn attribute_tokens(attribute: Attribute) -> TokenStream {
    let name = attribute.name;
    let value = match attribute.value {
        AttributeValue::Bare => quote! { ::std::option::Option::None },
        AttributeValue::Literal(value) => quote! {
            ::std::option::Option::Some(::std::string::String::from(#value))
        },
        AttributeValue::Expression(expression) => quote! {
            ::std::option::Option::Some(::std::string::ToString::to_string(&(#expression)))
        },
        AttributeValue::Pending { .. } => {
            unreachable!("callers route Pending attributes through build_pending_attributes_element")
        }
    };
    quote! { (::std::borrow::Cow::Borrowed(#name), #value) }
}

// ---------------------------------------------------------------------------
// Static rendering rules — keep in sync with the runtime renderer
// (afterglow/src/escape.rs and afterglow/src/render.rs), so content folded at
// expansion time is byte-identical to what runtime rendering would produce.
// ---------------------------------------------------------------------------

const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

fn is_void_element(tag: &str) -> bool {
    VOID_ELEMENTS.contains(&tag)
}

fn escape_text_into(input: &str, out: &mut String) {
    for character in input.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            character => out.push(character),
        }
    }
}

fn escape_attribute_into(input: &str, out: &mut String) {
    for character in input.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            character => out.push(character),
        }
    }
}
