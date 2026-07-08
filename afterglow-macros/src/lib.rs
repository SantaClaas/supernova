//! Proc-macro backend for the `afterglow` crate. Use `afterglow::html!`, not
//! this crate directly.

use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use quote::quote;

/// JSX-like templating macro producing an `afterglow::Node`.
///
/// # Syntax
///
/// - **Elements**: `<div class="card">...</div>`, self-closing `<br/>`. Tag
///   and attribute names may contain hyphens (`data-id`, `my-widget`).
/// - **Attributes**: `name="literal"`, `name={expr}` (the expression is
///   converted with `ToString` and escaped on render), or bare boolean
///   attributes like `disabled`.
/// - **Text**: string literals in child position, escaped on render:
///   `<p>"a < b"</p>`.
/// - **Interpolation**: `{expr}` in child position converts the expression
///   via `afterglow::Render` (strings and numbers render as escaped text).
/// - **Async widgets**: `@{expr}` where `expr` is a future. Renders a
///   `<?marker id="N">` placeholder in the shell; the resolved value is
///   converted via `Render` (so `Result<impl Render, E: Display>` works and
///   an `Err` renders as an error slot).
/// - **Fallback form**: `@{expr} else { <span>"loading…"</span> }` renders
///   the fallback markup between `<?start id="N">` and `<?end>` until the
///   future resolves. The fallback may itself contain `@{...}` widgets.
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
        Ok(output) => output.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

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

    fn parse_root(mut self) -> syn::Result<TokenStream> {
        let nodes = self.parse_nodes()?;
        if self.peek().is_some() {
            return Err(self.error_here("unexpected token after markup"));
        }
        Ok(combine_nodes(nodes))
    }

    /// Parses child nodes until a closing tag (`</`) or end of input. The
    /// closing tag itself is left for the caller.
    fn parse_nodes(&mut self) -> syn::Result<Vec<TokenStream>> {
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
                    nodes.push(self.parse_pending()?);
                }
                Some(_) => {
                    return Err(self.error_here(
                        "expected an element, a quoted string, `{expr}`, or `@{future}`",
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

    fn parse_element(&mut self) -> syn::Result<TokenStream> {
        self.expect_punct('<')?;
        let (tag, tag_span) = self.parse_name()?;

        let mut attributes = Vec::new();
        loop {
            match self.peek() {
                Some(TokenTree::Punct(punct)) if punct.as_char() == '/' => {
                    self.advance();
                    self.expect_punct('>')?;
                    return Ok(build_element(&tag, attributes, Vec::new()));
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

        Ok(build_element(&tag, attributes, children))
    }

    fn parse_attribute(&mut self) -> syn::Result<TokenStream> {
        let (name, _) = self.parse_name()?;

        let value = if self.peek_is_punct('=') {
            self.advance();
            match self.advance() {
                Some(TokenTree::Literal(literal)) => {
                    let syn::Lit::Str(string) = syn::Lit::new(literal.clone()) else {
                        return Err(syn::Error::new(
                            literal.span(),
                            "attribute values must be string literals or `{expr}`",
                        ));
                    };
                    quote! {
                        ::std::option::Option::Some(::std::string::String::from(#string))
                    }
                }
                Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace => {
                    let expression: syn::Expr = syn::parse2(group.stream())?;
                    quote! {
                        ::std::option::Option::Some(
                            ::std::string::ToString::to_string(&(#expression)),
                        )
                    }
                }
                _ => {
                    return Err(
                        self.error_here("expected a string literal or `{expr}` after `=`")
                    );
                }
            }
        } else {
            quote! { ::std::option::Option::None }
        };

        Ok(quote! { (::std::borrow::Cow::Borrowed(#name), #value) })
    }

    fn parse_text(&mut self) -> syn::Result<TokenStream> {
        let Some(TokenTree::Literal(literal)) = self.advance() else {
            unreachable!("parse_text is only called when peeking a literal");
        };
        let syn::Lit::Str(string) = syn::Lit::new(literal.clone()) else {
            return Err(syn::Error::new(
                literal.span(),
                "text content must be a quoted string; interpolate other values with `{expr}`",
            ));
        };
        Ok(quote! { ::afterglow::Node::text(#string) })
    }

    fn parse_interpolation(&mut self) -> syn::Result<TokenStream> {
        let Some(TokenTree::Group(group)) = self.advance() else {
            unreachable!("parse_interpolation is only called when peeking a brace group");
        };
        let expression: syn::Expr = syn::parse2(group.stream())?;
        Ok(quote! { ::afterglow::Render::into_node(#expression) })
    }

    /// Parses `@{future}` with an optional `else { fallback markup }`.
    fn parse_pending(&mut self) -> syn::Result<TokenStream> {
        self.expect_punct('@')?;
        let Some(TokenTree::Group(group)) = self.peek() else {
            return Err(self.error_here("expected `{future}` after `@`"));
        };
        if group.delimiter() != Delimiter::Brace {
            return Err(self.error_here("expected `{future}` after `@`"));
        }
        let Some(TokenTree::Group(group)) = self.advance() else {
            unreachable!("peeked above");
        };
        let expression: syn::Expr = syn::parse2(group.stream())?;

        let fallback = match self.peek() {
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
                let mut fallback_parser = Parser::new(group.stream());
                let nodes = fallback_parser.parse_nodes()?;
                if fallback_parser.peek().is_some() {
                    return Err(fallback_parser.error_here("unexpected token in fallback markup"));
                }
                Some(combine_nodes(nodes))
            }
            _ => None,
        };

        Ok(match fallback {
            None => quote! {
                ::afterglow::Node::pending(async move { (#expression).await })
            },
            Some(fallback) => quote! {
                ::afterglow::Node::pending_with_fallback(
                    async move { (#expression).await },
                    #fallback,
                )
            },
        })
    }
}

fn combine_nodes(mut nodes: Vec<TokenStream>) -> TokenStream {
    match nodes.len() {
        0 => quote! { ::afterglow::Node::Fragment(::std::vec::Vec::new()) },
        1 => nodes.pop().expect("length checked above"),
        _ => quote! { ::afterglow::Node::fragment(::std::vec![#(#nodes),*]) },
    }
}

fn build_element(
    tag: &str,
    attributes: Vec<TokenStream>,
    children: Vec<TokenStream>,
) -> TokenStream {
    quote! {
        ::afterglow::Node::element(
            #tag,
            ::std::vec![#(#attributes),*],
            ::std::vec![#(#children),*],
        )
    }
}
