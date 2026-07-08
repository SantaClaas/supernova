/// Escapes text content: `&`, `<`, `>`.
pub(crate) fn escape_text(input: &str, out: &mut String) {
    for character in input.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            character => out.push(character),
        }
    }
}

/// Escapes attribute values: text escapes plus both quote characters, so the
/// value is safe inside single- or double-quoted attributes.
pub(crate) fn escape_attribute(input: &str, out: &mut String) {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn escapes_text_metacharacters() {
        let mut out = String::new();
        escape_text("a < b && c > \"d\"", &mut out);
        assert_eq!("a &lt; b &amp;&amp; c &gt; \"d\"", out);
    }

    #[test]
    fn escapes_attribute_quotes() {
        let mut out = String::new();
        escape_attribute("say \"hi\" & 'bye' <now>", &mut out);
        assert_eq!("say &quot;hi&quot; &amp; &#39;bye&#39; &lt;now&gt;", out);
    }
}
