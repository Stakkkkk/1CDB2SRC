//! Top-level fields of 1C brace lists (`{a,{b,c},"d"}`), for the few external
//! rows this adapter rewrites. Quotes are 1C strings with `""` escapes.

pub fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

/// Fields of the brace list opening at `text[start]` (trimmed) and the byte
/// index just past its closing brace; `None` when unbalanced.
pub fn fields(text: &str, start: usize) -> Option<(Vec<&str>, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&b'{') {
        return None;
    }
    let (mut depth, mut quoted, mut field_start) = (0usize, false, start + 1);
    let mut out = Vec::new();
    let mut i = start;
    while i < bytes.len() {
        let c = bytes[i];
        if quoted {
            if c == b'"' {
                if bytes.get(i + 1) == Some(&b'"') {
                    i += 1;
                } else {
                    quoted = false;
                }
            }
        } else {
            match c {
                b'"' => quoted = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        out.push(text[field_start..i].trim());
                        return Some((out, i + 1));
                    }
                }
                b',' if depth == 1 => {
                    out.push(text[field_start..i].trim());
                    field_start = i + 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_top_level_fields_with_nesting_and_quotes() {
        let text = "{1,\r\n{2,\"a,}{\"\"b\",x},\"q\",{}}";
        let (f, end) = fields(text, 0).unwrap();
        assert_eq!(f, vec!["1", "{2,\"a,}{\"\"b\",x}", "\"q\"", "{}"]);
        assert_eq!(end, text.len());
    }

    #[test]
    fn unbalanced_list_is_none() {
        assert!(fields("{1,{2}", 0).is_none());
    }

    #[test]
    fn strips_utf8_bom() {
        assert_eq!(strip_bom("\u{feff}{1}"), "{1}");
        assert_eq!(strip_bom("{1}"), "{1}");
    }
}
