use std::sync::LazyLock;

use anyhow::Result;
use regex::Regex;

use super::Language;

static ASSIGNMENT_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?P<key>[A-Za-z_@$][\w$@.:>-]*)
        \s*
        (?P<op>:=|=>|=|\+=)
        \s*
        (?P<value>
            @"(?s:(?:[^"]|"")*)"
            |
            "(?:[^"\\]|\\.)*"
            |
            '(?:[^'\\]|\\.)*'
            |
            `[^`]*`
            |
            [+-]?\d+(?:\.\d+)?
        )
    "#,
    )
    .unwrap()
});

static ASSIGNMENT_ANY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?P<key>[A-Za-z_@$][\w$@.:>-]*)
        \s*
        (?P<op>:=|=>|=|\+=)
        \s*
        (?P<rhs>.+)
    "#,
    )
    .unwrap()
});

static TYPED_ASSIGNMENT_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?P<key>[A-Za-z_@$][\w$@.-]*)
        \s*:\s*[^=]+?
        =\s*
        (?P<value>
            @"(?s:(?:[^"]|"")*)"
            |
            "(?:[^"\\]|\\.)*"
            |
            '(?:[^'\\]|\\.)*'
            |
            `[^`]*`
            |
            [+-]?\d+(?:\.\d+)?
        )
    "#,
    )
    .unwrap()
});

static PAIR_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            ^
            |
            [\{\[,]\s*
            |
            ,\s*
        )
        (?P<key>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[A-Za-z_@$][\w$@.-]*)
        \s*:\s*
        (?P<value>
            "(?:[^"\\]|\\.)*"
            |
            '(?:[^'\\]|\\.)*'
            |
            `[^`]*`
            |
            [+-]?\d+(?:\.\d+)?
        )
    "#,
    )
    .unwrap()
});

static TYPE_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?P<key>[A-Za-z_@$][\w$@.-]*)
        \s*:\s*
        (?P<value>
            "(?:[^"\\]|\\.)*"
            |
            '(?:[^'\\]|\\.)*'
            |
            `[^`]*`
        )
    "#,
    )
    .unwrap()
});

static CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?:
            (?P<assign>[A-Za-z_@$][\w$@.:>-]*)\s*(?::=|=)\s*
        )?
        (?P<call>(?:new\s+)?[A-Za-z_@$][\w$@.:>-]*)
        \s*
        \((?P<args>[^)]*)\)
    "#,
    )
    .unwrap()
});

static BRACE_LIST_ASSIGN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        (?P<key>[A-Za-z_@$][\w$@.:>-]*)
        \s*=\s*
        \{(?P<body>[^}]*)\}
    "#,
    )
    .unwrap()
});

pub(super) fn stream_context_candidates<F>(
    source: &[u8],
    language: &Language,
    sink: &mut F,
) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let text = String::from_utf8_lossy(source);
    if text.is_empty() {
        return Ok(());
    }

    match language {
        Language::Bash => extract_bash(&text, sink),
        Language::Python => extract_python(&text, sink),
        Language::Ruby => extract_ruby(&text, sink),
        Language::Php => extract_php(&text, sink),
        Language::Yaml => extract_yaml(&text, sink),
        Language::Toml => extract_toml(&text, sink),
        Language::JavaScript => extract_javascript_like(&text, false, sink),
        Language::TypeScript => extract_javascript_like(&text, true, sink),
        Language::Rust => extract_rust(&text, sink),
        Language::C | Language::CSharp | Language::Cpp | Language::Go | Language::Java => {
            extract_c_style(&text, language, sink)
        }
        Language::Css | Language::Html => Ok(()),
    }
}

fn extract_bash<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::shell());
    for line in cleaned.lines() {
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

fn extract_python<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::python());
    for line in cleaned.lines() {
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_pairs(line, true, sink).is_break() {
            return Ok(());
        }
        if emit_calls(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

fn extract_ruby<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::hash_only());
    for line in cleaned.lines() {
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_assignment_lists(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_calls(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

fn extract_php<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::php());
    for line in cleaned.lines() {
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_assignment_lists(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_calls(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

fn extract_yaml<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::hash_only());
    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('-') && !trimmed.contains(':') {
            continue;
        }
        if let Some((key, value)) = split_mapping_pair(trimmed) {
            let key = key.trim_start_matches('-').trim();
            if emit_value(key, value, true, true, sink).is_break() {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn extract_toml<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::hash_only());
    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('[') {
            continue;
        }
        if let Some((key, value)) = split_assignment(trimmed, '=') {
            if emit_value(key, value, true, false, sink).is_break() {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn extract_javascript_like<F>(text: &str, include_type_literals: bool, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::c_style().with_backticks());
    for line in cleaned.lines() {
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_pairs(line, false, sink).is_break() {
            return Ok(());
        }
        if include_type_literals && emit_type_literals(line, sink).is_break() {
            return Ok(());
        }
        if emit_assignment_lists(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_calls(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

fn extract_rust<F>(text: &str, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let cleaned = strip_comments(text, CommentStyle::c_style());
    for line in cleaned.lines() {
        if emit_typed_assignment_literals(line, sink).is_break() {
            return Ok(());
        }
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_calls(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

fn extract_c_style<F>(text: &str, language: &Language, sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let style = match language {
        Language::CSharp => CommentStyle::c_style().with_verbatim_strings(),
        _ => CommentStyle::c_style(),
    };
    let cleaned = strip_comments(text, style);
    for line in cleaned.lines() {
        if emit_assignment_literals(line, false, sink).is_break() {
            return Ok(());
        }
        if emit_brace_list_assignments(line, sink).is_break() {
            return Ok(());
        }
        if matches!(language, Language::Cpp) && looks_like_cpp_ctor_initializer_line(line) {
            continue;
        }
        if emit_calls(line, false, sink).is_break() {
            return Ok(());
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Flow {
    Continue,
    Break,
}

impl Flow {
    fn is_break(self) -> bool {
        matches!(self, Self::Break)
    }
}

fn emit_assignment_literals<F>(line: &str, keep_full_key: bool, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    for caps in ASSIGNMENT_LITERAL_RE.captures_iter(line) {
        let Some(key) = caps.name("key").map(|m| m.as_str()) else {
            continue;
        };
        let Some(value) = caps.name("value").map(|m| m.as_str()) else {
            continue;
        };
        if emit_value(key, value, keep_full_key, false, sink).is_break() {
            return Flow::Break;
        }
    }
    Flow::Continue
}

fn emit_typed_assignment_literals<F>(line: &str, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    for caps in TYPED_ASSIGNMENT_LITERAL_RE.captures_iter(line) {
        let Some(key) = caps.name("key").map(|m| m.as_str()) else {
            continue;
        };
        let Some(value) = caps.name("value").map(|m| m.as_str()) else {
            continue;
        };
        if emit_value(key, value, false, false, sink).is_break() {
            return Flow::Break;
        }
    }
    Flow::Continue
}

fn emit_assignment_lists<F>(line: &str, keep_full_key: bool, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    if let Some(caps) = ASSIGNMENT_ANY_RE.captures(line) {
        let Some(key) = caps.name("key").map(|m| m.as_str()) else {
            return Flow::Continue;
        };
        let Some(rhs) = caps.name("rhs").map(|m| m.as_str()) else {
            return Flow::Continue;
        };
        if rhs.contains(',') || rhs.contains('[') || rhs.contains('{') {
            for value in extract_literal_values(rhs, false) {
                if emit_value(key, &value, keep_full_key, false, sink).is_break() {
                    return Flow::Break;
                }
            }
        }
    }
    Flow::Continue
}

fn emit_brace_list_assignments<F>(line: &str, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    for caps in BRACE_LIST_ASSIGN_RE.captures_iter(line) {
        let Some(key) = caps.name("key").map(|m| m.as_str()) else {
            continue;
        };
        let Some(body) = caps.name("body").map(|m| m.as_str()) else {
            continue;
        };
        for value in extract_literal_values(body, false) {
            if emit_value(key, &value, false, false, sink).is_break() {
                return Flow::Break;
            }
        }
    }
    Flow::Continue
}

fn emit_pairs<F>(line: &str, keep_full_key: bool, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    for caps in PAIR_LITERAL_RE.captures_iter(line) {
        let Some(key) = caps.name("key").map(|m| m.as_str()) else {
            continue;
        };
        let Some(value) = caps.name("value").map(|m| m.as_str()) else {
            continue;
        };
        if emit_value(key, value, keep_full_key, false, sink).is_break() {
            return Flow::Break;
        }
    }
    Flow::Continue
}

fn emit_type_literals<F>(line: &str, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    for caps in TYPE_LITERAL_RE.captures_iter(line) {
        let Some(key) = caps.name("key").map(|m| m.as_str()) else {
            continue;
        };
        let Some(value) = caps.name("value").map(|m| m.as_str()) else {
            continue;
        };
        if emit_value(key, value, false, false, sink).is_break() {
            return Flow::Break;
        }
    }
    Flow::Continue
}

fn emit_calls<F>(line: &str, keep_full_assign_key: bool, sink: &mut F) -> Flow
where
    F: FnMut(&str) -> bool,
{
    for caps in CALL_RE.captures_iter(line) {
        let assign_key = caps.name("assign").map(|m| m.as_str());
        let Some(call) = caps.name("call").map(|m| m.as_str()) else {
            continue;
        };
        let Some(args) = caps.name("args").map(|m| m.as_str()) else {
            continue;
        };

        let values = extract_literal_values(args, false);
        if values.is_empty() {
            continue;
        }

        if let Some(key) = assign_key {
            for value in &values {
                if emit_value(key, value, keep_full_assign_key, false, sink).is_break() {
                    return Flow::Break;
                }
            }
        }

        let call_name = normalize_call_name(call);
        for value in &values {
            if emit_value(&call_name, value, true, false, sink).is_break() {
                return Flow::Break;
            }
        }

        if values.len() >= 2 {
            let first = values[0].trim_matches('"').trim_matches('\'');
            let second = &values[1];
            if looks_like_embedded_key(first)
                && emit_value(first, second, true, false, sink).is_break()
            {
                return Flow::Break;
            }
        }
    }
    Flow::Continue
}

fn emit_value<F>(
    key: &str,
    value: &str,
    keep_full_key: bool,
    allow_bare: bool,
    sink: &mut F,
) -> Flow
where
    F: FnMut(&str) -> bool,
{
    let key = normalize_key(key, keep_full_key);
    let value = normalize_value(value, allow_bare);
    if key.is_empty() || value.is_empty() {
        return Flow::Continue;
    }
    let candidate = format!("{key} = {value}");
    if sink(&candidate) {
        Flow::Continue
    } else {
        Flow::Break
    }
}

fn normalize_key(key: &str, keep_full_key: bool) -> String {
    let mut key = key.trim().trim_start_matches('$').trim_start_matches('@').to_string();
    if (key.starts_with('"') && key.ends_with('"'))
        || (key.starts_with('\'') && key.ends_with('\''))
    {
        key = key[1..key.len() - 1].to_string();
    }
    if keep_full_key {
        return key;
    }
    key.rsplit(['.', ':', '>'])
        .find(|segment| !segment.is_empty())
        .unwrap_or(&key)
        .trim_matches('-')
        .to_string()
}

fn normalize_value(value: &str, allow_bare: bool) -> String {
    let trimmed = value.trim().trim_end_matches([',', ';']);
    if trimmed.is_empty() {
        return String::new();
    }

    if let Some(stripped) = trim_wrapped_literal(trimmed) {
        return stripped;
    }

    if allow_bare || looks_like_number(trimmed) {
        return trimmed.trim_matches([')', ']', '}']).to_string();
    }

    String::new()
}

fn trim_wrapped_literal(value: &str) -> Option<String> {
    if value.starts_with("@\"") && value.ends_with('"') && value.len() >= 3 {
        return Some(value[2..value.len() - 1].replace("\"\"", "\""));
    }
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        return Some(value[1..value.len() - 1].to_string());
    }
    if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
        return Some(value[1..value.len() - 1].to_string());
    }
    if value.starts_with('`') && value.ends_with('`') && value.len() >= 2 {
        return Some(value[1..value.len() - 1].to_string());
    }
    None
}

fn normalize_call_name(call: &str) -> String {
    let call = call.trim().trim_start_matches("new ").trim();
    call.rsplit(['.', ':', '>'])
        .find(|segment| !segment.is_empty())
        .unwrap_or(call)
        .trim_matches('-')
        .to_string()
}

fn looks_like_embedded_key(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '='))
}

fn looks_like_number(value: &str) -> bool {
    value.chars().all(|ch| ch.is_ascii_digit() || ch == '.' || ch == '-' || ch == '+')
}

fn looks_like_cpp_ctor_initializer_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.contains(") :") || trimmed.starts_with(':') || trimmed.starts_with(',')
}

fn extract_literal_values(input: &str, allow_bare: bool) -> Vec<String> {
    let bytes = input.as_bytes();
    let mut values = Vec::new();
    let mut idx = 0;

    while idx < bytes.len() {
        match bytes[idx] {
            b' ' | b'\t' | b'\r' | b'\n' | b',' => {
                idx += 1;
            }
            b'@' if idx + 1 < bytes.len() && bytes[idx + 1] == b'"' => {
                let start = idx;
                idx += 2;
                while idx < bytes.len() {
                    if bytes[idx] == b'"' {
                        if idx + 1 < bytes.len() && bytes[idx + 1] == b'"' {
                            idx += 2;
                            continue;
                        }
                        idx += 1;
                        break;
                    }
                    idx += 1;
                }
                values.push(input[start..idx].to_string());
            }
            b'"' | b'\'' | b'`' => {
                let quote = bytes[idx];
                let start = idx;
                idx += 1;
                while idx < bytes.len() {
                    if bytes[idx] == b'\\' && quote != b'`' {
                        idx += 2;
                        continue;
                    }
                    if bytes[idx] == quote {
                        idx += 1;
                        break;
                    }
                    idx += 1;
                }
                values.push(input[start..idx].to_string());
            }
            b'[' | b'(' | b'{' => {
                let (close, start) = match bytes[idx] {
                    b'[' => (b']', idx + 1),
                    b'(' => (b')', idx + 1),
                    _ => (b'}', idx + 1),
                };
                idx += 1;
                let mut depth = 1usize;
                let inner_start = start;
                while idx < bytes.len() && depth > 0 {
                    match bytes[idx] {
                        b'"' | b'\'' | b'`' => {
                            let quote = bytes[idx];
                            idx += 1;
                            while idx < bytes.len() {
                                if bytes[idx] == b'\\' && quote != b'`' {
                                    idx += 2;
                                    continue;
                                }
                                if bytes[idx] == quote {
                                    idx += 1;
                                    break;
                                }
                                idx += 1;
                            }
                        }
                        ch if ch == bytes[start - 1] => {
                            depth += 1;
                            idx += 1;
                        }
                        ch if ch == close => {
                            depth -= 1;
                            if depth == 0 {
                                let inner = &input[inner_start..idx];
                                values.extend(extract_literal_values(inner, allow_bare));
                            }
                            idx += 1;
                        }
                        _ => idx += 1,
                    }
                }
            }
            ch if ch.is_ascii_digit() || ch == b'+' || ch == b'-' => {
                let start = idx;
                idx += 1;
                while idx < bytes.len()
                    && (bytes[idx].is_ascii_digit() || matches!(bytes[idx], b'.' | b'_' | b'x'))
                {
                    idx += 1;
                }
                values.push(input[start..idx].to_string());
            }
            ch if allow_bare
                && (ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'$' | b'@')) =>
            {
                let start = idx;
                idx += 1;
                while idx < bytes.len()
                    && !matches!(
                        bytes[idx],
                        b' ' | b'\t' | b'\r' | b'\n' | b',' | b')' | b']' | b'}'
                    )
                {
                    idx += 1;
                }
                values.push(input[start..idx].to_string());
            }
            _ => idx += 1,
        }
    }

    values
}

fn split_mapping_pair(line: &str) -> Option<(&str, &str)> {
    let mut in_single = false;
    let mut in_double = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ':' if !in_single && !in_double => return Some((&line[..idx], &line[idx + 1..])),
            _ => {}
        }
    }
    None
}

fn split_assignment(line: &str, needle: char) -> Option<(&str, &str)> {
    let mut in_single = false;
    let mut in_double = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ch if ch == needle && !in_single && !in_double => {
                return Some((&line[..idx], &line[idx + 1..]));
            }
            _ => {}
        }
    }
    None
}

#[derive(Clone, Copy)]
struct CommentStyle {
    line_comment_hash: bool,
    line_comment_slash: bool,
    block_comments: bool,
    backticks: bool,
    verbatim_strings: bool,
    triple_quotes: bool,
}

impl CommentStyle {
    const fn c_style() -> Self {
        Self {
            line_comment_hash: false,
            line_comment_slash: true,
            block_comments: true,
            backticks: false,
            verbatim_strings: false,
            triple_quotes: false,
        }
    }

    const fn shell() -> Self {
        Self {
            line_comment_hash: true,
            line_comment_slash: false,
            block_comments: false,
            backticks: false,
            verbatim_strings: false,
            triple_quotes: false,
        }
    }

    const fn hash_only() -> Self {
        Self {
            line_comment_hash: true,
            line_comment_slash: false,
            block_comments: false,
            backticks: false,
            verbatim_strings: false,
            triple_quotes: false,
        }
    }

    const fn php() -> Self {
        Self {
            line_comment_hash: true,
            line_comment_slash: true,
            block_comments: true,
            backticks: false,
            verbatim_strings: false,
            triple_quotes: false,
        }
    }

    const fn python() -> Self {
        Self {
            line_comment_hash: true,
            line_comment_slash: false,
            block_comments: false,
            backticks: false,
            verbatim_strings: false,
            triple_quotes: true,
        }
    }

    const fn with_backticks(mut self) -> Self {
        self.backticks = true;
        self
    }

    const fn with_verbatim_strings(mut self) -> Self {
        self.verbatim_strings = true;
        self
    }
}

// NOTE: We index `source` byte-by-byte and cast via `bytes[idx] as char`.
// This is correct for comment/string delimiter detection because all
// delimiters we care about (`'`, `"`, `/`, `*`, `#`, `` ` ``, `\n`, `@`)
// are single-byte ASCII.  Interior bytes of multi-byte UTF-8 sequences
// have their high bit set (0x80..0xFF) so they can never collide with
// those ASCII delimiters.  The cast produces a garbage char for non-ASCII
// bytes, but the output is only consumed by regex patterns that match
// ASCII identifiers and quoted strings, so this is harmless.
fn strip_comments(source: &str, style: CommentStyle) -> String {
    #[derive(Clone, Copy)]
    enum StringState {
        Single,
        Double,
        Backtick,
        Verbatim,
        TripleSingle,
        TripleDouble,
    }

    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut idx = 0usize;
    let mut string_state: Option<StringState> = None;
    let mut in_block_comment = false;

    while idx < bytes.len() {
        if in_block_comment {
            if idx + 1 < bytes.len() && bytes[idx] == b'*' && bytes[idx + 1] == b'/' {
                in_block_comment = false;
                idx += 2;
            } else {
                if bytes[idx] == b'\n' {
                    out.push('\n');
                }
                idx += 1;
            }
            continue;
        }

        if let Some(state) = string_state {
            match state {
                StringState::Single => {
                    out.push(bytes[idx] as char);
                    if bytes[idx] == b'\\' && idx + 1 < bytes.len() {
                        out.push(bytes[idx + 1] as char);
                        idx += 2;
                        continue;
                    }
                    if bytes[idx] == b'\'' {
                        string_state = None;
                    }
                    idx += 1;
                }
                StringState::Double => {
                    out.push(bytes[idx] as char);
                    if bytes[idx] == b'\\' && idx + 1 < bytes.len() {
                        out.push(bytes[idx + 1] as char);
                        idx += 2;
                        continue;
                    }
                    if bytes[idx] == b'"' {
                        string_state = None;
                    }
                    idx += 1;
                }
                StringState::Backtick => {
                    out.push(bytes[idx] as char);
                    if bytes[idx] == b'`' {
                        string_state = None;
                    }
                    idx += 1;
                }
                StringState::Verbatim => {
                    out.push(bytes[idx] as char);
                    if bytes[idx] == b'"' {
                        if idx + 1 < bytes.len() && bytes[idx + 1] == b'"' {
                            out.push('"');
                            idx += 2;
                            continue;
                        }
                        string_state = None;
                    }
                    idx += 1;
                }
                StringState::TripleSingle => {
                    out.push(bytes[idx] as char);
                    if idx + 2 < bytes.len()
                        && bytes[idx] == b'\''
                        && bytes[idx + 1] == b'\''
                        && bytes[idx + 2] == b'\''
                    {
                        out.push('\'');
                        out.push('\'');
                        idx += 3;
                        string_state = None;
                        continue;
                    }
                    idx += 1;
                }
                StringState::TripleDouble => {
                    out.push(bytes[idx] as char);
                    if idx + 2 < bytes.len()
                        && bytes[idx] == b'"'
                        && bytes[idx + 1] == b'"'
                        && bytes[idx + 2] == b'"'
                    {
                        out.push('"');
                        out.push('"');
                        idx += 3;
                        string_state = None;
                        continue;
                    }
                    idx += 1;
                }
            }
            continue;
        }

        if style.block_comments
            && idx + 1 < bytes.len()
            && bytes[idx] == b'/'
            && bytes[idx + 1] == b'*'
        {
            in_block_comment = true;
            idx += 2;
            continue;
        }

        if style.line_comment_slash
            && idx + 1 < bytes.len()
            && bytes[idx] == b'/'
            && bytes[idx + 1] == b'/'
        {
            while idx < bytes.len() && bytes[idx] != b'\n' {
                idx += 1;
            }
            continue;
        }

        if style.line_comment_hash && bytes[idx] == b'#' {
            while idx < bytes.len() && bytes[idx] != b'\n' {
                idx += 1;
            }
            continue;
        }

        if style.verbatim_strings
            && idx + 1 < bytes.len()
            && bytes[idx] == b'@'
            && bytes[idx + 1] == b'"'
        {
            out.push('@');
            out.push('"');
            idx += 2;
            string_state = Some(StringState::Verbatim);
            continue;
        }

        if style.triple_quotes && idx + 2 < bytes.len() {
            if bytes[idx] == b'\'' && bytes[idx + 1] == b'\'' && bytes[idx + 2] == b'\'' {
                out.push('\'');
                out.push('\'');
                out.push('\'');
                idx += 3;
                string_state = Some(StringState::TripleSingle);
                continue;
            }
            if bytes[idx] == b'"' && bytes[idx + 1] == b'"' && bytes[idx + 2] == b'"' {
                out.push('"');
                out.push('"');
                out.push('"');
                idx += 3;
                string_state = Some(StringState::TripleDouble);
                continue;
            }
        }

        match bytes[idx] {
            b'\'' => {
                out.push('\'');
                string_state = Some(StringState::Single);
                idx += 1;
            }
            b'"' => {
                out.push('"');
                string_state = Some(StringState::Double);
                idx += 1;
            }
            b'`' if style.backticks => {
                out.push('`');
                string_state = Some(StringState::Backtick);
                idx += 1;
            }
            _ => {
                out.push(bytes[idx] as char);
                idx += 1;
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_literal_values ──────────────────────────────────────────

    #[test]
    fn extract_literals_double_quoted() {
        let vals = extract_literal_values(r#""hello", "world""#, false);
        assert_eq!(vals, vec![r#""hello""#, r#""world""#]);
    }

    #[test]
    fn extract_literals_single_quoted() {
        let vals = extract_literal_values("'abc', 'def'", false);
        assert_eq!(vals, vec!["'abc'", "'def'"]);
    }

    #[test]
    fn extract_literals_backtick() {
        let vals = extract_literal_values("`template ${var}`", false);
        assert_eq!(vals, vec!["`template ${var}`"]);
    }

    #[test]
    fn extract_literals_escaped_quotes() {
        let vals = extract_literal_values(r#""he said \"hi\"""#, false);
        assert_eq!(vals, vec![r#""he said \"hi\"""#]);
    }

    #[test]
    fn extract_literals_numbers() {
        let vals = extract_literal_values("42, -3.14, +1", false);
        assert_eq!(vals, vec!["42", "-3.14", "+1"]);
    }

    #[test]
    fn extract_literals_nested_brackets() {
        let vals = extract_literal_values(r#"["a", ["b", "c"]]"#, false);
        assert_eq!(vals, vec![r#""a""#, r#""b""#, r#""c""#]);
    }

    #[test]
    fn extract_literals_nested_parens() {
        let vals = extract_literal_values(r#"("x", ("y"))"#, false);
        assert_eq!(vals, vec![r#""x""#, r#""y""#]);
    }

    #[test]
    fn extract_literals_nested_braces() {
        let vals = extract_literal_values(r#"{"key": "val"}"#, false);
        assert_eq!(vals, vec![r#""key""#, r#""val""#]);
    }

    #[test]
    fn extract_literals_mixed_nesting() {
        let vals = extract_literal_values(r#"[{"a": "b"}, ("c")]"#, false);
        assert_eq!(vals, vec![r#""a""#, r#""b""#, r#""c""#]);
    }

    #[test]
    fn extract_literals_empty_input() {
        let vals = extract_literal_values("", false);
        assert!(vals.is_empty());
    }

    #[test]
    fn extract_literals_only_whitespace() {
        let vals = extract_literal_values("   \t\n  ", false);
        assert!(vals.is_empty());
    }

    #[test]
    fn extract_literals_unclosed_string() {
        // Gracefully handles unclosed quote — takes everything to end
        let vals = extract_literal_values(r#""unclosed"#, false);
        assert_eq!(vals.len(), 1);
        assert!(vals[0].starts_with('"'));
    }

    #[test]
    fn extract_literals_mismatched_brackets_does_not_panic() {
        // Must not panic on mismatched brackets — result may be empty because
        // the unclosed bracket consumes to EOF and the inner recursion only
        // fires once the bracket is closed.
        let _ = extract_literal_values(r#"["a", "b""#, false);
    }

    #[test]
    fn extract_literals_verbatim_string() {
        let vals = extract_literal_values(r#"@"line1""line2""#, false);
        assert_eq!(vals.len(), 1);
        assert_eq!(vals[0], r#"@"line1""line2""#);
    }

    #[test]
    fn extract_literals_bare_values_when_allowed() {
        let vals = extract_literal_values("foo, bar_baz", true);
        assert_eq!(vals, vec!["foo", "bar_baz"]);
    }

    #[test]
    fn extract_literals_bare_values_rejected_when_disallowed() {
        let vals = extract_literal_values("foo, bar", false);
        assert!(vals.is_empty());
    }

    // ── strip_comments ──────────────────────────────────────────────────

    #[test]
    fn strip_c_style_line_comment() {
        let result = strip_comments("x = 1; // comment\ny = 2;", CommentStyle::c_style());
        assert_eq!(result, "x = 1; \ny = 2;");
    }

    #[test]
    fn strip_c_style_block_comment() {
        let result = strip_comments("a /* block */ b", CommentStyle::c_style());
        assert_eq!(result, "a  b");
    }

    #[test]
    fn strip_c_style_block_comment_multiline() {
        let result = strip_comments("a /* line1\nline2 */ b", CommentStyle::c_style());
        assert_eq!(result, "a \n b");
    }

    #[test]
    fn strip_hash_comment() {
        let result = strip_comments("key = val # comment\nnext", CommentStyle::shell());
        assert_eq!(result, "key = val \nnext");
    }

    #[test]
    fn strip_preserves_hash_inside_string() {
        let result = strip_comments(r#"x = "has # inside""#, CommentStyle::shell());
        assert_eq!(result, r#"x = "has # inside""#);
    }

    #[test]
    fn strip_preserves_slash_inside_string() {
        let result = strip_comments(r#"x = "has // inside""#, CommentStyle::c_style());
        assert_eq!(result, r#"x = "has // inside""#);
    }

    #[test]
    fn strip_python_triple_double_quotes() {
        let result = strip_comments(
            "x = 1\n\"\"\"docstring # not a comment\"\"\"\ny = 2",
            CommentStyle::python(),
        );
        assert!(result.contains("docstring # not a comment"));
        assert!(result.contains("y = 2"));
    }

    #[test]
    fn strip_python_triple_single_quotes() {
        let result = strip_comments("'''multi\nline'''# real comment", CommentStyle::python());
        assert!(result.contains("multi\nline"));
        assert!(!result.contains("real comment"));
    }

    #[test]
    fn strip_csharp_verbatim_string() {
        let style = CommentStyle::c_style().with_verbatim_strings();
        let result = strip_comments(r#"x = @"path\to\file" // comment"#, style);
        assert!(result.contains(r#"@"path\to\file""#));
        assert!(!result.contains("comment"));
    }

    #[test]
    fn strip_backtick_template_preserves_content() {
        let style = CommentStyle::c_style().with_backticks();
        let result = strip_comments("x = `template // not a comment`", style);
        assert_eq!(result, "x = `template // not a comment`");
    }

    #[test]
    fn strip_php_both_comment_styles() {
        let result = strip_comments("a # hash\nb // slash\nc", CommentStyle::php());
        assert_eq!(result, "a \nb \nc");
    }

    #[test]
    fn strip_escaped_quote_in_string() {
        let result =
            strip_comments(r#"x = "escaped \" quote" // comment"#, CommentStyle::c_style());
        assert!(result.contains(r#"escaped \" quote"#));
        assert!(!result.contains("comment"));
    }

    #[test]
    fn strip_no_comments_passthrough() {
        let input = "let x = 42;\nlet y = \"hello\";";
        let result = strip_comments(input, CommentStyle::c_style());
        assert_eq!(result, input);
    }

    // ── normalize_key / normalize_value ────────────────────────────────

    #[test]
    fn normalize_key_strips_prefix_symbols() {
        assert_eq!(normalize_key("$var", false), "var");
        assert_eq!(normalize_key("@ivar", false), "ivar");
    }

    #[test]
    fn normalize_key_extracts_last_segment() {
        assert_eq!(normalize_key("self.password", false), "password");
        assert_eq!(normalize_key("obj::field", false), "field");
    }

    #[test]
    fn normalize_key_keeps_full_when_requested() {
        assert_eq!(normalize_key("self.password", true), "self.password");
    }

    #[test]
    fn normalize_value_strips_quotes() {
        assert_eq!(normalize_value(r#""hello""#, false), "hello");
        assert_eq!(normalize_value("'world'", false), "world");
        assert_eq!(normalize_value("`tmpl`", false), "tmpl");
    }

    #[test]
    fn normalize_value_rejects_bare_when_not_allowed() {
        assert_eq!(normalize_value("bareword", false), "");
    }

    #[test]
    fn normalize_value_accepts_bare_when_allowed() {
        assert_eq!(normalize_value("bareword", true), "bareword");
    }

    #[test]
    fn normalize_value_accepts_numbers() {
        assert_eq!(normalize_value("42", false), "42");
        assert_eq!(normalize_value("-3.14", false), "-3.14");
    }
}
