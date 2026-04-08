use anyhow::Result;
use tl::{Node, ParserOptions};

use super::{css, lexer, Language};

pub(super) fn stream_context_candidates<F>(source: &[u8], sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let html = String::from_utf8_lossy(source);
    if html.trim().is_empty() {
        return Ok(());
    }

    let dom = match tl::parse(&html, ParserOptions::default()) {
        Ok(dom) => dom,
        Err(_) => return Ok(()),
    };
    let parser = dom.parser();

    for node in dom.nodes() {
        let Some(tag) = node.as_tag() else {
            continue;
        };
        let tag_name = tag.name().as_utf8_str().to_string();

        for (key, value) in tag.attributes().iter() {
            let Some(value) = value else {
                continue;
            };
            let candidate = format!("{key} = {value}");
            if !sink(&candidate) {
                return Ok(());
            }
        }

        let inner_text = tag.inner_text(parser).trim().to_string();
        match tag_name.as_str() {
            "script" => {
                let candidate = format!("<script> = {inner_text}");
                if !inner_text.is_empty() && !sink(&candidate) {
                    return Ok(());
                }
                lexer::stream_context_candidates(
                    inner_text.as_bytes(),
                    &Language::JavaScript,
                    sink,
                )?;
            }
            "style" => {
                if !inner_text.is_empty() {
                    css::stream_context_candidates(inner_text.as_bytes(), sink)?;
                }
            }
            _ => {
                if !inner_text.is_empty()
                    && !matches!(node, Node::Comment(_))
                    && !sink(&format!("{tag_name} = {inner_text}"))
                {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}
