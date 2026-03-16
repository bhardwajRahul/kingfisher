use anyhow::Result;
use serde::Serialize;
use toon_format::{Delimiter, EncodeOptions, Indent};

fn llm_encode_options() -> EncodeOptions {
    EncodeOptions::new()
        .with_delimiter(Delimiter::Pipe)
        .with_indent(Indent::Spaces(2))
        .with_key_folding(toon_format::types::KeyFoldingMode::Safe)
        .with_flatten_depth(2)
}

pub fn encode_llm_friendly<T: Serialize>(value: &T) -> Result<String> {
    Ok(toon_format::encode(value, &llm_encode_options())?)
}
