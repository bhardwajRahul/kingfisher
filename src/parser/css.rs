use anyhow::Result;
use cssparser::{
    parse_important, AtRuleParser, CowRcStr, DeclarationParser, ParseError, Parser, ParserInput,
    ParserState, RuleBodyItemParser, RuleBodyParser, StyleSheetParser, ToCss, Token,
};

pub(super) fn stream_context_candidates<F>(source: &[u8], sink: &mut F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    let css = String::from_utf8_lossy(source);
    if css.trim().is_empty() {
        return Ok(());
    }

    let mut input = ParserInput::new(&css);
    let mut parser = Parser::new(&mut input);
    let mut collector = Collector { sink, stopped: false };
    for _ in StyleSheetParser::new(&mut parser, &mut collector) {}
    Ok(())
}

struct Collector<'a, F> {
    sink: &'a mut F,
    stopped: bool,
}

impl<'a, F> Collector<'a, F>
where
    F: FnMut(&str) -> bool,
{
    fn emit(&mut self, name: &str, value: &str) {
        if self.stopped {
            return;
        }
        let candidate = format!("{name} = {value}");
        self.stopped = !(self.sink)(&candidate);
    }
}

impl<'i, F> DeclarationParser<'i> for Collector<'_, F>
where
    F: FnMut(&str) -> bool,
{
    type Declaration = ();
    type Error = ();

    fn parse_value<'t>(
        &mut self,
        name: CowRcStr<'i>,
        input: &mut Parser<'i, 't>,
        _declaration_start: &ParserState,
    ) -> Result<(), ParseError<'i, ()>> {
        let mut values = Vec::new();
        let mut important = false;
        loop {
            let start = input.state();
            let token = match input.next_including_whitespace().cloned() {
                Ok(token) => token,
                Err(_) => break,
            };

            if token == Token::Delim('!') {
                input.reset(&start);
                if parse_important(input).is_ok() && input.is_exhausted() {
                    important = true;
                    break;
                }
                input.reset(&start);
            }

            collect_token_values(token, input, &mut values);
        }

        if values.is_empty() && !important {
            return Ok(());
        }

        if values.is_empty() && important {
            values.push("important".to_string());
        }

        for value in values {
            self.emit(&name, &value);
            if self.stopped {
                break;
            }
        }
        Ok(())
    }
}

impl<'i, F> AtRuleParser<'i> for Collector<'_, F>
where
    F: FnMut(&str) -> bool,
{
    type Prelude = ();
    type AtRule = ();
    type Error = ();
}

impl<'i, F> cssparser::QualifiedRuleParser<'i> for Collector<'_, F>
where
    F: FnMut(&str) -> bool,
{
    type Prelude = ();
    type QualifiedRule = ();
    type Error = ();

    fn parse_prelude<'t>(&mut self, input: &mut Parser<'i, 't>) -> Result<(), ParseError<'i, ()>> {
        while input.next_including_whitespace().is_ok() {}
        Ok(())
    }

    fn parse_block<'t>(
        &mut self,
        _prelude: (),
        _start: &ParserState,
        input: &mut Parser<'i, 't>,
    ) -> Result<(), ParseError<'i, ()>> {
        for _ in RuleBodyParser::new(input, self) {}
        Ok(())
    }
}

impl<F> RuleBodyItemParser<'_, (), ()> for Collector<'_, F>
where
    F: FnMut(&str) -> bool,
{
    fn parse_qualified(&self) -> bool {
        true
    }

    fn parse_declarations(&self) -> bool {
        true
    }
}

fn collect_token_values<'i, 't>(
    token: Token<'i>,
    input: &mut Parser<'i, 't>,
    values: &mut Vec<String>,
) {
    match token {
        Token::QuotedString(value) => values.push(value.to_string()),
        Token::UnquotedUrl(value) => values.push(value.to_string()),
        Token::Ident(value) => values.push(value.to_string()),
        Token::Hash(value) | Token::IDHash(value) => values.push(value.to_string()),
        Token::Number { .. }
        | Token::Percentage { .. }
        | Token::Dimension { .. }
        | Token::Function(_) => {
            values.push(token.to_css_string());
            if matches!(token, Token::Function(_)) {
                let _ = input.parse_nested_block(|nested| {
                    while let Ok(next) = nested.next_including_whitespace().cloned() {
                        collect_token_values(next, nested, values);
                    }
                    Ok::<(), ParseError<'i, ()>>(())
                });
            }
        }
        Token::ParenthesisBlock | Token::SquareBracketBlock | Token::CurlyBracketBlock => {
            let _ = input.parse_nested_block(|nested| {
                while let Ok(next) = nested.next_including_whitespace().cloned() {
                    collect_token_values(next, nested, values);
                }
                Ok::<(), ParseError<'i, ()>>(())
            });
        }
        _ => {}
    }
}
