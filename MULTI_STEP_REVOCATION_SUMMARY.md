# Multi-Step Revocation Implementation Summary

## Overview

This implementation adds support for 2-step revocation processes in Kingfisher. Some API services require looking up an internal ID or metadata before the actual revocation/deletion can be performed.

## Changes Made

### 1. Core Types (`crates/kingfisher-rules/src/rule.rs`)

#### New Enum Variant
- Added `HttpMultiStep(HttpMultiStepRevocation)` to the `Revocation` enum

#### New Structures
- **`HttpMultiStepRevocation`**: Contains a vector of 1-2 sequential steps
- **`RevocationStep`**: Represents a single step with:
  - Optional step name
  - HTTP request configuration
  - Optional multipart config  
  - Optional variable extraction configuration
- **`ResponseExtractor`**: Enum for extracting values from responses:
  - `JsonPath`: Extract from JSON using JSONPath syntax
  - `Regex`: Extract using regex pattern with capture group
  - `Header`: Extract from response header
  - `Body`: Use entire response body
  - `StatusCode`: Extract HTTP status code

#### Restored Type
- **`TlsMode`**: Re-added enum that was previously removed (required by validation code)
  - Added `tls_mode` field to `RuleSyntax`
  - Added `tls_mode()` method to `Rule`

### 2. Execution Logic (`src/direct_revoke.rs`)

#### New Functions
- **`extract_value_from_response()`**: Extracts values from HTTP responses
  - Implements basic JSONPath parsing for nested objects and arrays
  - Regex extraction with first capture group
  - Header and body extraction
- **`execute_revocation_step()`**: Executes a single revocation step
  - Renders templates with current variables
  - Performs HTTP request
  - Extracts variables from response
  - Updates globals for next step
- **`execute_multi_step_revocation()`**: Orchestrates multi-step flow
  - Validates step count (1-2)
  - Executes steps sequentially
  - Returns result from final step

#### Updated Functions
- **`extract_revocation_vars()`**: Now handles `HttpMultiStep` variant
- **`run_direct_revocation()`**: Added match arm for `HttpMultiStep`

### 3. Module Exports (`crates/kingfisher-rules/src/lib.rs`)

Added exports for new types:
- `HttpMultiStepRevocation`
- `ResponseExtractor`
- `RevocationStep`
- `TlsMode` (restored)

### 4. Reporter Integration (`src/reporter.rs`)

Added pattern match arm for `Revocation::HttpMultiStep(_)` to generate revoke commands.

### 5. Documentation

#### Updated `docs/RULES.md`
- Added Section 2: "Multi-Step Revocation" with:
  - Overview and use cases
  - Response extractor types table
  - Multi-step schema documentation
  - Requirements and constraints
  - 4 comprehensive examples:
    1. Basic 2-step revocation
    2. Multiple extraction methods
    3. Complex JSONPath extraction
    4. Single-step migration path
  - Guidance on when to use multi-step vs single-step

#### New `docs/MULTI_STEP_REVOCATION.md`
- Complete implementation documentation
- Architecture details
- API reference
- Usage examples
- Testing guidance
- Error handling information
- Debug logging instructions

### 6. Examples

Created `crates/kingfisher-rules/data/rules/example_multistep.yml` with 5 example rules:
1. Basic 2-step with JSON extraction
2. Multiple extractions (JSON, Header, nested)
3. Regex extraction from XML
4. Single-step for comparison
5. Array extraction from JSON

## Features

### JSONPath Support
Basic implementation supporting:
- Nested fields: `$.data.user.id`
- Array indexing: `$.items[0].id`  
- Combined: `$.data.sessions[0].session_id`

### Variable Flow
- Variables from step 1 available in step 2
- All standard Liquid filters work on extracted variables
- Variables are uppercase by convention

### Validation
- Minimum 1, maximum 2 steps
- Final step requires `response_matcher`
- Intermediate steps are optional
- Clear error messages for all failure cases

## Backwards Compatibility

All existing revocation types continue to work:
- `Revocation::AWS` ✓
- `Revocation::GCP` ✓  
- `Revocation::Http(_)` ✓
- Single-step YAML format unchanged

## Testing

### Manual Testing
```bash
# Test with example rule
kingfisher revoke --rule kingfisher.example_multistep.1 <token>

# With debug logging
RUST_LOG=debug kingfisher revoke --rule <rule_id> <token>
```

### Validation
```bash
# Compile check
cargo check

# Run existing tests
cargo test

# Specific revocation tests
cargo test revoke
```

## Example Usage

### YAML Configuration
```yaml
revocation:
  type: HttpMultiStep
  content:
    steps:
      - name: lookup_id
        request:
          method: GET
          url: https://api.example.com/tokens/current
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - type: StatusMatch
              status: [200]
        extract:
          TOKEN_ID:
            type: JsonPath
            path: "$.data.id"
      
      - name: delete
        request:
          method: DELETE
          url: https://api.example.com/tokens/{{ TOKEN_ID }}
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - type: StatusMatch
              status: [204]
```

### CLI Usage
```bash
# Revoke using multi-step rule
kingfisher revoke --rule example.service <token>

# With additional variables
kingfisher revoke --rule example.service --var EXTRA=value <token>

# JSON output
kingfisher revoke --rule example.service --format json <token>
```

## Files Modified

### Core Implementation
- `crates/kingfisher-rules/src/rule.rs` (+115 lines)
- `crates/kingfisher-rules/src/lib.rs` (+3 exports)
- `src/direct_revoke.rs` (+180 lines)
- `src/reporter.rs` (+8 lines)

### Documentation
- `docs/RULES.md` (+240 lines)
- `docs/MULTI_STEP_REVOCATION.md` (new file, 350 lines)
- `MULTI_STEP_REVOCATION_SUMMARY.md` (this file)

### Examples
- `crates/kingfisher-rules/data/rules/example_multistep.yml` (new file, 230 lines)

## Compilation Status

✅ Code compiles successfully with no warnings
```
cargo check
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.51s
```

## Future Enhancements

Potential improvements for future versions:
1. Support for more than 2 steps (if needed)
2. Enhanced JSONPath implementation (more complex queries)
3. Conditional step execution based on response values
4. Parallel step execution where dependencies allow
5. Step retry logic with different parameters per step
6. Response caching between steps
7. Variable transformation functions beyond Liquid filters

## Migration Guide

For existing single-step revocations, no changes are needed. To convert to multi-step:

**Before (single-step):**
```yaml
revocation:
  type: Http
  content:
    request:
      method: DELETE
      url: https://api.example.com/tokens/revoke
      headers:
        Authorization: "Bearer {{ TOKEN }}"
      response_matcher:
        - type: StatusMatch
          status: [204]
```

**After (multi-step with lookup):**
```yaml
revocation:
  type: HttpMultiStep
  content:
    steps:
      - name: lookup_id
        request:
          method: GET
          url: https://api.example.com/tokens/current
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - type: StatusMatch
              status: [200]
        extract:
          TOKEN_ID:
            type: JsonPath
            path: "$.id"
      
      - name: delete
        request:
          method: DELETE
          url: https://api.example.com/tokens/{{ TOKEN_ID }}
          headers:
            Authorization: "Bearer {{ TOKEN }}"
          response_matcher:
            - type: StatusMatch
              status: [204]
```

## Constraints

- Maximum 2 steps per revocation
- Steps execute sequentially (no parallelism)
- Final step must have `response_matcher`
- JSONPath implementation is basic (common patterns only)
- Variables flow forward only (step 1 → step 2)

## Error Handling

Clear error messages for:
- Invalid step count (< 1 or > 2)
- Missing response_matcher on final step
- Variable extraction failures with context
- Invalid JSONPath expressions
- Missing headers or response fields
- HTTP request failures with retry logic

## Debug Output

When `RUST_LOG=debug` is set:
- Step execution start/end
- URLs being called (with rendered templates)
- Variables extracted with values
- Response status codes
- Intermediate step completion
- Error details with stack traces

## Questions & Support

For questions or issues:
1. Check `docs/RULES.md` for detailed examples
2. Review `docs/MULTI_STEP_REVOCATION.md` for implementation details
3. Examine `crates/kingfisher-rules/data/rules/example_multistep.yml` for working examples
4. Enable debug logging: `RUST_LOG=debug kingfisher revoke ...`
