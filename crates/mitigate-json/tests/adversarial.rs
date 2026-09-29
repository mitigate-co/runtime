//! Reproducible parser boundaries. All inputs are synthetic; no I/O or RNG.
use mitigate_json::{InvalidJson, parse};
use serde_json::{Value, json};

#[test]
fn exact_byte_depth_node_string_and_key_budgets_have_positive_controls() {
    let mut bytes = b"null".to_vec();
    bytes.resize(1_048_576, b' ');
    assert_eq!(parse(&bytes), Ok(Value::Null));
    bytes.push(b' ');
    assert_eq!(parse(&bytes), Err(InvalidJson));

    for (depth, accepted) in [(32, true), (33, false), (129, false)] {
        let input = format!("{}null{}", "[".repeat(depth), "]".repeat(depth));
        assert_eq!(parse(input.as_bytes()).is_ok(), accepted);
    }
    for (nodes, accepted) in [(32_767, true), (32_768, false)] {
        // The array itself consumes one node in addition to each null element.
        let input = format!("[{}null]", "null,".repeat(nodes - 1));
        assert_eq!(parse(input.as_bytes()).is_ok(), accepted);
    }
    for (length, accepted) in [(65_536, true), (65_537, false)] {
        let input = serde_json::to_vec(&"x".repeat(length)).unwrap();
        assert_eq!(parse(&input).is_ok(), accepted);
    }
    for (length, accepted) in [(32_768, true), (32_769, false)] {
        let input = serde_json::to_vec(&"é".repeat(length)).unwrap();
        assert_eq!(
            parse(&input).is_ok(),
            accepted,
            "string bound counts UTF-8 bytes"
        );
    }
    for (length, accepted) in [(4096, true), (4097, false)] {
        let input = serde_json::to_vec(&json!({("x".repeat(length)): null})).unwrap();
        assert_eq!(parse(&input).is_ok(), accepted);
    }
}

#[test]
fn escaped_duplicates_surrogates_and_trailing_values_are_unambiguous() {
    let rejected: &[&[u8]] = &[
        br#"{"id":1,"\u0069d":1}"#,
        br#"{"facts":{"name":0,"na\u006de":0}}"#,
        r#"{"facts":[{"\ud83d\ude00":true,"😀":true}]}"#.as_bytes(),
        br#""\ud800""#,
        br#""\udc00""#,
        br#""\ud800\u0041""#,
        br#"{"synthetic-content-canary":NaN}"#,
        br#"{"synthetic-content-canary":1e9999}"#,
        br#"{} {}"#,
        b"null\x00",
        b"\xef\xbb\xbf{}",
        b"\"\xff\"",
    ];
    for (index, input) in rejected.iter().enumerate() {
        assert_eq!(parse(input), Err(InvalidJson), "corpus case {index}");
        assert_eq!(format!("{:?}", parse(input).unwrap_err()), "InvalidJson");
    }
    assert_eq!(parse(br#""\ud83d\ude00""#), Ok(json!("😀")));
    assert_eq!(parse(br#"{"id":1,"ID":2}"#), Ok(json!({"id":1,"ID":2})));
}
