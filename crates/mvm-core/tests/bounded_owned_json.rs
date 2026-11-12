use mvm_core::bounded_owned_json::{JsonShapeLimits, validate_shape};

fn limits() -> JsonShapeLimits {
    JsonShapeLimits {
        bytes: 65536,
        nodes: 1024,
        depth: 32,
        text: 65536,
    }
}

#[test]
fn borrowed_preparse_accepts_original_owned_profile() {
    validate_shape(
        br#"{"operation":"bounded","body":[1,true,null,"a"]}"#,
        limits(),
    )
    .unwrap();
}

#[test]
fn exact_node_depth_text_limits_include_keys_and_decoded_escapes() {
    let mut bound = limits();
    bound.nodes = 3;
    bound.depth = 1;
    bound.text = 2;
    validate_shape(br#"{"a":"\u0062"}"#, bound).unwrap();
    bound.nodes = 2;
    assert!(validate_shape(br#"{"a":"b"}"#, bound).is_err());
    bound = limits();
    bound.depth = 1;
    assert!(validate_shape(b"[[0]]", bound).is_err());
    bound = limits();
    bound.text = 1;
    assert!(validate_shape(br#"{"a":"b"}"#, bound).is_err());
}

#[test]
fn bytes_and_trailing_json_are_refused() {
    let mut bound = limits();
    bound.bytes = 1;
    assert!(validate_shape(b"[]", bound).is_err());
    assert!(validate_shape(b"0 1", limits()).is_err());
}

#[test]
fn inspected_shape_counts_the_same_borrowed_walk_before_owned_decode() {
    let shape =
        mvm_core::bounded_owned_json::inspect_shape(br#"{"a":"\u0062","list":[0,true]}"#, limits())
            .unwrap();
    assert_eq!(shape.nodes, 7);
    assert_eq!(shape.text_bytes, 6);
    assert!(mvm_core::bounded_owned_json::inspect_shape(b"0 1", limits()).is_err());
}
