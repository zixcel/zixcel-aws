mod support;

use zixcel_aws::{HeaderV1, OperationModeV1, QueryParameterV1, canonical_preview};

use support::request;

#[test]
fn matches_aws_sigv4_get_vanilla_vector() {
    let preview = canonical_preview(&request(OperationModeV1::Execute)).expect("canonical preview");
    assert_eq!(
        preview.canonical_request_sha256,
        "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
    );
    assert_eq!(preview.signed_header_names, ["host", "x-amz-date"]);
}

#[test]
fn matches_query_order_and_header_trim_vectors() {
    let mut query = request(OperationModeV1::Propose);
    query.request.input.request.query = vec![
        QueryParameterV1 {
            name: "Param2".to_owned(),
            value: "value2".to_owned(),
        },
        QueryParameterV1 {
            name: "Param1".to_owned(),
            value: "value1".to_owned(),
        },
    ];
    assert_eq!(
        canonical_preview(&query)
            .expect("query preview")
            .canonical_request_sha256,
        "816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0"
    );

    let mut headers = request(OperationModeV1::Propose);
    headers.request.input.request.headers = vec![
        HeaderV1 {
            name: "My-Header1".to_owned(),
            value: " value1 ".to_owned(),
        },
        HeaderV1 {
            name: "My-Header2".to_owned(),
            value: "\"a   b   c\"".to_owned(),
        },
    ];
    assert_eq!(
        canonical_preview(&headers)
            .expect("header preview")
            .canonical_request_sha256,
        "a726db9b0df21c14f559d0a978e563112acb1b9e05476f0a6a1c7d68f28605c7"
    );
}
