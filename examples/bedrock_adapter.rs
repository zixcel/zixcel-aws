use zixcel_aws::adapters::bedrock::{BedrockMantleInput, sign_request};
use zixcel_aws::prepare;

fn main() -> Result<(), zixcel_aws::AwsError> {
    let request = sign_request(BedrockMantleInput {
        request_id: "request-bedrock-example".to_owned(),
        credential_ref: concat!(
            "secret://aws/tenant-example/zixcel-aws/",
            "amazon-bedrock-model-request/aws/primary"
        )
        .to_owned(),
        subject: "subject-example".to_owned(),
        device: "device-example".to_owned(),
        workload: "spiffe://zixcel.local/workload/hatter-example".to_owned(),
        grant: "grant-example".to_owned(),
        region: "ap-northeast-1".to_owned(),
        timestamp: "20150830T123600Z".to_owned(),
        expires_at_epoch_seconds: 1_440_938_460,
        payload_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_owned(),
    });
    let plan = prepare(&request)?;
    assert!(
        plan.steps
            .iter()
            .all(|step| !step.external_network_required)
    );
    Ok(())
}
