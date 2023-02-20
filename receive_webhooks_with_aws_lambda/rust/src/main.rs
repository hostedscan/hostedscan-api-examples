use lambda_http::{run, service_fn, Body, Error, Request, Response};
use serde::Deserialize;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use std::env;

type HmacSha256 = Hmac<Sha256>;

const HOSTEDSCAN_SIGNATURE_HEADER: &str = "X-HOSTEDSCAN-SIGNATURE";
const HOSTEDSCAN_TIMESTAMP_HEADER: &str = "X-HOSTEDSCAN-TIMESTAMP";

// See https://docs.hostedscan.com/webhooks/event-types for event type definitions
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum HostedScanEvent {
    #[serde(rename = "risk.opened")]
    RiskOpened(RiskOpenedOrClosedEvent),
    #[serde(rename = "risk.closed")]
    RiskClosed(RiskOpenedOrClosedEvent),
    #[serde(rename = "scan.succeeded")]
    ScanSucceeded(ScanSucceededEvent),
}

#[derive(Deserialize, Debug)]
struct RiskOpenedOrClosedEvent {
    data: RiskOpenedOrClosedData,
}

#[derive(Deserialize, Debug)]
struct RiskOpenedOrClosedData {
    id: String,
    target: String,
    risk_definition: RiskDefinition,
}

#[derive(Deserialize, Debug)]
struct ScanSucceededEvent {
    data: ScanSucceededData,
}

#[derive(Deserialize, Debug)]
struct RiskDefinition {
    title: String,
    threat_level: String,
    scan_type: String,
    // Fields below may not be populated by some scanners. Set them as Options. Otherwise messages without one of these fields will fail to deserialize.
    description: Option<String>,
    solution: Option<String>,
    references: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
struct ScanSucceededData {
    id: String,
    #[serde(rename = "type")]
    scan_type: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(service_fn(handler)).await?;
    Ok(())
}

async fn handler(request: Request) -> Result<Response<Body>, Error> {
    let result = async {
        // Get headers and message body
        let signature = request.headers().get(HOSTEDSCAN_SIGNATURE_HEADER).ok_or("missing signature header")?;
        let timestamp = request.headers().get(HOSTEDSCAN_TIMESTAMP_HEADER).ok_or("missing timestamp header")?;
        let body = std::str::from_utf8(request.body()).or(Err("invalid utf-8 sequence"))?;
        
        // Verify the webhook signature
        let secret = env::var("SIGNING_SECRET").or(Err("no signing secret configured"))?;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).or(Err("unexpected issue with HMAC"))?;
        mac.update(&[timestamp.as_bytes(), b".", body.as_bytes()].concat());
        let result = mac.finalize();
        let received = hex::decode(signature.to_str().or(Err("invalid signature string"))?).or(Err("invalid signature header"))?;
        let expected = result.into_bytes();
        if expected[..] != received[..] {
            println!("{:?}", request);
            return Err("received signature did not match expected")?;
        }
        
        // Handle the event
        let event = serde_json::from_str::<HostedScanEvent>(body).or(Err("not a valid hostedscan event"))?;
        match event {
            HostedScanEvent::RiskOpened(e) => {
                println!("Risk opened for target [{}] with id [{}], title [{}], and severity [{}]", e.data.target, e.data.id, e.data.risk_definition.title, e.data.risk_definition.threat_level);
                println!("Full event {:?}", e);
                // Open ticket or send other notifications here. Use the id to de-duplicate.
            }
            HostedScanEvent::RiskClosed(e) => {
                println!("Risk closed for target [{}] with id [{}]", e.data.target, e.data.id);
                println!("Full event {:?}", e);
                // Close ticket or send other notifications here. Use the id to de-duplicate.
            }
            _ => {
                // Do nothing for any other event types
            }
        }

        return Ok::<Response<Body>, Error>(Response::builder().status(200).body("success".into()).map_err(Box::new)?);
    }.await;

    match result {
        Ok(response) => return Ok(response),
        Err(err) => {
            println!("{}", err);
            // On error, return an http response with error code.
            // This is done because Lambda http functions will map a panic or other non-http response into a 200 success by default,
            // which is misleading and can also leak function internals from the unhandled error message.
            return Ok(Response::builder().status(400).body("invalid request".into()).map_err(Box::new)?);
        }
    };
}
