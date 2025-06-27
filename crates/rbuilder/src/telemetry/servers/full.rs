//! Telemetry helps track what is happening in the running application using metrics and tracing.
//!
//! Interface to telemetry should be set of simple functions like:
//! fn record_event(event_data)
//!
//! All internals are global variables.
//!
//! Full server may expose metrics that could leak information when running tdx.

use alloy_primitives::{hex, B256};
use ssz::{Decode, Encode};
use std::net::SocketAddr;
use tree_hash::TreeHash;
use warp::{Filter, Rejection, Reply};

use crate::{
    mev_boost::submission::SubmitBlockRequest,
    telemetry::{
        get_payload, get_payload_count,
        metrics::{gather_prometheus_metrics, set_version},
        start_cleanup_task, SignedGetPayloadV3, REGISTRY,
    },
    utils::build_info::Version,
};

pub async fn spawn(addr: SocketAddr, version: Version) -> eyre::Result<()> {
    set_version(version);

    // Start the automatic payload cleanup task
    start_cleanup_task();

    // metrics over /debug/metrics/prometheus
    let metrics_route = warp::path!("debug" / "metrics" / "prometheus").and_then(metrics_handler);

    // payload retrieval endpoint according to optimistic v3 spec
    let get_payload_v3 = warp::path("get_payload_v3")
        .and(warp::post())
        .and(warp::body::bytes())
        .and_then(get_payload_v3_handler);

    // simple count endpoint
    let payload_count = warp::path("payload_count")
        .and(warp::get())
        .and_then(payload_count_handler);

    let routes = metrics_route.or(get_payload_v3).or(payload_count);
    tokio::spawn(warp::serve(routes).run(addr));

    Ok(())
}

async fn metrics_handler() -> Result<impl Reply, Rejection> {
    Ok(gather_prometheus_metrics(&REGISTRY))
}

const BUILDER_DOMAIN: [u8; 4] = hex!("00000001");
const GENESIS_FORK_VERSION_HOODI: [u8; 4] = hex!("10000910");
const GENESIS_VALIDATORS_ROOT_HOODI: B256 = B256::ZERO;

#[derive(tree_hash_derive::TreeHash)]
struct ForkData {
    current_version: [u8; 4],
    genesis_validators_root: B256,
}

#[derive(tree_hash_derive::TreeHash)]
struct SigningData {
    root: B256,
    domain: [u8; 32],
}

fn compute_signing_root<T: TreeHash>(data: &T) -> B256 {
    let root = data.tree_hash_root();
    let domain = compute_domain(
        BUILDER_DOMAIN,
        GENESIS_FORK_VERSION_HOODI,
        GENESIS_VALIDATORS_ROOT_HOODI,
    );
    let signing_data = SigningData {
        root: B256::from_slice(&root.0),
        domain,
    };

    B256::from_slice(&signing_data.tree_hash_root().0)
}

fn compute_domain(domain_type: [u8; 4], fork_version: [u8; 4], validators_root: B256) -> [u8; 32] {
    let fork_data_root = &ForkData {
        current_version: fork_version,
        genesis_validators_root: validators_root,
    }
    .tree_hash_root();

    let mut domain = [0; 32];
    domain[..4].copy_from_slice(&domain_type[..4]);
    domain[4..].copy_from_slice(&fork_data_root[..28]);

    domain
}

/// Verify the signature of a SignedGetPayloadV3 request
fn verify_get_payload_signature(req: &SignedGetPayloadV3) -> bool {
    let pk = bls::PublicKey::deserialize(&req.message.relay_public_key[..])
        .expect("failed to deserialize pubkey");
    let sig =
        bls::Signature::deserialize(&req.signature[..]).expect("failed to deserialize signature");

    let root = compute_signing_root(&req.message);

    sig.verify(&pk, (*root).into())
}

async fn get_payload_v3_handler(
    bytes: warp::hyper::body::Bytes,
) -> Result<Box<dyn Reply>, Rejection> {
    let block_hash = if let Ok(signed_request) = SignedGetPayloadV3::from_ssz_bytes(&bytes) {
        // Verify the signature
        if !verify_get_payload_signature(&signed_request) {
            return Ok(Box::new(warp::reply::with_status(
                "Invalid signature".to_string(),
                warp::http::StatusCode::UNAUTHORIZED,
            )));
        }
        signed_request.message.block_hash
    } else {
        return Ok(Box::new(warp::reply::with_status(
            "Invalid request format".to_string(),
            warp::http::StatusCode::BAD_REQUEST,
        )));
    };

    // Get the payload by block hash
    match get_payload(&block_hash) {
        Some(payload) => {
            // Return the payload as SSZ bytes according to the spec
            let bytes = match &payload.submission {
                SubmitBlockRequest::Electra(s) => s.submission.as_ssz_bytes(),
                SubmitBlockRequest::Deneb(s) => s.submission.as_ssz_bytes(),
                SubmitBlockRequest::Capella(s) => s.submission.as_ssz_bytes(),
            };

            Ok(Box::new(warp::reply::with_header(
                bytes,
                "Content-Type",
                "application/octet-stream",
            )))
        }
        None => Ok(Box::new(warp::reply::with_status(
            "Payload not found".to_string(),
            warp::http::StatusCode::NOT_FOUND,
        ))),
    }
}

async fn payload_count_handler() -> Result<impl Reply, Rejection> {
    let count = get_payload_count();
    Ok(warp::reply::json(&serde_json::json!({"count": count})))
}
