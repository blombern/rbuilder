use std::sync::Arc;
use dashmap::DashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use alloy_rpc_types_beacon::BlsSignature;
use crate::mev_boost::submission::SubmitBlockRequestWithMetadata;

#[derive(Debug, Clone, Serialize, Deserialize, ssz_derive::Encode, ssz_derive::Decode, tree_hash_derive::TreeHash)]
pub struct GetPayloadV3 {
    pub block_hash: B256,
    pub request_ts: u64,
    pub relay_public_key: alloy_rpc_types_beacon::BlsPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, ssz_derive::Encode, ssz_derive::Decode)]
pub struct SignedGetPayloadV3 {
    pub message: GetPayloadV3,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone)]
pub struct TimestampedPayload {
    payload: SubmitBlockRequestWithMetadata,
    stored_at: Instant,
}

/// Global in-memory storage for SubmitBlockRequest payloads with timestamps
pub static PAYLOAD_STORAGE: OnceLock<Arc<DashMap<B256, TimestampedPayload>>> = OnceLock::new();

/// Store a payload using the block hash as the key
pub fn store_payload(block_hash: B256, payload: SubmitBlockRequestWithMetadata) {
    let storage = PAYLOAD_STORAGE.get_or_init(|| Arc::new(DashMap::new()));
    let timestamped = TimestampedPayload {
        payload,
        stored_at: Instant::now(),
    };
    storage.insert(block_hash, timestamped);
}

/// Retrieve a payload by block hash
pub fn get_payload(block_hash: &B256) -> Option<SubmitBlockRequestWithMetadata> {
    let storage = PAYLOAD_STORAGE.get_or_init(|| Arc::new(DashMap::new()));
    storage.get(block_hash).map(|entry| entry.payload.clone())
}

/// Get all stored payloads
pub fn get_all_payloads() -> Vec<(B256, SubmitBlockRequestWithMetadata)> {
    let storage = PAYLOAD_STORAGE.get_or_init(|| Arc::new(DashMap::new()));
    storage.iter().map(|entry| (*entry.key(), entry.payload.clone())).collect()
}

/// Get the number of stored payloads
pub fn get_payload_count() -> usize {
    let storage = PAYLOAD_STORAGE.get_or_init(|| Arc::new(DashMap::new()));
    storage.len()
}

/// Remove expired payloads (older than 2 minutes)
pub fn cleanup_expired_payloads() {
    let storage = PAYLOAD_STORAGE.get_or_init(|| Arc::new(DashMap::new()));
    let cutoff = Instant::now() - Duration::from_secs(120); // 2 minutes
    
    storage.retain(|_key, value| value.stored_at > cutoff);
}

/// Start the automatic cleanup task
pub fn start_cleanup_task() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(30)); // Clean every 30 seconds
        loop {
            interval.tick().await;
            cleanup_expired_payloads();
        }
    });
}
