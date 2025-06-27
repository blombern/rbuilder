use alloy_primitives::U256;
use alloy_rpc_types_beacon::{
    BlsSignature,
    relay::{BidTrace, SignedBidSubmissionV2, SignedBidSubmissionV3, SignedBidSubmissionV4},
    requests::ExecutionRequestsV4,
};
use alloy_rpc_types_engine::{BlobsBundleV1, ExecutionPayloadV3};
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};

use crate::primitives::OrderId;

use super::adjustment::AdjustmentDataV2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ElectraSubmitBlockRequest {
    #[serde(flatten)]
    pub submission: SignedBidSubmissionV4,
    pub adjustment_data: AdjustmentDataV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DenebSubmitBlockRequest {
    #[serde(flatten)]
    pub submission: SignedBidSubmissionV3,
    pub adjustment_data: AdjustmentDataV2,
}

impl DenebSubmitBlockRequest {
    pub fn as_ssz_bytes(&self) -> Vec<u8> {
        self.submission.as_ssz_bytes()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapellaSubmitBlockRequest {
    #[serde(flatten)]
    pub submission: SignedBidSubmissionV2,
    pub adjustment_data: AdjustmentDataV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SubmitBlockRequest {
    Capella(CapellaSubmitBlockRequest),
    Deneb(DenebSubmitBlockRequest),
    Electra(ElectraSubmitBlockRequest),
}

impl SubmitBlockRequest {
    pub fn bid_trace(&self) -> &BidTrace {
        match self {
            SubmitBlockRequest::Capella(req) => &req.submission.message,
            SubmitBlockRequest::Deneb(req) => &req.submission.message,
            SubmitBlockRequest::Electra(req) => &req.submission.message,
        }
    }

    pub fn tx_count(&self) -> u32 {
        match self {
            SubmitBlockRequest::Capella(req) => req
                .submission
                .execution_payload
                .payload_inner
                .transactions
                .len() as u32,
            SubmitBlockRequest::Deneb(req) => req
                .submission
                .execution_payload
                .payload_inner
                .payload_inner
                .transactions
                .len() as u32,
            SubmitBlockRequest::Electra(req) => req
                .submission
                .execution_payload
                .payload_inner
                .payload_inner
                .transactions
                .len() as u32,
        }
    }

    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if let Ok(result) = SignedBidSubmissionV4::from_ssz_bytes(bytes) {
            return Ok(SubmitBlockRequest::Electra(ElectraSubmitBlockRequest {
                submission: result,
                adjustment_data: Default::default(),
            }));
        }
        if let Ok(result) = SignedBidSubmissionV3::from_ssz_bytes(bytes) {
            return Ok(SubmitBlockRequest::Deneb(DenebSubmitBlockRequest {
                submission: result,
                adjustment_data: Default::default(),
            }));
        }

        let result = SignedBidSubmissionV2::from_ssz_bytes(bytes)?;
        Ok(SubmitBlockRequest::Capella(CapellaSubmitBlockRequest {
            submission: result,
            adjustment_data: Default::default(),
        }))
    }
}

#[derive(Clone, Debug)]
pub struct BidMetadata {
    pub value: BidValueMetadata,
    pub order_ids: Vec<OrderId>,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct BidValueMetadata {
    pub coinbase_reward: U256,
    pub top_competitor_bid: Option<U256>,
}

#[derive(Clone, Debug)]
pub struct SubmitBlockRequestWithMetadata {
    pub submission: SubmitBlockRequest,
    pub metadata: BidMetadata,
}

/// Signed bid submission that is serialized without blobs bundle.
#[derive(Debug)]
pub struct SubmitBlockRequestNoBlobs<'a>(pub &'a SubmitBlockRequest);

impl serde::Serialize for SubmitBlockRequestNoBlobs<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.0 {
            SubmitBlockRequest::Capella(v2) => v2.serialize(serializer),
            SubmitBlockRequest::Deneb(v3) => {
                #[derive(serde::Serialize)]
                struct SignedBidSubmissionV3Ref<'a> {
                    message: &'a BidTrace,
                    #[serde(with = "alloy_rpc_types_beacon::payload::beacon_payload_v3")]
                    execution_payload: &'a ExecutionPayloadV3,
                    blobs_bundle: &'a BlobsBundleV1,
                    signature: &'a BlsSignature,
                }

                SignedBidSubmissionV3Ref {
                    message: &v3.submission.message,
                    execution_payload: &v3.submission.execution_payload,
                    blobs_bundle: &BlobsBundleV1::new([]), // override blobs bundle with empty one
                    signature: &v3.submission.signature,
                }
                .serialize(serializer)
            }
            SubmitBlockRequest::Electra(v4) => {
                #[derive(serde::Serialize)]
                struct SignedBidSubmissionV4Ref<'a> {
                    message: &'a BidTrace,
                    #[serde(with = "alloy_rpc_types_beacon::payload::beacon_payload_v3")]
                    execution_payload: &'a ExecutionPayloadV3,
                    blobs_bundle: &'a BlobsBundleV1,
                    execution_requests: &'a ExecutionRequestsV4,
                    signature: &'a BlsSignature,
                }

                SignedBidSubmissionV4Ref {
                    message: &v4.submission.message,
                    execution_payload: &v4.submission.execution_payload,
                    blobs_bundle: &BlobsBundleV1::new([]), // override blobs bundle with empty one
                    signature: &v4.submission.signature,
                    execution_requests: &v4.submission.execution_requests,
                }
                .serialize(serializer)
            }
        }
    }
}
