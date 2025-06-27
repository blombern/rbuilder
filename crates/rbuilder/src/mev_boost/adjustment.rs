use alloy_consensus::Bytes48;
use alloy_primitives::{Address, B256, Bloom, Bytes, U256};
use alloy_rpc_types_beacon::{BlsSignature, relay::BidTrace, requests::ExecutionRequestsV4};
use serde_with::{DisplayFromStr, serde_as};
use ssz_types::{FixedVector, VariableList};
use tree_hash::TreeHash;

use super::submission::SubmitBlockRequest;

#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
    ssz_derive::Decode,
    ssz_derive::Encode,
)]
pub struct AdjustmentDataV2 {
    pub el_transactions_root: B256,
    pub el_withdrawals_root: B256,
    pub builder_address: Address,
    pub builder_proof: Vec<Bytes>,
    pub fee_recipient_address: Address,
    pub fee_recipient_proof: Vec<Bytes>,
    pub fee_payer_address: Address,
    pub fee_payer_proof: Vec<Bytes>,
    pub el_placeholder_transaction_proof: Vec<Bytes>,
    pub cl_placeholder_transaction_proof: Vec<B256>,
    pub placeholder_receipt_proof: Vec<Bytes>,
    pub pre_payment_logs_bloom: Bloom,
}

/// Deneb ExecutionPayloadHeader
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/beacon-chain.md#executionpayloadheader
#[serde_as]
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    ssz_derive::Decode,
    ssz_derive::Encode,
    Default,
    PartialEq,
    Eq,
)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPayloadHeaderV3 {
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: Bloom,
    pub prev_randao: B256,
    #[serde_as(as = "DisplayFromStr")]
    pub block_number: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub gas_limit: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub gas_used: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub timestamp: u64,
    pub extra_data: Bytes,
    #[serde_as(as = "DisplayFromStr")]
    pub base_fee_per_gas: U256,
    pub block_hash: B256,
    pub transactions_root: B256,
    pub withdrawals_root: B256,
    #[serde_as(as = "DisplayFromStr")]
    pub blob_gas_used: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub excess_blob_gas: u64,
}

#[derive(
    Debug, Clone, serde::Serialize, serde::Deserialize, ssz_derive::Encode, ssz_derive::Decode,
)]
pub struct AdjustableHeaderSubmissionV4 {
    pub bid_trace: BidTrace,
    pub execution_payload_header: ExecutionPayloadHeaderV3,
    pub execution_requests: ExecutionRequestsV4,
    pub commitments: Vec<Bytes48>,
    pub adjustment_data: AdjustmentDataV2,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    ssz_derive::Encode,
    ssz_derive::Decode,
)]
pub struct SignedMessage<T: ssz::Encode + ssz::Decode> {
    pub message: T,
    pub signature: BlsSignature,
}

pub type SignedAdjustableHeaderSubmissionV4 = SignedMessage<AdjustableHeaderSubmissionV4>;

impl From<&SubmitBlockRequest> for SignedAdjustableHeaderSubmissionV4 {
    fn from(s: &SubmitBlockRequest) -> Self {
        match s {
            SubmitBlockRequest::Electra(s) => {
                let bid_trace = s.submission.message.clone();
                let execution_payload_header = ExecutionPayloadHeaderV3 {
                    parent_hash: s
                        .submission
                        .execution_payload
                        .payload_inner
                        .payload_inner
                        .parent_hash,
                    fee_recipient: s
                        .submission
                        .execution_payload
                        .payload_inner
                        .payload_inner
                        .fee_recipient,
                    state_root: s
                        .submission
                        .execution_payload
                        .payload_inner
                        .payload_inner
                        .state_root,
                    receipts_root: s
                        .submission
                        .execution_payload
                        .payload_inner
                        .payload_inner
                        .receipts_root,
                    logs_bloom: s
                        .submission
                        .execution_payload
                        .payload_inner
                        .payload_inner
                        .logs_bloom,
                    prev_randao: s
                        .submission
                        .execution_payload
                        .payload_inner
                        .payload_inner
                        .prev_randao,
                    block_number: s
                        .submission
                        .execution_payload
                        .payload_inner
                        .payload_inner
                        .block_number,
                    gas_limit: s
                        .submission
                        .execution_payload
                        .payload_inner
                        .payload_inner
                        .gas_limit,
                    gas_used: s
                        .submission
                        .execution_payload
                        .payload_inner
                        .payload_inner
                        .gas_used,
                    timestamp: s
                        .submission
                        .execution_payload
                        .payload_inner
                        .payload_inner
                        .timestamp,
                    extra_data: s
                        .submission
                        .execution_payload
                        .payload_inner
                        .payload_inner
                        .extra_data
                        .clone(),
                    base_fee_per_gas: s
                        .submission
                        .execution_payload
                        .payload_inner
                        .payload_inner
                        .base_fee_per_gas,
                    block_hash: s
                        .submission
                        .execution_payload
                        .payload_inner
                        .payload_inner
                        .block_hash,
                    transactions_root: compute_transactions_root(
                        &s.submission
                            .execution_payload
                            .payload_inner
                            .payload_inner
                            .transactions[..],
                    ),
                    withdrawals_root: compute_withdrawals_root(
                        &s.submission.execution_payload.withdrawals()[..],
                    ),
                    blob_gas_used: s.submission.execution_payload.blob_gas_used,
                    excess_blob_gas: s.submission.execution_payload.excess_blob_gas,
                };
                let execution_requests = s.submission.execution_requests.clone();
                let commitments = s.submission.blobs_bundle.commitments.clone();
                let adjustment_data = s.adjustment_data.clone();

                let message = AdjustableHeaderSubmissionV4 {
                    bid_trace,
                    execution_payload_header,
                    execution_requests,
                    commitments,
                    adjustment_data,
                };
                let signature = s.submission.signature;

                SignedAdjustableHeaderSubmissionV4 { message, signature }
            }
            _ => todo!(),
        }
    }
}

type MaxBytesPerTransaction = typenum::U1073741824;
type MaxTransactionsPerPayload = typenum::U1048576;
type MaxWithdrawalsPerPayload = typenum::U16;
type BinaryTransaction = VariableList<u8, MaxBytesPerTransaction>;

pub fn compute_transactions_root(transactions: &[Bytes]) -> B256 {
    let transactions: VariableList<BinaryTransaction, MaxTransactionsPerPayload> =
        VariableList::from(
            transactions
                .iter()
                .map(|bytes| BinaryTransaction::from(bytes.to_vec()))
                .collect::<Vec<_>>(),
        );
    (*transactions.tree_hash_root()).into()
}

#[derive(tree_hash_derive::TreeHash)]
struct TreeHashAddress {
    inner: FixedVector<u8, typenum::U20>,
}

impl From<Address> for TreeHashAddress {
    fn from(address: Address) -> Self {
        Self {
            inner: FixedVector::from(address.to_vec()),
        }
    }
}

#[derive(tree_hash_derive::TreeHash)]
struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: TreeHashAddress,
    pub amount: u64,
}

pub fn compute_withdrawals_root(withdrawals: &[alloy_rpc_types::Withdrawal]) -> B256 {
    let withdrawals: VariableList<Withdrawal, MaxWithdrawalsPerPayload> = VariableList::from(
        withdrawals
            .to_owned()
            .iter()
            .copied()
            .map(|w| Withdrawal {
                index: w.index,
                validator_index: w.validator_index,
                address: TreeHashAddress::from(w.address),
                amount: w.amount,
            })
            .collect::<Vec<_>>(),
    );
    B256::from_slice(&withdrawals.tree_hash_root()[..])
}

#[derive(ssz_derive::Encode, serde::Serialize)]
pub struct HeaderSubmissionV3 {
    pub url: Vec<u8>,
    pub tx_count: u32,
    pub submission: SignedAdjustableHeaderSubmissionV4,
}
