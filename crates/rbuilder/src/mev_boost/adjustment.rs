use alloy_primitives::{Address, Bytes, B256};

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
pub struct AdjustmentData {
    pub state_root: B256,
    pub transactions_root: B256,
    pub receipts_root: B256,
    pub builder_address: Address,
    pub builder_proof: Vec<Bytes>,
    pub fee_recipient_address: Address,
    pub fee_recipient_proof: Vec<Bytes>,
    pub fee_payer_address: Address,
    pub fee_payer_proof: Vec<Bytes>,
    pub placeholder_transaction_proof: Vec<Bytes>,
    pub placeholder_receipt_proof: Vec<Bytes>,
}
