//! NOTE: This functionality is probably better implemented in a library somewhere.
//! Spec: https://github.com/ethereum/consensus-specs/blob/v0.12.1/ssz/merkle-proofs.md

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Bytes, B256};
use alloy_rlp::BytesMut;
use sha2::{Digest, Sha256};
use ssz_types::VariableList;
use tree_hash::TreeHash;

use crate::primitives::TransactionSignedEcRecoveredWithBlobs;

const TREE_DEPTH: usize = 20; // log₂(MAX_TRANSACTIONS_PER_PAYLOAD)

type MaxBytesPerTransaction = typenum::U1073741824;
pub type BinaryTransaction = VariableList<u8, MaxBytesPerTransaction>;

#[inline]
fn sha_pair(a: &B256, b: &B256) -> B256 {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    B256::from_slice(&h.finalize())
}

fn ssz_leaf_root(data: &Bytes) -> B256 {
    let binary_tx = BinaryTransaction::from(data.to_vec());
    (*binary_tx.tree_hash_root()).into()
}

/// Generate merkle proof data needed to recompute transactions root after modifying the last transaction.
/// This function implements the exact SSZ VariableList tree structure to match tree_hash.
pub fn generate_transactions_merkle_proof(txs: &[Bytes]) -> Vec<B256> {
    assert!(!txs.is_empty(), "block has no transactions");

    let last_tx_index = txs.len() - 1;

    // Build the exact tree structure that SSZ VariableList uses
    build_ssz_variablelist_proof(txs, last_tx_index)
}

/// Build SSZ VariableList merkle proof using the exact tree structure that tree_hash uses
fn build_ssz_variablelist_proof(txs: &[Bytes], element_index: usize) -> Vec<B256> {
    // Step 1: Compute all leaf hashes
    let mut leaves: Vec<B256> = txs.iter().map(ssz_leaf_root).collect();

    // Step 2: Pad to the limit of the VariableList (2^20 for transactions)
    // SSZ always pads to the maximum possible size defined by the type
    let max_chunk_count = 1 << TREE_DEPTH; // 2^20 = 1,048,576

    // Resize to max_chunk_count with zero hashes
    leaves.resize(max_chunk_count, B256::ZERO);

    // Step 3: Build the merkle tree bottom-up and collect the proof
    let mut branch = Vec::new();
    let mut current_level = leaves;
    let mut current_index = element_index;

    // Build the complete tree to depth TREE_DEPTH (20 levels)
    for _level in 0..TREE_DEPTH {
        // Get the sibling at this level
        let sibling_index = current_index ^ 1;
        branch.push(current_level[sibling_index]);

        // Build next level up
        let mut next_level = Vec::new();
        for i in (0..current_level.len()).step_by(2) {
            let left = current_level[i];
            let right = current_level[i + 1];
            next_level.push(sha_pair(&left, &right));
        }

        current_level = next_level;
        current_index /= 2;

        // Stop when we reach the root
        if current_level.len() == 1 {
            break;
        }
    }

    branch
}

pub fn to_transaction_bytes(transactions: &[TransactionSignedEcRecoveredWithBlobs]) -> Vec<Bytes> {
    let mut buf = BytesMut::new();
    transactions
        .iter()
        .map(|tx| {
            tx.encode_2718(&mut buf);
            std::mem::take(&mut buf).freeze().into()
        })
        .collect::<Vec<_>>()
}
