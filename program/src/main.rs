//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

// use alloy_sol_types::SolType;
use receipts_lib::{verify_mmpt_proof, TrieNode};

pub fn main() {
    // Read an input to the program.
    println!("cycle-tracker-start: io");
    println!("cycle-tracker-start: reading bytes");
    let encoded_proof = sp1_zkvm::io::read_vec();
    let encoded_root = sp1_zkvm::io::read_vec();
    let encoded_key = sp1_zkvm::io::read_vec();
    let encoded_expected_value = sp1_zkvm::io::read_vec();
    println!("cycle-tracker-end: reading bytes");

    println!("cycle-tracker-start: decomposing expected value into private and public parts");
    // TODO: split private and public portions- private is all of the receipt except the log we are interested in using on-chain
    println!("cycle-tracker-end: decomposing expected value into private and public parts");

    println!("cycle-tracker-start: serde");
    let proof_vector: Vec<TrieNode> = serde_cbor::from_slice(&encoded_proof).unwrap();
    let root_vector: Vec<u8> = serde_cbor::from_slice(&encoded_root).unwrap();
    let key_vector: Vec<u8> = serde_cbor::from_slice(&encoded_key).unwrap();
    let expected_value: &[u8] = serde_cbor::from_slice(&encoded_expected_value).unwrap();
    println!("cycle-tracker-end: serde");
    println!("cycle-tracker-end: io");

    let proof: &[TrieNode] = &proof_vector;
    if root_vector.len() != 32 {
        panic!("root_vector length is not 32");
    }
    let root: [u8; 32] = root_vector
        .try_into()
        .expect("root_vector must be exactly 32 bytes");

    if key_vector.len() != 32 {
        panic!("key_vector length is not 32");
    }
    let key: [u8; 32] = key_vector
        .try_into()
        .expect("key_vector must be exactly 32 bytes");

    println!("cycle-tracker-start: public inputs");
    sp1_zkvm::io::commit_slice(&root);
    sp1_zkvm::io::commit_slice(&key);
    sp1_zkvm::io::commit_slice(expected_value);
    println!("cycle-tracker-end: public inputs");

    // Verify the proof
    println!("cycle-tracker-start: verify_proof");
    let valid = verify_mmpt_proof(proof, &key, expected_value, &root);
    println!("cycle-tracker-end: verify_proof");
    println!("{}", valid)

    /*
        pub fn verify_recursive_proof(
        proof: &[TrieNode],    // The list of trie nodes from root to leaf
        key: &[u8; 32],        // The 32-byte hex key
        expected_value: &[u8], // Expected value at the leaf node
        root_hash: &[u8; 32],  // The root hash of the trie
    ) -> bool {
      */

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    // sp1_zkvm::io::commit_slice(&bytes);
}
