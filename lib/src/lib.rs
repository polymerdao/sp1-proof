use rlp::RlpStream;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

// Verifies MMPT receipt proof by working from leaf to root node, hashing children and checking they are present in their parent
pub fn verify_receipt_proof(proof: Vec<Vec<u8>>, raw_log: Vec<u8>, root: [u8; 32]) -> bool {
    // TODO: is this secure? is it possible to emit a receipt that contains the bytes corresponding to specific log without actually containing that log?
    // This problem is definitely present in storage/state trie where a parent node can and often does commit to the same leaf values but at different storage keys with different meanings
    let mut contains = raw_log;
    let mut hash = [0u8; 32];
    for node in proof.iter().rev() {
        if !node
            .windows(contains.len())
            .any(|window| window == contains.as_slice())
        {
            return false;
        }
        hash = keccak256(node);
        contains = hash.to_vec()
    }
    // Check that the root node matches the provided root node
    if hash != root {
        // ignore the warning here, we have a guard above to check that proof is not empty so the above iteration will always occur
        return false;
    }
    true
}

#[derive(Serialize, Deserialize)]
pub enum TrieNode {
    Branch {
        children: Box<[Option<Vec<u8>>; 16]>, // 16 possible nibbles
        value: Option<Vec<u8>>,               // Stored value at this branch (if any)
    },
    Leaf {
        partial_path: Vec<u8>, // Compact-encoded partial path
        value: Vec<u8>,        // Value stored at this leaf node
    },
    Extension {
        partial_path: Vec<u8>, // Compact-encoded partial path
        next_node: Vec<u8>,    // Hash of the next node
    },
}

/// Converts a 32-byte hex key into nibbles (each byte -> two nibbles)
fn key_to_nibbles(key: &[u8; 32]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(64); // Each byte produces two nibbles
    for byte in key {
        nibbles.push(byte >> 4); // High nibble
        nibbles.push(byte & 0x0f); // Low nibble
    }
    nibbles
}

/// Hash a node using Keccak-256 hashing
fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}

fn encode_node(node: &TrieNode) -> Vec<u8> {
    let mut stream = RlpStream::new();
    match node {
        TrieNode::Branch { children, value } => {
            stream.begin_list(17);
            for child in children.iter() {
                match child {
                    Some(hash) => stream.append(hash), // Correctly convert array to slice
                    None => stream.append_empty_data(),
                };
            }
            if let Some(val) = value {
                stream.append(val); // Use reference to Vec<u8>
            } else {
                stream.append_empty_data();
            }
        }
        TrieNode::Leaf {
            partial_path,
            value,
        } => {
            stream.begin_list(2);
            stream.append(partial_path); // Use reference to Vec<u8>
            stream.append(value); // Use reference to Vec<u8>
        }
        TrieNode::Extension {
            partial_path,
            next_node,
        } => {
            stream.begin_list(2);
            stream.append(partial_path); // Use reference to Vec<u8>
            stream.append(next_node); // Correctly convert array to slice
        }
    }
    stream.out().to_vec()
}

// Verifies any MMPT proof by walking down from the parent to leaf, following the path prescribed by the provided key
// This has the advantage that we do not make the assumption that the child hash bytes can only appear in the parent node at the position we expect
// The disadvantages is that it is much more complicated
pub fn verify_mmpt_proof(
    proof: &[TrieNode],    // The list of trie nodes from root to leaf
    key: &[u8; 32],        // The 32-byte hex key
    expected_value: &[u8], // Expected value at the leaf node
    root_hash: &[u8; 32],  // The root hash of the trie
) -> bool {
    // Convert the 32-byte hex key into nibbles
    let full_key_nibbles = key_to_nibbles(key);

    // Start at the root and iterate down to the leaf
    let mut current_hash = *root_hash; // Start with the provided root hash
    let mut remaining_key_nibbles = full_key_nibbles.as_slice();

    for node in proof.iter() {
        match node {
            TrieNode::Branch { children, value } => {
                // If we have exhausted the key and we're at a branch with a value, we should check the value
                if remaining_key_nibbles.is_empty() {
                    // We expect this branch to contain the value
                    if let Some(branch_value) = value {
                        return branch_value == expected_value; // Verify if the value matches
                    } else {
                        return false; // No value found in this branch
                    }
                }

                // Otherwise, we follow the path of the next nibble in the key
                let nibble = remaining_key_nibbles[0] as usize;
                remaining_key_nibbles = &remaining_key_nibbles[1..]; // Remove the nibble we used

                if let Some(child_hash) = &children[nibble] {
                    // Hash the branch node and verify it matches the current hash
                    if keccak256(&encode_node(node)) != current_hash {
                        return false; // Hash mismatch
                    }

                    let child_hash_value: Vec<u8> = child_hash.clone();

                    if child_hash_value.len() != 32 {
                        panic!("child_hash length is not 32");
                    }
                    let child_hash_array: [u8; 32] = child_hash_value
                        .try_into()
                        .expect("child_hash must be exactly 32 bytes");

                    // Update the current hash to the hash of the child node
                    current_hash = child_hash_array;
                } else {
                    return false; // No child at the expected index
                }
            }
            TrieNode::Leaf {
                partial_path,
                value,
            } => {
                // Check if the remaining nibbles match the partial path in the leaf node
                if partial_path == remaining_key_nibbles && value == expected_value {
                    // Hash the leaf node and verify it matches the current hash
                    return keccak256(&encode_node(node)) == current_hash;
                } else {
                    return false; // Key or value mismatch
                }
            }
            TrieNode::Extension {
                partial_path,
                next_node,
            } => {
                // The partial path in the extension node should match the first part of the remaining key nibbles
                if remaining_key_nibbles.starts_with(partial_path) {
                    // Remove the matched portion of the key
                    remaining_key_nibbles = &remaining_key_nibbles[partial_path.len()..];

                    // Hash the extension node and verify it matches the current hash
                    if keccak256(&encode_node(node)) != current_hash {
                        return false; // Hash mismatch
                    }

                    let next_node_value: Vec<u8> = next_node.clone();
                    // Move to the next node (pointed to by the extension node)
                    if next_node.len() != 32 {
                        panic!("next_node length is not 32");
                    }
                    let next_node_array: [u8; 32] = next_node_value
                        .try_into()
                        .expect("child_hash must be exactly 32 bytes");
                    current_hash = next_node_array;
                } else {
                    return false; // Partial path mismatch
                }
            }
        }
    }

    // If we have exhausted the proof without matching the expected value, return false
    false
}
