//use crate::channel_commit::CommitmentGadget;
use crate::MerkleTreeProof;
use bitvm::bigint::bits::limb_to_be_bits_toaltstack;
use bitvm::treepp::*;

pub struct MerkleTreeGadget;

impl MerkleTreeGadget {
    pub fn push_merkle_tree_proof(merkle_proof: &MerkleTreeProof) -> Script {
        script! {
            { merkle_proof.leaf.to_vec() }  // Convert [u8; 32] to Vec<u8>
            for elem in merkle_proof.siblings.iter() {
                { elem.to_vec() }  // Convert each [u8; 32] to Vec<u8>
            }
        }
    }

    pub(crate) fn query_and_verify_internal(logn: usize, is_sibling: bool) -> Script {
        script! {
            OP_DEPTH OP_1SUB OP_ROLL
            OP_DUP

            if is_sibling {
                OP_DEPTH OP_1SUB OP_ROLL
                OP_FROMALTSTACK OP_NOTIF OP_SWAP OP_ENDIF
                OP_CAT OP_SHA256

                for _ in 1..logn {
                    OP_DEPTH OP_1SUB OP_ROLL
                    OP_FROMALTSTACK OP_IF OP_SWAP OP_ENDIF
                    OP_CAT OP_SHA256
                }
            } else {
                for _ in 0..logn {
                    OP_DEPTH OP_1SUB OP_ROLL
                    OP_FROMALTSTACK OP_IF OP_SWAP OP_ENDIF
                    OP_CAT OP_SHA256
                }
            }

            OP_ROT
            OP_EQUALVERIFY
        }
    }

    /// input:
    ///   root_hash
    ///   pos
    ///
    /// output:
    ///   v (qm31 -- 4 elements)
    pub fn query_and_verify(logn: usize) -> Script {
        script! {
            { limb_to_be_bits_toaltstack(logn as u32) }
            { Self::query_and_verify_internal(logn, false) }
        }
    }

    pub fn query_and_verify_sibling(logn: usize) -> Script {
        script! {
            { limb_to_be_bits_toaltstack(logn as u32) }
            { Self::query_and_verify_internal(logn, true) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{MerkleTree, MerkleTreeGadget};
    use bitvm::treepp::*;
    use rand::{Rng, SeedableRng};
    use rand::rngs::StdRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_merkle_tree_verify() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for logn in 12..=20 {
            let verify_script = MerkleTreeGadget::query_and_verify(logn);
            println!("verify_script {:?}",verify_script ); 
            println!("MT.verify(2^{}) = {} bytes", logn, verify_script.len());

            let mut last_layer = vec![];
            println!("last layer {:?}", last_layer); 
            let mut rng = StdRng::from_entropy();
            for _ in 0..(1 << logn) {
                let mut hash = [0u8; 32];  // Create an array to hold 32 bytes
                rng.fill(&mut hash);       // Fill the array with random bytes
            
                // Push the hash into the vector
                last_layer.push(hash);
            }

            let merkle_tree = MerkleTree::new(last_layer.clone());

            let mut pos: u32 = prng.gen();
            pos &= (1 << logn) - 1;

            let proof = merkle_tree.query(pos as usize);
            println!("proof {:?}", proof); 

            let script = script! {
                { MerkleTreeGadget::push_merkle_tree_proof(&proof) }
                { merkle_tree.root_hash.to_vec() }
                { pos }
                { verify_script.clone() }
                { last_layer[pos as usize].to_vec() }
                OP_EQUALVERIFY
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_merkle_tree_verify_sibling() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for logn in 12..=20 {
            let verify_script = MerkleTreeGadget::query_and_verify_sibling(logn);

            let mut last_layer = vec![];
            let mut rng = StdRng::from_entropy();
            for _ in 0..(1 << logn) {
                let mut hash = [0u8; 32];  // Create an array to hold 32 bytes
                rng.fill(&mut hash);       // Fill the array with random bytes
            
                // Push the hash into the vector
                last_layer.push(hash);
            }

            let merkle_tree = MerkleTree::new(last_layer.clone());

            let mut pos: u32 = prng.gen();
            pos &= (1 << logn) - 1;

            let proof = merkle_tree.query((pos ^ 1) as usize);

            let script = script! {
                { MerkleTreeGadget::push_merkle_tree_proof(&proof) }
                { merkle_tree.root_hash.to_vec() }
                { pos }
                { verify_script.clone() }
                { last_layer[(pos ^ 1) as usize].to_vec() }
                OP_EQUALVERIFY
                OP_TRUE
            };

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }
}