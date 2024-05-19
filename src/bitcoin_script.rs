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
    use std::fs::File;
    use std::io::Write;
    use bitcoin::hashes::hex::FromHex;

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

            let mut file = match File::create("merkle_script.txt") {
                Err(why) => panic!("Couldn't create file: {}", why),
                Ok(file) => file,
            };

            // Write the contents of the script to the file
            match file.write_all(script.as_bytes()) {
                Err(why) => panic!("Couldn't write to file: {}", why),
                Ok(_) => println!("Successfully wrote to merkle_script.txt"),
            }

            let exec_result = execute_script(script);
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_merkle_tree_bitcoin_tx() {
        // hardcoded data obtained from block 10000: https://blockstream.info/block/000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506
        let tx_hashes = [
            "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
            "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
            "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
            "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
        ];
        let mut leaf_layer = vec![];
        for tx_hash_str in tx_hashes {
            let tx_hash_bytes: [u8; 32] = FromHex::from_hex(tx_hash_str).unwrap();
            leaf_layer.push(tx_hash_bytes);
            
        }
        let merkle_tree = MerkleTree::new(leaf_layer);
        // Generate a proof for a specific position
        let query_position = 2;
        let proof = merkle_tree.query(query_position);
        let verification_result = MerkleTree::verify(
            merkle_tree.root_hash,
            2, // logn = 2 since the leaf layer has 4 elements (2^2)
            &proof,
            query_position,
        );
        assert!(verification_result);
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