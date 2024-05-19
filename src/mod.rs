//use crate::channel_commit::Commitment;
//use crate::math::QM31;
use sha2::{Digest, Sha256};

mod bitcoin_script;
pub use bitcoin_script::*;

pub struct MerkleTree {
    pub leaf_layer: Vec<[u8; 32]>,
    pub intermediate_layers: Vec<Vec<[u8; 32]>>,
    pub root_hash: [u8; 32],
}

impl MerkleTree {
    pub fn new(leaf_layer: Vec<[u8; 32]>) -> Self {
        assert!(leaf_layer.len().is_power_of_two());

        let mut intermediate_layers = vec![];
        let mut cur = leaf_layer
            .chunks_exact(2)
            .map(|v| {
                let commit_1 = v[0];
                let commit_2 = v[1];

                let mut hash_result = [0u8; 32];

                let mut hasher = Sha256::new();
                Digest::update(&mut hasher, &commit_1);
                Digest::update(&mut hasher, &commit_2);
                hash_result.copy_from_slice(hasher.finalize().as_slice());
                hash_result
            })
            .collect::<Vec<[u8; 32]>>();
        intermediate_layers.push(cur.clone());

        while cur.len() > 1 {
            cur = cur
                .chunks_exact(2)
                .map(|v| {
                    let mut hash_result = [0u8; 32];
                    let mut hasher = Sha256::new();
                    Digest::update(&mut hasher, &v[0]);
                    Digest::update(&mut hasher, &v[1]);
                    hash_result.copy_from_slice(hasher.finalize().as_slice());
                    hash_result
                })
                .collect::<Vec<[u8; 32]>>();
            intermediate_layers.push(cur.clone());
        }

        Self {
            leaf_layer,
            intermediate_layers,
            root_hash: cur[0],
        }
    }

    pub fn query(&self, mut pos: usize) -> MerkleTreeProof {
        let logn = self.intermediate_layers.len();

        let mut merkle_tree_proof = MerkleTreeProof::default();
        merkle_tree_proof.leaf = self.leaf_layer[pos];
        merkle_tree_proof
            .siblings
            .push(self.leaf_layer[pos ^ 1]);

        for i in 0..(logn - 1) {
            pos >>= 1;
            merkle_tree_proof
                .siblings
                .push(self.intermediate_layers[i][pos ^ 1]);
        }

        merkle_tree_proof
    }

    pub fn verify(
        root_hash: [u8; 32],
        logn: usize,
        proof: &MerkleTreeProof,
        mut query: usize,
    ) -> bool {
        assert_eq!(proof.siblings.len(), logn);

        let mut leaf_hash = proof.leaf;

        for i in 0..logn {
            let (f0, f1) = if query & 1 == 0 {
                (leaf_hash, proof.siblings[i])
            } else {
                (proof.siblings[i], leaf_hash)
            };

            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, &f0);
            Digest::update(&mut hasher, &f1);
            leaf_hash.copy_from_slice(hasher.finalize().as_slice());

            query >>= 1;
        }

        leaf_hash == root_hash
    }
}

#[derive(Default, Clone, Debug)]
pub struct MerkleTreeProof {
    pub leaf: [u8;32],
    pub siblings: Vec<[u8; 32]>,
}

#[cfg(test)]
mod test {
    //use crate::math::{CM31, M31, QM31};
    use crate::MerkleTree;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_merkle_tree() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut last_layer = vec![];
        for _ in 0..1 << 12 {
            let mut tx_hash = [0u8; 32];  // Create an array of 32 bytes initialized to zero
            prng.fill(&mut tx_hash);  // Fill the array with random bytes
            last_layer.push(tx_hash);  // Push the random hash to the last_layer vector
        }

        let merkle_tree = MerkleTree::new(last_layer.clone());

        for _ in 0..10 {
            let query = (prng.gen::<u32>() % (1 << 12)) as usize;

            let proof = merkle_tree.query(query);
            assert!(MerkleTree::verify(merkle_tree.root_hash, 12, &proof, query));
        }
    }
}
