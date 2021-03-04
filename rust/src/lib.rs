#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::bindings::*;

mod bindings;

pub type MerkleHash = [u8; 32];

pub struct MerkleTree {
    ptr: *mut merkle_tree_t,
}

#[derive(Debug, Clone, Hash)]
pub struct InclusionProof {
    raw_path: Vec<u8>,
    tree_size: u64,
    root: MerkleHash,
}

#[derive(Debug, Clone, Hash)]
pub struct ConsistencyProof(Vec<u8>);

impl MerkleTree {
    pub fn new() -> Self {
        let ptr = unsafe { create_merkle_tree() };
        Self { ptr }
    }

    pub fn len(&self) -> usize {
        unsafe { merkle_tree_leaf_count(self.ptr) as usize }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn levels(&self) -> usize {
        unsafe { merkle_tree_level_count(self.ptr) as usize }
    }

    pub fn add_leaf(&mut self, data: &[u8]) -> usize {
        unsafe {
            merkle_tree_add_leaf(self.ptr,
                                 data.as_ptr() as *const i8,
                                 data.len() as size_t) as usize
        }
    }

    pub fn add_leaf_hash(&mut self, hash: MerkleHash) -> usize {
        unsafe {
            merkle_tree_add_leaf_hash(self.ptr, hash.as_ptr() as *const i8, 32)
                as usize
        }
    }

    pub fn get_hash(&mut self, leaf_index: usize) -> Option<MerkleHash> {
        unsafe {
            let ptr = merkle_tree_leaf_hash(self.ptr, leaf_index as size_t);
            if ptr.is_null() {
                return None;
            }
            let buf = std::slice::from_raw_parts(ptr as *const u8, 32);
            let mut result = [0; 32];
            result.copy_from_slice(buf);

            free_str(ptr);
            Some(result)
        }
    }

    pub fn root(&self) -> MerkleHash {
        unsafe {
            let ptr = merkle_tree_get_root(self.ptr);
            let buf = std::slice::from_raw_parts(ptr as *const u8, 32);

            let mut result = [0; 32];
            result.copy_from_slice(buf);

            free_str(ptr);
            result
        }
    }

    pub fn root_at(&self, snapshot: usize) -> Option<MerkleHash> {
        unsafe {
            let ptr = merkle_tree_get_root_snapshot(self.ptr,
                                                    snapshot as size_t);
            if ptr.is_null() {
                return None;
            }
            let buf = std::slice::from_raw_parts(ptr as *const u8, 32);

            let mut result = [0; 32];
            result.copy_from_slice(buf);

            free_str(ptr);
            Some(result)
        }
    }

    pub fn inclusion(&self, leaf_index: usize) -> Option<InclusionProof> {
        self.inclusion_at(leaf_index, self.len())
    }

    pub fn inclusion_at(&self, leaf_index: usize, snapshot: usize) -> Option<InclusionProof> {
        let root = self.root_at(snapshot)?;

        unsafe {
            let mut length = 0;
            let ptr = merkle_tree_get_path_snapshot(self.ptr,
                                                    leaf_index as size_t,
                                                     snapshot as size_t,
                                                     &mut length)
                as *const u8;

            if ptr.is_null() { None } else {
                let mut raw_path = Vec::new();

                for i in 0..length {
                    let ptr = ptr.offset(32 * i as isize);
                    let buf = std::slice::from_raw_parts(ptr, 32);

                    let mut result = [0; 32];
                    result.copy_from_slice(buf);

                    raw_path.extend(&result);
                }

                free_str(ptr as *const i8);

                Some(InclusionProof {
                    raw_path,
                    tree_size: snapshot as size_t,
                    root,
                })
            }
        }
    }

    pub fn consistency(&self, snapshot1: usize, snapshot2: usize) -> Option<ConsistencyProof> {
        unsafe {
            let mut length = 0;
            let ptr = merkle_tree_consistency_proof(self.ptr,
                                           snapshot1 as size_t,
                                           snapshot2 as size_t, &mut length)
                as *const u8;

            if ptr.is_null() { None } else {
                let mut proof = Vec::new();

                for i in 0..length {
                    let ptr = ptr.offset(32 * i as isize);
                    let buf = std::slice::from_raw_parts(ptr, 32);

                    let mut result = [0; 32];
                    result.copy_from_slice(buf);

                    proof.extend(&result);
                }

                free_str(ptr as *const i8);

                Some(ConsistencyProof(proof))
            }
        }
    }
}

impl Drop for MerkleTree {
    fn drop(&mut self) {
        unsafe {
            free_merkle_tree(self.ptr);
        }
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl InclusionProof {
    pub fn root(&self) -> &[u8] {
        &self.root
    }
}

pub struct Verifier {
    ptr: *mut verifier_t,
}

impl Verifier {
    pub fn new() -> Self {
        let ptr = unsafe { create_verifier() };
        Self { ptr }
    }

    pub fn hash_of(&self, data: &[u8]) -> MerkleHash {
        unsafe {
            let ptr = verifier_get_hash(self.ptr,
                                        data.as_ptr() as *const i8,
                                        data.len() as size_t) as *const u8;

            let buf = std::slice::from_raw_parts(ptr, 32);

            let mut result = [0; 32];
            result.copy_from_slice(buf);
            result
        }
    }

    pub fn verify_inclusion(&self, data: &[u8], leaf_index: usize, proof: &InclusionProof) -> bool {
        unsafe {
            verifier_verify_path(self.ptr, leaf_index as size_t, proof.tree_size,
                                 proof.raw_path.as_ptr() as *const i8,
                                 proof.raw_path.len() as size_t / 32,
                                 proof.root.as_ptr() as *const i8,
                                 data.as_ptr() as *const i8, data.len() as size_t)
        }
    }

    pub fn verify_consistency(&self, root1: MerkleHash, root2: MerkleHash,
                              snapshot1: usize, snapshot2: usize,
                              proof: &ConsistencyProof) -> bool {
        unsafe {
            verifier_verify_consistency(self.ptr, snapshot1 as size_t,
                                        snapshot2 as size_t,
                                        root1.as_ptr() as *const i8,
                                        root2.as_ptr() as *const i8,
                                        proof.0.as_ptr() as *const i8,
                                        proof.0.len() as size_t / 32)
        }
    }
}

impl Drop for Verifier {
    fn drop(&mut self) {
        unsafe { free_verifier(self.ptr) }
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::{MerkleTree, Verifier, MerkleHash};

    #[test]
    fn tree_works() {
        let _tree = MerkleTree::new();
    }

    #[test]
    fn insert_works() {
        let mut tree = MerkleTree::new();
        assert_eq!(tree.len(), 0);
        tree.add_leaf(b"hello world");
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn insert_null_works() {
        let mut tree = MerkleTree::new();
        assert_eq!(tree.len(), 0);
        tree.add_leaf(b"hello\0world");
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn check_hash() {
        let mut tree = MerkleTree::new();
        assert_eq!(tree.len(), 0);

        let index = tree.add_leaf(b"hello world");

        let expect = [78, 204, 243, 70, 8, 211, 27, 172, 92, 123, 236, 246, 0, 109, 245,
            144, 5, 216, 40, 24, 16, 86, 208, 146, 8, 78, 52, 30, 107, 176, 5, 189];
        assert_eq!(tree.get_hash(index).unwrap(), expect);
    }

    #[test]
    fn nonexistent_hash() {
        let mut tree = MerkleTree::new();
        assert!(tree.get_hash(1).is_none());
    }

    #[test]
    fn insert_hash() {
        let mut tree = MerkleTree::new();
        assert_eq!(tree.len(), 0);
        let hash = [78, 204, 243, 70, 8, 211, 27, 172, 92, 123, 236, 246, 0, 109, 245,
            144, 5, 216, 40, 24, 16, 86, 208, 146, 8, 78, 52, 30, 107, 176, 5, 189];
        tree.add_leaf_hash(hash);
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn roots() {
        let empty_root: MerkleHash = [227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153,
            111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85];
        let new_root: MerkleHash = [78, 204, 243, 70, 8, 211, 27, 172, 92, 123, 236, 246, 0, 109, 245,
            144, 5, 216, 40, 24, 16, 86, 208, 146, 8, 78, 52, 30, 107, 176, 5, 189];

        let mut tree = MerkleTree::new();
        assert_eq!(tree.root(), empty_root);

        tree.add_leaf(b"hello world");
        assert_eq!(tree.root(), new_root);
    }

    #[test]
    fn root_at_snapshots() {
        let new_root: MerkleHash = [78, 204, 243, 70, 8, 211, 27, 172, 92, 123, 236, 246, 0, 109, 245,
            144, 5, 216, 40, 24, 16, 86, 208, 146, 8, 78, 52, 30, 107, 176, 5, 189];

        let mut tree = MerkleTree::new();
        tree.add_leaf(b"hello world");
        tree.add_leaf(b"foo");
        assert_eq!(tree.root_at(1).unwrap(), new_root);
    }

    #[test]
    fn root_at_nonexistent_snapshot() {
        let tree = MerkleTree::new();
        assert!(tree.root_at(1).is_none());
    }

    #[test]
    fn inclusion() {
        let mut tree = MerkleTree::new();
        let index = tree.add_leaf(b"hello world");
        tree.add_leaf(b"foo");
        let proof = tree.inclusion(index).unwrap();
        println!("{:?}", proof);

        let verifier = Verifier::new();
        assert!(verifier.verify_inclusion(b"hello world", index, &proof));
        assert!(!verifier.verify_inclusion(b"foo", index, &proof));
    }

    #[test]
    fn inclusion_at() {
        let mut tree = MerkleTree::new();
        tree.add_leaf(b"hello world");
        let index = tree.add_leaf(b"foo");
        tree.add_leaf(b"bar");

        let proof = tree.inclusion_at(index, index).unwrap();

        let verifier = Verifier::new();
        assert!(verifier.verify_inclusion(b"foo", index, &proof));
    }

    #[test]
    fn consistency() {
        let mut tree = MerkleTree::new();

        let snapshot1 = tree.add_leaf(b"hello world");
        let root1 = tree.root();

        let snapshot2 = tree.add_leaf(b"foo");
        let root2 = tree.root();

        let snapshot3 = tree.add_leaf(b"bar");
        let root3 = tree.root();

        let proof = tree.consistency(snapshot1, snapshot2).unwrap();
        let verifier = Verifier::new();
        assert!(verifier.verify_consistency(root1, root2, snapshot1, snapshot2, &proof));
        assert!(!verifier.verify_consistency(root1, root3, snapshot1, snapshot3, &proof));
    }
}
