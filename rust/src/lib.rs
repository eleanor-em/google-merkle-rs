#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]

use std::ops::{Deref, DerefMut};

use crate::bindings::*;

mod bindings;

// TODO: implement Deref/DerefMut
pub struct MerkleTree {
    ptr: *mut merkle_tree_t,
}

#[derive(Debug)]
pub struct InclusionProof {
    path: Vec<[u8; 32]>,
    leaf_index: size_t,
    tree_size: u64,
    root: [u8; 32],
}

impl MerkleTree {
    pub fn new() -> Self {
        let ptr = unsafe { create_merkle_tree() };
        Self { ptr }
    }

    pub fn node_size(&self) -> usize {
        unsafe { merkle_tree_node_size(self.ptr) as usize }
    }

    pub fn len(&self) -> usize {
        unsafe { merkle_tree_leaf_count(self.ptr) as usize }
    }

    pub fn add_leaf(&mut self, data: &[u8]) -> usize {
        unsafe {
            merkle_tree_add_leaf(self.ptr,
                                 data.as_ptr() as *const i8,
                                 data.len() as size_t) as usize
        }
    }

    pub fn add_leaf_hash(&mut self, hash: [u8; 32]) -> usize {
        unsafe {
            merkle_tree_add_leaf_hash(self.ptr, hash.as_ptr() as *const i8, 32)
                as usize
        }
    }

    pub fn get_hash(&mut self, leaf_index: usize) -> Option<[u8; 32]> {
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

    pub fn root(&self) -> [u8; 32] {
        unsafe {
            let ptr = merkle_tree_get_root(self.ptr);
            let buf = std::slice::from_raw_parts(ptr as *const u8, 32);

            let mut result = [0; 32];
            result.copy_from_slice(buf);

            free_str(ptr);
            result
        }
    }

    pub fn root_at(&self, snapshot: usize) -> Option<[u8; 32]> {
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
        unsafe {
            let mut length = 0;
            let ptr = merkle_tree_get_path(self.ptr,
                                           leaf_index as size_t,
                                           &mut length)
                as *mut *const i8;

            if ptr.is_null() { None } else {
                let mut path = Vec::new();
                let array = std::slice::from_raw_parts(ptr, length as usize);
                for ptr in array {
                    let buf = std::slice::from_raw_parts(*ptr as *const u8, 32);

                    let mut result = [0; 32];
                    result.copy_from_slice(buf);
                    path.push(result);
                }

                free_path(ptr, length);

                Some(InclusionProof {
                    path,
                    leaf_index: leaf_index as size_t,
                    tree_size: self.len() as size_t,
                    root: self.root(),
                })
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

pub struct Verifier {
    ptr: *mut verifier_t,
}

impl Verifier {
    pub fn new() -> Self {
        let ptr = unsafe { create_verifier() };
        Self { ptr }
    }

    pub fn verify_inclusion(&self, data: &[u8], proof: &InclusionProof) -> bool {
        unsafe {
            let mut ptrs = Vec::new();
            for buf in proof.path.iter() {
                ptrs.push(buf.as_ptr() as *const i8);
            }

            verifier_verify_path(self.ptr, proof.leaf_index, proof.tree_size,
                                 ptrs.as_mut_ptr(), ptrs.len() as size_t,
                                 proof.root.as_ptr() as *const i8,
                                 data.as_ptr() as *const i8, data.len() as size_t)
        }
    }
}

impl Drop for Verifier {
    fn drop(&mut self) {
        unsafe { free_verifier(self.ptr) }
    }
}

#[cfg(test)]
mod tests {
    use crate::{MerkleTree, Verifier};

    #[test]
    fn tree_works() {
        let tree = MerkleTree::new();
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
        let empty_root: [u8; 32] = [227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153,
            111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85];
        let new_root: [u8; 32] = [78, 204, 243, 70, 8, 211, 27, 172, 92, 123, 236, 246, 0, 109, 245,
            144, 5, 216, 40, 24, 16, 86, 208, 146, 8, 78, 52, 30, 107, 176, 5, 189];

        let mut tree = MerkleTree::new();
        assert_eq!(tree.root(), empty_root);

        tree.add_leaf(b"hello world");
        assert_eq!(tree.root(), new_root);
    }

    #[test]
    fn root_at_snapshots() {
        let new_root: [u8; 32] = [78, 204, 243, 70, 8, 211, 27, 172, 92, 123, 236, 246, 0, 109, 245,
            144, 5, 216, 40, 24, 16, 86, 208, 146, 8, 78, 52, 30, 107, 176, 5, 189];

        let mut tree = MerkleTree::new();
        tree.add_leaf(b"hello world");
        tree.add_leaf(b"foo");
        assert_eq!(tree.root_at(1).unwrap(), new_root);
    }

    #[test]
    fn root_at_nonexistent_snapshot() {
        let mut tree = MerkleTree::new();
        assert!(tree.root_at(1).is_none());
    }

    #[test]
    fn inclusion() {
        let mut tree = MerkleTree::new();
        let index = tree.add_leaf(b"hello world");
        tree.add_leaf(b"foo");
        let proof = tree.inclusion(index).unwrap();
        println!("{:?}", tree.get_hash(1));
        println!("{:?}", tree.get_hash(2));
        println!("{:?}", tree.root());
        println!("{:?}", proof);

        let verifier = Verifier::new();
        assert!(verifier.verify_inclusion(b"hello world", &proof));
        assert!(!verifier.verify_inclusion(b"foo", &proof));
    }
}
