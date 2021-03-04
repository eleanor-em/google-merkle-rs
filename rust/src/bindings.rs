/* automatically generated by rust-bindgen 0.57.0 */

pub const __bool_true_false_are_defined: u32 = 1;
pub type size_t = ::std::os::raw::c_ulong;
#[repr(C)]
#[repr(align(16))]
#[derive(Debug, Copy, Clone)]
pub struct max_align_t {
    pub __clang_max_align_nonce1: ::std::os::raw::c_longlong,
    pub __bindgen_padding_0: u64,
    pub __clang_max_align_nonce2: u128,
}
#[test]
fn bindgen_test_layout_max_align_t() {
    assert_eq!(
        ::std::mem::size_of::<max_align_t>(),
        32usize,
        concat!("Size of: ", stringify!(max_align_t))
    );
    assert_eq!(
        ::std::mem::align_of::<max_align_t>(),
        16usize,
        concat!("Alignment of ", stringify!(max_align_t))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<max_align_t>())).__clang_max_align_nonce1 as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(max_align_t),
            "::",
            stringify!(__clang_max_align_nonce1)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<max_align_t>())).__clang_max_align_nonce2 as *const _ as usize
        },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(max_align_t),
            "::",
            stringify!(__clang_max_align_nonce2)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MerkleTree {
    _unused: [u8; 0],
}
pub type merkle_tree_t = MerkleTree;
extern "C" {
    pub fn create_merkle_tree() -> *mut merkle_tree_t;
}
extern "C" {
    pub fn free_merkle_tree(tree: *mut merkle_tree_t);
}
extern "C" {
    pub fn merkle_tree_leaf_count(tree: *mut merkle_tree_t) -> size_t;
}
extern "C" {
    pub fn merkle_tree_leaf_hash(
        tree: *mut merkle_tree_t,
        leaf_index: size_t,
    ) -> *const ::std::os::raw::c_char;
}
extern "C" {
    pub fn merkle_tree_level_count(tree: *mut merkle_tree_t) -> size_t;
}
extern "C" {
    pub fn merkle_tree_add_leaf(
        tree: *mut merkle_tree_t,
        data: *const ::std::os::raw::c_char,
        data_size: size_t,
    ) -> size_t;
}
extern "C" {
    pub fn merkle_tree_add_leaf_hash(
        tree: *mut merkle_tree_t,
        hash: *const ::std::os::raw::c_char,
        hash_size: size_t,
    ) -> size_t;
}
extern "C" {
    pub fn merkle_tree_get_root(tree: *mut merkle_tree_t) -> *const ::std::os::raw::c_char;
}
extern "C" {
    pub fn merkle_tree_get_root_snapshot(
        tree: *mut merkle_tree_t,
        snapshot: size_t,
    ) -> *const ::std::os::raw::c_char;
}
extern "C" {
    pub fn merkle_tree_get_path_snapshot(
        tree: *mut merkle_tree_t,
        leaf_index: size_t,
        snapshot: size_t,
        path_length: *mut size_t,
    ) -> *mut ::std::os::raw::c_char;
}
extern "C" {
    pub fn merkle_tree_consistency_proof(
        tree: *mut merkle_tree_t,
        snapshot1: size_t,
        snapshot2: size_t,
        path_length: *mut size_t,
    ) -> *mut ::std::os::raw::c_char;
}
extern "C" {
    pub fn free_str(str_: *const ::std::os::raw::c_char);
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MerkleVerifier {
    _unused: [u8; 0],
}
pub type verifier_t = MerkleVerifier;
extern "C" {
    pub fn create_verifier() -> *mut verifier_t;
}
extern "C" {
    pub fn free_verifier(verifier: *mut verifier_t);
}
extern "C" {
    pub fn verifier_verify_path(
        verifier: *mut verifier_t,
        leaf: size_t,
        tree_size: size_t,
        path: *const ::std::os::raw::c_char,
        path_length: size_t,
        root: *const ::std::os::raw::c_char,
        data: *const ::std::os::raw::c_char,
        data_size: size_t,
    ) -> bool;
}
extern "C" {
    pub fn verifier_verify_consistency(
        verifier: *mut verifier_t,
        snapshot1: size_t,
        snapshot2: size_t,
        root1: *const ::std::os::raw::c_char,
        root2: *const ::std::os::raw::c_char,
        proof: *const ::std::os::raw::c_char,
        proof_length: size_t,
    ) -> bool;
}
extern "C" {
    pub fn verifier_get_hash(
        verifier: *mut verifier_t,
        data: *const ::std::os::raw::c_char,
        data_size: size_t,
    ) -> *const ::std::os::raw::c_char;
}
