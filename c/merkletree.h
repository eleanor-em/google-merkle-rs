#ifndef MERKLETREE_EXPORT_H
#define MERKLETREE_EXPORT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct MerkleTree;
typedef struct MerkleTree merkle_tree_t;

merkle_tree_t *create_merkle_tree();
void free_merkle_tree(merkle_tree_t *tree);
size_t merkle_tree_node_size(merkle_tree_t *tree);
size_t merkle_tree_leaf_count(merkle_tree_t *tree);
const char *merkle_tree_leaf_hash(merkle_tree_t *tree, size_t leaf_index);
size_t merkle_tree_level_count(merkle_tree_t *tree);
size_t merkle_tree_add_leaf(merkle_tree_t *tree, const char *data, size_t data_size);
size_t merkle_tree_add_leaf_hash(merkle_tree_t *tree, const char *hash, size_t hash_size);
const char *merkle_tree_get_root(merkle_tree_t *tree);
const char *merkle_tree_get_root_snapshot(merkle_tree_t *tree, size_t snapshot);
char *merkle_tree_get_path(merkle_tree_t *tree, size_t leaf_index, size_t *path_length);
char *merkle_tree_get_path_snapshot(merkle_tree_t *tree, size_t leaf_index, size_t snapshot, size_t *path_length);
char *merkle_tree_consistency_proof(merkle_tree_t *tree, size_t snapshot1, size_t snapshot2, size_t *path_length);

void free_str(const char *str);

#ifdef __cplusplus
}
#endif

#endif
