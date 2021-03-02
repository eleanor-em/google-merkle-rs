extern "C" {
#include "merkletree.h"
}

#include "merkletree/merkle_tree.h"
#include "merkletree/serial_hasher.h"
#include <memory>
#include <string>
#include <cstdlib>
#include <cstring>

merkle_tree_t *create_merkle_tree() {
    return new MerkleTree(std::make_unique<Sha256Hasher>());
}

void free_merkle_tree(merkle_tree_t *tree) {
    delete tree;
}

size_t merkle_tree_node_size(merkle_tree_t *tree) {
    return tree->NodeSize();
}

size_t merkle_tree_leaf_count(merkle_tree_t *tree) {
    return tree->LeafCount();
}

const char *merkle_tree_leaf_hash(merkle_tree_t *tree, size_t leaf_index) {
    const auto result = tree->LeafHash(leaf_index);
    if (result.empty()) {
        return nullptr;
    }
    char *ptr = static_cast<char *>(calloc(result.size() + 1, sizeof(char)));
    memcpy(ptr, result.c_str(), result.size());
    return ptr;
}

size_t merkle_tree_level_count(merkle_tree_t *tree) {
    return tree->LevelCount();
}

size_t merkle_tree_add_leaf(merkle_tree_t *tree, const char *data, size_t data_size) {
    std::string data_str;
    data_str.assign(data, data_size);
    return tree->AddLeaf(data_str);
}

size_t merkle_tree_add_leaf_hash(merkle_tree_t *tree, const char *hash, size_t hash_size) {
    std::string hash_str;
    hash_str.assign(hash, hash_size);
    return tree->AddLeafHash(hash_str);
}


const char *merkle_tree_get_root(merkle_tree_t *tree) {
    const auto result = tree->CurrentRoot();
    char *ptr = static_cast<char *>(calloc(result.size() + 1, sizeof(char)));
    memcpy(ptr, result.c_str(), result.size());
    return ptr;
}

const char *merkle_tree_get_root_snapshot(merkle_tree_t *tree, size_t snapshot) {
    const auto result = tree->RootAtSnapshot(snapshot);
    if (result.empty()) {
        return nullptr;
    }
    char *ptr = static_cast<char *>(calloc(result.size() + 1, sizeof(char)));
    memcpy(ptr, result.c_str(), result.size());
    return ptr;
}

char *merkle_tree_get_path(merkle_tree_t *tree, size_t leaf_index, size_t *path_length) {
    const auto result = tree->PathToCurrentRoot(leaf_index);
    *path_length = result.size();

    if (!result.empty()) {
        char *ret = (char *) malloc(32 * result.size());
        size_t i = 0;

        for (const auto &elem : result) {
            memcpy(ret + 32 * i, elem.c_str(), 32);
            ++i;
        }
        return ret;
    } else {
        return nullptr;
    }
}

char *merkle_tree_get_path_snapshot(merkle_tree_t *tree, size_t leaf_index, size_t snapshot, size_t *path_length) {
    const auto result = tree->PathToRootAtSnapshot(leaf_index, snapshot);
    *path_length = result.size();

    if (!result.empty()) {
        char *ret = (char *) malloc(32 * result.size());
        size_t i = 0;

        for (const auto &elem : result) {
            memcpy(ret + 32 * i, elem.c_str(), 32);
            ++i;
        }
        return ret;
    } else {
        return nullptr;
    }
}

char *merkle_tree_consistency_proof(merkle_tree_t *tree, size_t snapshot1, size_t snapshot2, size_t *path_length) {
    const auto result = tree->SnapshotConsistency(snapshot1, snapshot2);
    *path_length = result.size();

    if (!result.empty()) {
        char *ret = (char *) malloc(32 * result.size());
        size_t i = 0;
        for (const auto &elem : result) {
            memcpy(ret + 32 * i, elem.c_str(), 32);
            ++i;
        }
        return ret;
    } else {
        return nullptr;
    }
}

void free_str(const char *str) {
    free((void *) str);
}
