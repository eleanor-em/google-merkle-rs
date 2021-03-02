extern "C" {
#include "verifier.h"
}

#include "merkletree/serial_hasher.h"
#include "merkletree/merkle_verifier.h"

#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

using std::vector;
using std::string;

verifier_t *create_verifier() {
    return new MerkleVerifier(std::make_unique<Sha256Hasher>());
}

void free_verifier(verifier_t *verifier) {
    delete verifier;
}

bool verifier_verify_path(verifier_t *verifier, size_t leaf, size_t tree_size, const char *path, size_t path_length,
                          const char *root, const char *data, size_t data_size) {
    std::string data_str, root_str;
    data_str.assign(data, data_size);
    root_str.assign(root, 32);

    vector<string> path_vec;
    for (size_t i = 0; i < path_length; ++i) {
        std::string chunk;
        chunk.assign(path + 32 * i, 32);
        path_vec.push_back(chunk);
    }

    return verifier->VerifyPath(leaf, tree_size, path_vec, root_str, data_str);
}

const char *verifier_root_from_path(verifier_t *verifier, size_t leaf, size_t tree_size, const char *path,
                                    size_t path_length, const char *data, size_t data_size) {
    std::string data_str;
    data_str.assign(data, data_size);

    vector<string> path_vec;
    for (size_t i = 0; i < path_length; ++i) {
        std::string chunk;
        chunk.assign(path + 32 * i, 32);
        path_vec.push_back(chunk);
    }

    const auto result = verifier->RootFromPath(leaf,  tree_size, path_vec, data_str);

    char *ptr = (char *) malloc(32);
    memcpy(ptr, result.c_str(), 32);
    return ptr;
}

bool verifier_verify_consistency(verifier_t *verifier, size_t snapshot1, size_t snapshot2, const char *root1,
                                 const char *root2, const char *proof, size_t proof_length) {
    std::string root1_str, root2_str;
    root1_str.assign(root1, 32);
    root2_str.assign(root2, 32);

    vector<string> proof_vec;
    for (size_t i = 0; i < proof_length; ++i) {
        std::string chunk;
        chunk.assign(proof + 32 * i, 32);
        proof_vec.push_back(chunk);
    }

    return verifier->VerifyConsistency(snapshot1, snapshot2, root1_str, root2_str, proof_vec);
}

const char *verifier_get_hash(verifier_t *verifier, const char *data, size_t data_size) {
    std::string data_str;
    data_str.assign(data, data_size);
    const auto result = verifier->LeafHash(data_str);
    if (result.empty()) {
        return nullptr;
    }
    char *ptr = (char *) malloc(32);
    memcpy(ptr, result.c_str(), 32);
    return ptr;
}
