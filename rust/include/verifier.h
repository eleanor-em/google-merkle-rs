#ifndef VERIFIER_EXPORT_H
#define VERIFIER_EXPORT_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct MerkleVerifier;
typedef struct MerkleVerifier verifier_t;

verifier_t *create_verifier();
void free_verifier(verifier_t *verifier);
bool verifier_verify_path(verifier_t *verifier, size_t leaf, size_t tree_size, const char **path, size_t path_length,
                          const char *root, const char *data, size_t data_size);
const char *verifier_root_from_path(verifier_t *verifier, size_t leaf, size_t tree_size, const char **path,
                                    size_t path_length, const char *data, size_t data_size);
bool verifier_verify_consistency(verifier_t *verifier, size_t snapshot1, size_t snapshot2, const char *root1,
                                 const char *root2, const char **proof, size_t proof_length);
const char *verifier_get_hash(verifier_t *verifier, const char *data, size_t data_size);

#ifdef __cplusplus
}
#endif

#endif
