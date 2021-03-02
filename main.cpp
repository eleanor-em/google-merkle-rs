#include <cstdio>
#include <chrono>
#include <memory>
#include "merkletree/merkle_tree.h"
#include "merkletree/merkle_verifier.h"
#include "merkletree/serial_hasher.h"
#include "c/merkletree.h"
#include "c/verifier.h"

using std::make_unique;
using namespace std::chrono;

void benchmark(size_t n) {
    std::printf("Benchmarking tree with %d elements...\n", n);
    auto tree = MerkleTree(make_unique<Sha256Hasher>());
    auto verifier = MerkleVerifier(make_unique<Sha256Hasher>());

    auto then = high_resolution_clock::now();
    for (size_t i = 0; i < n; ++i) {
        tree.AddLeaf(std::to_string(i));
    }
    auto now = high_resolution_clock::now();
    auto time_span = duration_cast<duration<double>>(now - then);
    std::printf("Create tree: %.2fs\n", time_span.count());

    then = high_resolution_clock::now();
    for (size_t i = 2; i < n; ++i) {
        auto snapshot = tree.SnapshotConsistency(i - 1, i);
        if (!verifier.VerifyConsistency(i - 1, i, tree.RootAtSnapshot(i - 1), tree.RootAtSnapshot(i), snapshot)) {
            printf("?? failed to verify consistency!");
        }
    }
    now = high_resolution_clock::now();
    time_span = duration_cast<duration<double>>(now - then);
    std::printf("Prove consistency: %.2fs\n", time_span.count());

    then = high_resolution_clock::now();
    for (size_t i = 0; i < n; ++i) {
        auto path = tree.PathToCurrentRoot(i + 1);
        if (!verifier.VerifyPath(i + 1, tree.LeafCount(), path, tree.CurrentRoot(), std::to_string(i))) {
            printf("?? failed to verify path!");
        }
    }
    now = high_resolution_clock::now();
    time_span = duration_cast<duration<double>>(now - then);
    std::printf("Verify paths: %.2fs\n", time_span.count());
}

int main() {
    benchmark(100000);
    return 0;
}
