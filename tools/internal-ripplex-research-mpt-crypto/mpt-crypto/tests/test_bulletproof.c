#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include <openssl/rand.h>
#include "secp256k1_mpt.h"

#define N_BITS 64


int secp256k1_bulletproof_compute_vectors(
        const secp256k1_context* ctx,
        uint64_t value,
        unsigned char al[N_BITS][32],
        unsigned char ar[N_BITS][32],
        unsigned char sl[N_BITS][32],
        unsigned char sr[N_BITS][32]);

int secp256k1_bulletproof_commit_AS(
        const secp256k1_context* ctx,
        secp256k1_pubkey* A, secp256k1_pubkey* S_cmt,
        unsigned char al[64][32], unsigned char ar[64][32],
        unsigned char sl[64][32], unsigned char sr[64][32],
        const unsigned char* rho, const unsigned char* rho_s,
        const secp256k1_pubkey* pk_base);

// Helper function to get a random 32-byte scalar
static int get_random_bytes(unsigned char* buffer32) {
    secp256k1_pubkey temp_pubkey;
    return secp256k1_elgamal_generate_keypair(NULL, buffer32, &temp_pubkey);
}


// --- TEST IMPLEMENTATION ---
static void test_bulletproof_structure(const secp256k1_context* ctx) {
    unsigned char privkey[32];
    secp256k1_pubkey pubkey_base;
    uint64_t value = 1000;

    // --- Vector Declarations (Stack Allocation) ---
    unsigned char blinding_factor[32];
    unsigned char al[N_BITS][32], ar[N_BITS][32];
    unsigned char sl[N_BITS][32], sr[N_BITS][32];
    unsigned char rho[32], rho_s[32]; // Commitment blinders
    secp256k1_pubkey A, S; // Output Commitment Points

    printf("Running test: Bulletproof structural integrity (Phase 1)...\n");

    // Generate necessary random inputs
    assert(secp256k1_elgamal_generate_keypair(ctx, privkey, &pubkey_base) == 1);
    assert(get_random_bytes(blinding_factor) == 1);
    assert(get_random_bytes(rho) == 1);
    assert(get_random_bytes(rho_s) == 1);

    // 1. Compute Vectors (Encodes value, generates randomness)
    int result_vectors = secp256k1_bulletproof_compute_vectors(
            ctx, value, al, ar, sl, sr);
    assert(result_vectors == 1);

    // 2. Compute Initial Commitments A and S
    int result_commit = secp256k1_bulletproof_commit_AS(
            ctx, &A, &S, al, ar, sl, sr, rho, rho_s, &pubkey_base);
    assert(result_commit == 1);

    printf("Structural integrity passed!\n");
}

int main() {
    secp256k1_context* ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    assert(ctx != NULL);

    // Context Setup and Randomization
    unsigned char seed[32];
    assert(RAND_bytes(seed, sizeof(seed)) == 1);
    assert(secp256k1_context_randomize(ctx, seed) == 1);

    // Execute the structural test

    //test_bulletproof_structure(ctx);

    secp256k1_context_destroy(ctx);
    return 0;
}