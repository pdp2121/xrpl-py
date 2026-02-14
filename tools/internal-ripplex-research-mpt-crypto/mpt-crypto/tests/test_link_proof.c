#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <secp256k1.h>
#include "secp256k1_mpt.h"
#include <openssl/rand.h>

/* Helper to get H generator used in the library */
void get_h_generator_test(const secp256k1_context* ctx, secp256k1_pubkey* h) {
    unsigned char h_scalar[32] = {0};
    h_scalar[31] = 0x03;
    assert(secp256k1_ec_pubkey_create(ctx, h, h_scalar) == 1);
}

void test_link_proof_basic() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char r[32], rho[32], priv_pk[32], context_id[32];
    uint64_t amount = 5000;
    unsigned char m_scalar[32] = {0};

    secp256k1_pubkey pk, c1, c2, pcm, mG, rPk, h_gen, rhoH;
    unsigned char proof[195];

    printf("DEBUG: Starting test...\n");

    /* 1. Setup Identities and Randomness */
    RAND_bytes(priv_pk, 32);
    RAND_bytes(r, 32);
    RAND_bytes(rho, 32);
    RAND_bytes(context_id, 32);
    for (int i = 0; i < 8; i++) m_scalar[31-i] = (amount >> (i*8)) & 0xFF;

    /* 2. Create Public Key (Pk = xG) */
    assert(secp256k1_ec_pubkey_create(ctx, &pk, priv_pk) == 1);

    /* 3. Create ElGamal Commitment (C1, C2) */
    // C1 = r * G
    assert(secp256k1_ec_pubkey_create(ctx, &c1, r) == 1);

    // C2 = m * G + r * Pk
    assert(secp256k1_ec_pubkey_create(ctx, &mG, m_scalar) == 1);
    rPk = pk;
    assert(secp256k1_ec_pubkey_tweak_mul(ctx, &rPk, r) == 1);
    const secp256k1_pubkey* add_c2[2] = {&mG, &rPk};
    assert(secp256k1_ec_pubkey_combine(ctx, &c2, add_c2, 2) == 1);

    /* 4. Create Pedersen Commitment (PCm = m * G + rho * H) */
    get_h_generator_test(ctx, &h_gen);
    rhoH = h_gen;
    assert(secp256k1_ec_pubkey_tweak_mul(ctx, &rhoH, rho) == 1);
    const secp256k1_pubkey* add_pcm[2] = {&mG, &rhoH};
    assert(secp256k1_ec_pubkey_combine(ctx, &pcm, add_pcm, 2) == 1);

    printf("DEBUG: Setup complete. Entering Prove function...\n");

    /* 5. Generate Link Proof */
    // We pass the EXACT r and rho used above
    int prove_ret = secp256k1_elgamal_pedersen_link_prove(
            ctx, proof, &c1, &c2, &pk, &pcm, amount, r, rho, context_id
    );
    assert(prove_ret == 1);

    printf("DEBUG: Entering Verify function...\n");

    /* 6. Verify Link Proof */
    int verify_ret = secp256k1_elgamal_pedersen_link_verify(
            ctx, proof, &c1, &c2, &pk, &pcm, context_id
    );

    if (verify_ret == 1) {
        printf("SUCCESS: Link Proof verified!\n");
    } else {
        printf("FAILURE: Link Proof verification failed.\n");
    }

    assert(verify_ret == 1);

    secp256k1_context_destroy(ctx);
}

int main() {
    test_link_proof_basic();
    return 0;
}