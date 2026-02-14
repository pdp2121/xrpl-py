#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <secp256k1.h>
#include <openssl/rand.h> // For context randomization
#include "secp256k1_mpt.h"

// Helper function to print bytes as hex
void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("* **%s:** `", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("`\n");
}

// Helper function to convert hex string (no 0x prefix) to bytes
// Basic implementation, assumes valid hex input.
int hex_to_bytes(const char* hex, unsigned char* bytes, size_t len) {
    if (strlen(hex) != len * 2) return 0; // Invalid length
    for (size_t i = 0; i < len; ++i) {
        if (sscanf(hex + 2 * i, "%2hhx", &bytes[i]) != 1) {
            return 0; // Invalid hex char
        }
    }
    return 1;
}

int main() {
    // --- Setup Context ---
    secp256k1_context* ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    assert(ctx != NULL);
    unsigned char seed[32];
    assert(RAND_bytes(seed, sizeof(seed)) == 1);
    assert(secp256k1_context_randomize(ctx, seed) == 1);

    // --- KAT Variables ---
    unsigned char privkey_d[32];
    secp256k1_pubkey pubkey_Q;
    unsigned char blinding_k[32];
    uint64_t amount;
    secp256k1_pubkey c1_struct, c2_struct;
    unsigned char c1_bytes[33], c2_bytes[33];
    size_t len;

    // --- Generate KAT 1 ---
    printf("## KAT 1: Non-Zero Amount\n\n");
    amount = 1000;
    assert(hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000001", privkey_d, 32) == 1);
    assert(hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000002", blinding_k, 32) == 1);

    // Calculate Public Key Q = d*G
    assert(secp256k1_ec_pubkey_create(ctx, &pubkey_Q, privkey_d) == 1);

    // Encrypt
    assert(secp256k1_elgamal_encrypt(ctx, &c1_struct, &c2_struct, &pubkey_Q, amount, blinding_k) == 1);

    // Serialize Ciphertext
    len = sizeof(c1_bytes);
    assert(secp256k1_ec_pubkey_serialize(ctx, c1_bytes, &len, &c1_struct, SECP256K1_EC_COMPRESSED) == 1);
    len = sizeof(c2_bytes);
    assert(secp256k1_ec_pubkey_serialize(ctx, c2_bytes, &len, &c2_struct, SECP256K1_EC_COMPRESSED) == 1);

    // Print KAT 1 Results
    print_hex("Recipient Private Key (`d`)", privkey_d, 32);
    unsigned char pubkey_q_bytes[33];
    len = sizeof(pubkey_q_bytes);
    secp256k1_ec_pubkey_serialize(ctx, pubkey_q_bytes, &len, &pubkey_Q, SECP256K1_EC_COMPRESSED);
    print_hex("Recipient Public Key (`Q = d*G`)", pubkey_q_bytes, 33);
    printf("* **Amount (`amount`):** `%llu` (decimal)\n", (unsigned long long)amount);
    print_hex("Blinding Factor (`k`)", blinding_k, 32);
    printf("* ---\n");
    print_hex("Expected Ciphertext C1 (`k*G`)", c1_bytes, 33);
    print_hex("Expected Ciphertext C2 (`(amount*G) + (k*Q)`)", c2_bytes, 33);
    printf("\n");

    // --- Generate KAT 2 ---
    printf("## KAT 2: Zero Amount\n\n");
    amount = 0;
    // Keys and blinding factor are the same as KAT 1
    assert(hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000001", privkey_d, 32) == 1);
    assert(hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000002", blinding_k, 32) == 1);
    assert(secp256k1_ec_pubkey_create(ctx, &pubkey_Q, privkey_d) == 1);

    // Encrypt
    assert(secp256k1_elgamal_encrypt(ctx, &c1_struct, &c2_struct, &pubkey_Q, amount, blinding_k) == 1);

    // Serialize Ciphertext
    len = sizeof(c1_bytes);
    assert(secp256k1_ec_pubkey_serialize(ctx, c1_bytes, &len, &c1_struct, SECP256K1_EC_COMPRESSED) == 1);
    len = sizeof(c2_bytes);
    assert(secp256k1_ec_pubkey_serialize(ctx, c2_bytes, &len, &c2_struct, SECP256K1_EC_COMPRESSED) == 1);

    // Print KAT 2 Results
    print_hex("Recipient Private Key (`d`)", privkey_d, 32);
    len = sizeof(pubkey_q_bytes);
    secp256k1_ec_pubkey_serialize(ctx, pubkey_q_bytes, &len, &pubkey_Q, SECP256K1_EC_COMPRESSED);
    print_hex("Recipient Public Key (`Q = d*G`)", pubkey_q_bytes, 33);
    printf("* **Amount (`amount`):** `%llu` (decimal)\n", (unsigned long long)amount);
    print_hex("Blinding Factor (`k`)", blinding_k, 32);
    printf("* ---\n");
    print_hex("Expected Ciphertext C1 (`k*G`)", c1_bytes, 33);
    print_hex("Expected Ciphertext C2 (`(0*G) + (k*Q) = S`)", c2_bytes, 33);
    printf("\n");

    // --- Cleanup ---
    secp256k1_context_destroy(ctx);
    return 0;
}