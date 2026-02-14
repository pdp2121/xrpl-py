#include "secp256k1_mpt.h"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

constexpr size_t ecPrivKeyLength = 32; // Private Key length
constexpr size_t ecPubKeyLength = 64;  // Public Key length
constexpr size_t ecGamalEncryptedLength = 33;
constexpr size_t ecGamalEncryptedTotalLength = 66;

using Buffer = std::vector<unsigned char>;

secp256k1_context *secp256k1Context() {
  static secp256k1_context *ctx = secp256k1_context_create(
      SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
  return ctx;
}

[[noreturn]] void Throw(char const *s) { throw std::runtime_error(s); }

Buffer hexToBuffer(const std::string &hex) {
  if (hex.length() % 2 != 0)
    Throw("Hex string has odd length.");
  Buffer buffer;
  for (size_t i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    // std::stoul converts the hex string (base 16) to an unsigned long
    unsigned char byte = (unsigned char)std::stoul(byteString, nullptr, 16);
    buffer.push_back(byte);
  }
  return buffer;
}

std::string bufferToHex(const Buffer &buffer) {
  std::stringstream ss;
  ss << std::hex << std::uppercase << std::setfill('0');
  for (unsigned char b : buffer)
    ss << std::setw(2) << static_cast<int>(b);
  return ss.str();
}

Buffer serializeEcPair(secp256k1_pubkey const &in1,
                       secp256k1_pubkey const &in2) {
  Buffer buffer(ecGamalEncryptedTotalLength);

  auto serializePubKey = [](secp256k1_pubkey const &pub, unsigned char *out) {
    size_t outLen = ecGamalEncryptedLength;
    int const ret = secp256k1_ec_pubkey_serialize(
        secp256k1Context(), out, &outLen, &pub, SECP256K1_EC_COMPRESSED);
    return ret == 1 && outLen == ecGamalEncryptedLength;
  };

  unsigned char *ptr = buffer.data();
  bool const res1 = serializePubKey(in1, ptr);
  bool const res2 = serializePubKey(in2, ptr + ecGamalEncryptedLength);

  if (!res1 || !res2)
    Throw("Failed to serialize into 66 byte compressed format");

  return buffer;
}

bool makeEcPair(unsigned char const *buffer, size_t len, secp256k1_pubkey &out1,
                secp256k1_pubkey &out2) {
  if (len != ecGamalEncryptedTotalLength)
    return false;

  auto parsePubKey = [](unsigned char const *data, size_t length,
                        secp256k1_pubkey &out) {
    return secp256k1_ec_pubkey_parse(secp256k1Context(), &out, data, length);
  };

  int const ret1 = parsePubKey(buffer, ecGamalEncryptedLength, out1);

  int const ret2 = parsePubKey(buffer + ecGamalEncryptedLength,
                               ecGamalEncryptedLength, out2);

  return ret1 == 1 && ret2 == 1;
}

Buffer encryptAmount(uint64_t amt, Buffer const &pubKeyBuffer) {
  if (pubKeyBuffer.size() != ecPubKeyLength)
    Throw("Public key size mismatch in encryptAmount.");

  unsigned char blindingFactor[32];
  if (RAND_bytes(blindingFactor, 32) != 1)
    Throw("Failed to generate random number (blinding factor).");

  secp256k1_pubkey pubKey;
  std::memcpy(pubKey.data, pubKeyBuffer.data(), ecPubKeyLength);

  secp256k1_pubkey c1, c2;

  if (!secp256k1_elgamal_encrypt(secp256k1Context(), &c1, &c2, &pubKey, amt,
                                 blindingFactor))
    Throw("Failed to encrypt amount (C lib failure).");

  return serializeEcPair(c1, c2);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage:" << std::endl;
    std::cerr << "  1. Generate Key Pair: " << argv[0] << " generate"
              << std::endl;
    std::cerr << "  2. Encrypt Amount:    " << argv[0]
              << " encrypt <AMOUNT> <PUBKEY_64_BYTE_HEX>" << std::endl;
    std::cerr << "  3. Decrypt Amount:    " << argv[0]
              << " decrypt <CIPHERTEXT_66_BYTE_HEX> <PRIVKEY_32_BYTE_HEX>"
              << std::endl;
    return 1;
  }

  try {
    std::string command = argv[1];

    // --- MODE 1: GENERATE KEY PAIR ---
    if (command == "generate") {
      unsigned char privKey[ecPrivKeyLength];
      secp256k1_pubkey pubKey;

      if (!secp256k1_elgamal_generate_keypair(secp256k1Context(), privKey,
                                              &pubKey))
        Throw("Failed to generate key pair"); // Using simple Throw

      std::cout << "----- Generate Keys -----" << std::endl;

      std::cout << "Public Key (64-byte Hex):  "
                << bufferToHex(
                       Buffer(pubKey.data, pubKey.data + ecPubKeyLength))
                << std::endl;

      std::cout << "Private Key (32-byte Hex): "
                << bufferToHex(Buffer(privKey, privKey + ecPrivKeyLength))
                << std::endl;

      std::cout << "--------------------------" << std::endl;
      return 0;
    }

    // --- MODE 2: ENCRYPT AMOUNT ---
    else if (command == "encrypt") {
      if (argc != 4)
        Throw("Encrypt usage: encrypt <AMOUNT> <PUBKEY_HEX>");

      uint64_t amount = std::stoull(argv[2]);
      std::string pubKeyHex64 = argv[3];

      if (pubKeyHex64.length() != 128)
        Throw("Public key must be 64 bytes (128 hex chars).");

      Buffer pubKeyBuffer = hexToBuffer(pubKeyHex64);

      Buffer ciphertext = encryptAmount(amount, pubKeyBuffer);

      std::cout << "----- Encrypte Amount -----" << std::endl;
      std::cout << bufferToHex(ciphertext) << std::endl;
      std::cout << "--------------------------" << std::endl;

      return 0;
    }

    // --- MODE 3: DECRYPT AMOUNT ---
    else if (command == "decrypt") {
      if (argc != 4)
        Throw("Decrypt usage: decrypt <CIPHERTEXT_66_BYTE_HEX> "
              "<PRIVKEY_32_BYTE_HEX>");

      std::string ciphertextHex = argv[2];
      std::string privKeyHex = argv[3];

      if (ciphertextHex.length() != 132 || privKeyHex.length() != 64)
        Throw("Ciphertext must be 66 bytes (132 hex) and PrivKey 32 bytes (64 "
              "hex).");

      Buffer ciphertextBuffer = hexToBuffer(ciphertextHex);
      Buffer privKeyBuffer = hexToBuffer(privKeyHex);

      secp256k1_pubkey c1, c2;
      uint64_t decryptedAmt;

      if (!makeEcPair(ciphertextBuffer.data(), ciphertextBuffer.size(), c1, c2))
        Throw("Failed to convert into individual EC components using "
              "makeEcPair.");

      if (!secp256k1_elgamal_decrypt(secp256k1Context(), &decryptedAmt, &c1,
                                     &c2, privKeyBuffer.data()))
        Throw("Failed to decrypt amount (C lib failure).");

      std::cout << "----- Decrypt Amount -----" << std::endl;
      std::cout << decryptedAmt << std::endl;
      std::cout << "--------------------------" << std::endl;

      return 0;
    }

    else {
      std::cerr << "Invalid command: " << command << std::endl;
      return 1;
    }

  } catch (const std::exception &e) {
    std::cerr << "Runtime Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}