#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "./../include/SHA1.hpp"

/* constructor / destructor */
MyCryptoLibrary::SHA1::SHA1() : _sizeOutputHash{SHA_DIGEST_LENGTH} {}
/******************************************************************************/
MyCryptoLibrary::SHA1::~SHA1() {}
/******************************************************************************/
/**
 * @brief Computes the SHA-1 hash value
 *
 * Computes the SHA-1 hash of the given input vector
 *
 * @param inputV The input data as a vector of unsigned characters
 * @return A vector of unsigned characters containing the computed hash
 */
std::vector<unsigned char>
MyCryptoLibrary::SHA1::hash(const std::vector<unsigned char> &inputV) {
  _inputVpadded.clear();
  initialization(inputV.size());
  preProcessing(inputV);
  processing();
  std::vector<unsigned char> hashV;
  hashV.reserve(SHA_DIGEST_LENGTH);

  const uint32_t hashParts[] = {_h0, _h1, _h2, _h3, _h4};

  for (uint32_t part : hashParts) {
    hashV.push_back((part >> 24) & 0xFF);
    hashV.push_back((part >> 16) & 0xFF);
    hashV.push_back((part >> 8) & 0xFF);
    hashV.push_back(part & 0xFF);
  }
  return hashV;
}
/******************************************************************************/
/**
 * @brief Computes the SHA-1 hash value
 *
 * Computes the SHA-1 hash of the given input vector from a predefined internal
 * state
 *
 * @param inputV The input data as a vector of unsigned characters
 * @param h0 Internal state of the SHA1
 * @param h1 Internal state of the SHA1
 * @param h2 Internal state of the SHA1
 * @param h3 Internal state of the SHA1
 * @param h4 Internal state of the SHA1
 * @param messageSize Size of the entire message that was intended to hash from
 * the start
 *
 * @return A vector of bytes containing the computed hash
 */
std::vector<unsigned char>
MyCryptoLibrary::SHA1::hash(const std::vector<unsigned char> &inputV,
                            uint32_t h0, uint32_t h1, uint32_t h2, uint32_t h3,
                            uint32_t h4, std::size_t messageSize) {
  _inputVpadded.clear();
  initialization(messageSize, h0, h1, h2, h3, h4);
  preProcessing(inputV);
  processing();
  std::vector<unsigned char> hashV;
  hashV.reserve(SHA_DIGEST_LENGTH);

  const uint32_t hashParts[] = {_h0, _h1, _h2, _h3, _h4};

  for (uint32_t part : hashParts) {
    hashV.push_back((part >> 24) & 0xFF);
    hashV.push_back((part >> 16) & 0xFF);
    hashV.push_back((part >> 8) & 0xFF);
    hashV.push_back(part & 0xFF);
  }
  return hashV;
}
/******************************************************************************/
/**
 * Initializes internal state based on the input length
 *
 * @param sizeInputV The size of the original message in bytes
 */
void MyCryptoLibrary::SHA1::initialization(const std::size_t sizeInputV) {
  _h0 = 0x67452301;
  _h1 = 0xEFCDAB89;
  _h2 = 0x98BADCFE;
  _h3 = 0x10325476;
  _h4 = 0xC3D2E1F0;
  _ml = sizeInputV * CHAR_BIT; // message length in bits (always a multiple of
                               // the number of bits in a character)
}
/******************************************************************************/
/**
 * Initializes internal state based on the input length and predefined input
 * state
 *
 * @param sizeInputV The size of the original message in bytes
 * @param h0 Internal state of the SHA1
 * @param h1 Internal state of the SHA1
 * @param h2 Internal state of the SHA1
 * @param h3 Internal state of the SHA1
 * @param h4 Internal state of the SHA1
 */
void MyCryptoLibrary::SHA1::initialization(const std::size_t sizeInputV,
                                           uint32_t h0, uint32_t h1,
                                           uint32_t h2, uint32_t h3,
                                           uint32_t h4) {
  _h0 = h0;
  _h1 = h1;
  _h2 = h2;
  _h3 = h3;
  _h4 = h4;
  _ml = sizeInputV * CHAR_BIT; // message length in bits (always a multiple of
                               // the number of bits in a character)
}
/******************************************************************************/
/**
 * Preprocesses the input data (padding, appending length) as required by the
 * SHA-1 algorithm.
 *
 * @param inputV The input data as a vector of unsigned char.
 */
void MyCryptoLibrary::SHA1::preProcessing(
    const std::vector<unsigned char> &inputV) {
  // Initialize padded input vector with original message
  _inputVpadded = inputV;

  // Step 1: Append the bit '1' (equivalent to adding 0x80)
  _inputVpadded.push_back(0x80);

  // Step 2: Append '0' bits until the length of the message (in bits) is
  // congruent to 448 mod 512
  while ((_inputVpadded.size() * 8) % 512 != 448) {
    _inputVpadded.push_back(0x00);
  }

  // Step 3: Append the original message length (ml) as a 64-bit big-endian
  // integer _ml is already in bits
  for (int i = 7; i >= 0; --i) {
    _inputVpadded.push_back(
        static_cast<unsigned char>((_ml >> (i * 8)) & 0xFF));
  }
}
/******************************************************************************/
/// Processes the padded message in 512-bit blocks.
void MyCryptoLibrary::SHA1::processing() {
  // Process the padded input in 512-bit blocks
  for (std::size_t i = 0; i < _inputVpadded.size(); i += 64) {
    std::vector<unsigned char> block(_inputVpadded.begin() + i,
                                     _inputVpadded.begin() + i + 64);
    // Prepare the message schedule (W)
    uint32_t W[80];

    for (int t = 0; t < 16; ++t) {
      W[t] = (static_cast<uint32_t>(block[t * 4]) << 24) |
             (static_cast<uint32_t>(block[t * 4 + 1]) << 16) |
             (static_cast<uint32_t>(block[t * 4 + 2]) << 8) |
             (static_cast<uint32_t>(block[t * 4 + 3]));
    }

    for (int t = 16; t < 80; ++t) {
      W[t] = leftRotate(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    // Initialize hash values
    uint32_t a = _h0;
    uint32_t b = _h1;
    uint32_t c = _h2;
    uint32_t d = _h3;
    uint32_t e = _h4;

    // Main loop
    for (int t = 0; t < 80; ++t) {
      uint32_t f, k;
      if (t < 20) {
        f = (b & c) | (~b & d);
        k = 0x5A827999;
      } else if (t < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }

      uint32_t temp = leftRotate(a, 5) + f + e + W[t] + k;
      e = d;
      d = c;
      c = leftRotate(b, 30);
      b = a;
      a = temp;
    }

    // Update the hash values
    _h0 += a;
    _h1 += b;
    _h2 += c;
    _h3 += d;
    _h4 += e;
  }
}
/******************************************************************************/
/**
 * Performs a left-rotation (circular shift) on a 32-bit integer.
 *
 * @param value The value to rotate.
 * @param bits The number of bits to rotate by.
 * @return The rotated value.
 */
uint32_t MyCryptoLibrary::SHA1::leftRotate(uint32_t value, int bits) {
  return (value << bits) | (value >> (32 - bits));
}
/******************************************************************************/