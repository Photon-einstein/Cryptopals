#ifndef MESSAGE_EXTRACTION_FACILITY_HPP
#define MESSAGE_EXTRACTION_FACILITY_HPP

#include <memory>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <string>
#include <vector>

namespace MessageExtractionFacility {

/**
 * @brief This method will convert hexadecimal string to a vector of bytes
 *
 * This method will convert hexadecimal string to a vector of bytes, using zero
 * alignment
 *
 * @param hexStr The input to be converted
 *
 * @return The vector of bytes resulting of the conversion
 */
std::vector<unsigned char> hexToBytes(const std::string &hexStr);

/**
 * @brief This method converts a vector of bytes into a string in hex format
 *
 * This method will convert a vector of bytes into a string of hexadecimal
 * characters, padded with zero
 *
 * @param data The vector with bytes to be converted
 * @return A string containing the chars with hexadecimal format, zero padded
 */
std::string toHexString(const std::vector<unsigned char> &data);

struct BIGNUM_deleter {
  void operator()(BIGNUM *bn) const { BN_free(bn); }
};
using UniqueBIGNUM = std::unique_ptr<BIGNUM, BIGNUM_deleter>;

UniqueBIGNUM hexToUniqueBIGNUM(const std::string &hex_str);

std::string BIGNUMToHex(BIGNUM *bn);

std::string BIGNUMToDec(BIGNUM *bn);

}; // namespace MessageExtractionFacility

#endif // MESSAGE_EXTRACTION_FACILITY_HPP
