#ifndef MESSAGE_EXTRACTION_FACILITY_HPP
#define MESSAGE_EXTRACTION_FACILITY_HPP

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <format>
#include <memory>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <string>
#include <vector>

namespace MessageExtractionFacility {

struct BIGNUM_deleter {
  void operator()(BIGNUM *bn) const { BN_free(bn); }
};
using UniqueBIGNUM = std::unique_ptr<BIGNUM, BIGNUM_deleter>;

/**
 * @brief This method will convert hexadecimal string to a vector of bytes.
 *
 * This method will convert hexadecimal string to a vector of bytes, using zero
 * alignment.
 *
 * @param hexStr The input to be converted.
 *
 * @return The vector of bytes resulting of the conversion.
 */
std::vector<unsigned char> hexToBytes(const std::string &hexStr);

/**
 * @brief This method converts a vector of bytes into a string in hex format.
 *
 * This method will convert a vector of bytes into a string of hexadecimal
 * characters, padded with zero's.
 *
 * @param data The vector with bytes to be converted.
 *
 * @return A string containing the chars with hexadecimal format, zero padded.
 */
std::string toHexString(const std::vector<unsigned char> &data);

/**
 * @brief This method will convert an hexadecimal number to an unique big
 * number.
 *
 * This method will convert an hexadecimal number to an unique big number.
 *
 * @param hexNumber The number in hexadecimal format.
 *
 * @return The number in an UniqueBIGNUM format.
 * @throws std::runtime_error if conversion fails.
 */
UniqueBIGNUM hexToUniqueBIGNUM(const std::string &hexNumber);

/**
 * @brief This method will convert a number in a BIGNUM format to
 * a hexadecimal format, ensuring an even number of hex digits.
 *
 * This method will convert a number in a BIGNUM format to
 * a hexadecimal format, performing all the calculations necessary.
 * It ensures the resulting hex string has an even length, padding with a
 * leading '0' if the natural hex representation has an odd length.
 *
 * @param bn The number in a BIGNUM format.
 *
 * @return The number converted to a hexadecimal format with an even number of
 * digits.
 * @throws std::runtime_error if conversion fails.
 */
std::string BIGNUMToHex(BIGNUM *bn);

/**
 * @brief This method will convert a number in a BIGNUM format to
 * a decimal format.
 *
 * This method will convert a number in a BIGNUM format to
 * a decimal format, performing all the calculations necessary.
 *
 * @param bn The number in a BIGNUM format.
 *
 * @return The number converted to a decimal format.
 * @throws std::runtime_error if conversion fails.
 */
std::string BIGNUMToDec(BIGNUM *bn);

/**
 * @brief Converts a string representation of a UUID to a boost::uuids::uuid
 * object.
 *
 * This function expects the input string to be in a standard UUID format,
 * such as "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx" (with or without braces).
 *
 * @param uuidString The string representation of the UUID.
 * @return A boost::uuids::uuid object.
 * @throws std::runtime_error if the input string is not a valid UUID format.
 */
boost::uuids::uuid stringToBoostUuid(const std::string &uuidString);

/**
 * @brief Converts an integer to its hexadecimal string representation without
 * the "0x" prefix, ensuring an even number of hexadecimal digits (padding with
 * '0' if necessary).
 *
 * @param value The integer to convert.
 * @param uppercase If true, hex digits A-F will be uppercase (e.g., "FF").
 * If false, lowercase (e.g., "ff").
 * @return The hexadecimal string with an even number of digits.
 */
std::string intToHexEvenDigits(int value, bool uppercase = true);

}; // namespace MessageExtractionFacility

#endif // MESSAGE_EXTRACTION_FACILITY_HPP
