#include <charconv>
#include <iomanip>
#include <iostream>
#include <openssl/rand.h>
#include <sstream>

#include "./../include/MessageExtractionFacility.hpp"

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
std::vector<unsigned char>
MessageExtractionFacility::hexToBytes(const std::string &hexStr) {
  bool flagOdd{false};
  int step = 2;
  if (hexStr.length() % 2 != 0) {
    flagOdd = true;
    step = 1;
  }
  std::vector<unsigned char> bytes;
  for (size_t i = 0; i < hexStr.length(); i += step) {
    std::string byteString = hexStr.substr(i, step);
    unsigned char byte;
    // Using std::from_chars for faster conversion (C++17)
    std::from_chars(byteString.data(), byteString.data() + byteString.size(),
                    byte, 16);
    bytes.push_back(byte);
    if (flagOdd) {
      step = 2;
      flagOdd = false;
    }
  }
  return bytes;
}
/******************************************************************************/
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
std::string
MessageExtractionFacility::toHexString(const std::vector<unsigned char> &data) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0'); // Use hex format and pad with zeros
  for (unsigned char byte : data) {
    ss << std::setw(2)
       << static_cast<int>(byte); // Convert to int to print properly
  }
  return ss.str();
}
/******************************************************************************/
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
MessageExtractionFacility::UniqueBIGNUM
MessageExtractionFacility::hexToUniqueBIGNUM(const std::string &hexNumber) {
  BIGNUM *bnPtr = nullptr; // BN_hex2bn needs a pointer to a BIGNUM*
                           // It will allocate the BIGNUM itself.
  if (!BN_hex2bn(&bnPtr, hexNumber.c_str())) {
    // OpenSSL functions return 0 on error, non-zero on success.
    // Get OpenSSL error string for more details.
    char errBuf[256];
    ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
    throw std::runtime_error(
        "MessageExtractionFacility log | hexToUniqueBIGNUM(): "
        "Failed to convert hex string to BIGNUM: " +
        std::string(errBuf));
  }
  return UniqueBIGNUM(bnPtr); // Wrap the raw pointer in UniqueBIGNUM
}
/******************************************************************************/
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
std::string MessageExtractionFacility::BIGNUMToHex(BIGNUM *bn) {
  // BN_bn2hex allocates memory that needs to be freed with OPENSSL_free
  char *hexChars = BN_bn2hex(bn);
  if (!hexChars) {
    throw std::runtime_error("MessageExtractionFacility log | BIGNUMToHex(): "
                             "Failed to convert BIGNUM to hex string.");
  }
  std::string hexStr(hexChars); // Convert C-string to std::string
  OPENSSL_free(hexChars);       // Free the allocated memory

  // Check if the length of the hexadecimal string is odd
  // This happens for values like 0 ("0"), 1 ("1"), 10 ("A"), 256 ("100"), etc.
  if (hexStr.length() % 2 != 0) {
    // If odd, prepend a '0' to make the length even
    hexStr = "0" + hexStr;
  }
  return hexStr;
}
/******************************************************************************/
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
std::string MessageExtractionFacility::BIGNUMToDec(BIGNUM *bn) {
  if (!bn) {
    return "";
  }
  char *decChars = BN_bn2dec(bn); // Allocates memory
  if (!decChars) {
    char errBuf[256];
    ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
    throw std::runtime_error("MessageExtractionFacility log | BIGNUMToDec(): "
                             "Failed to convert BIGNUM to decimal string: " +
                             std::string(errBuf));
  }
  std::string decStr(decChars); // Copy to std::string
  OPENSSL_free(decChars);       // Free the allocated C-style string
  return decStr;
}
/******************************************************************************/
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
boost::uuids::uuid
MessageExtractionFacility::stringToBoostUuid(const std::string &uuidString) {
  try {
    boost::uuids::string_generator generator;
    return generator(uuidString);
  } catch (const std::runtime_error &e) {
    throw std::runtime_error("Failed to convert string to UUID: '" +
                             uuidString + "' - " + e.what());
  }
}
/******************************************************************************/
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
std::string MessageExtractionFacility::intToHexEvenDigits(int value,
                                                          bool uppercase) {
  using UnsignedInt = std::make_unsigned_t<int>; // e.g., unsigned int
  UnsignedInt uvalue = static_cast<UnsignedInt>(value);

  std::string hex_str;
  if (uppercase) {
    hex_str = std::format("{:X}", uvalue);
  } else {
    hex_str = std::format("{:x}", uvalue);
  }

  if (hex_str.length() % 2 != 0) {
    int required_width = hex_str.length() + 1;
    if (uppercase) {
      return std::format("{:0{}X}", uvalue, required_width);
    } else {
      return std::format("{:0{}x}", uvalue, required_width);
    }
  } else {
    return hex_str;
  }
}
/******************************************************************************/
