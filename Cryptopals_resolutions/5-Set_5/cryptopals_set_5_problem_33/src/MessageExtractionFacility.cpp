#include "./../include/MessageExtractionFacility.hpp"

#include <charconv>
#include <iomanip>
#include <iostream>
#include <sstream>

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
 * @brief This method converts a vector of bytes into a string in hex format
 *
 * This method will convert a vector of bytes into a string of hexadecimal
 * characters, padded with zero
 *
 * @param data The vector with bytes to be converted
 * @return A string containing the chars with hexadecimal format, zero padded
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
// Function to convert hex string to UniqueBIGNUM
MessageExtractionFacility::UniqueBIGNUM
MessageExtractionFacility::hexToUniqueBIGNUM(const std::string &hexStr) {
  BIGNUM *bnPtr = nullptr; // BN_hex2bn needs a pointer to a BIGNUM*
                           // It will allocate the BIGNUM itself.
  if (!BN_hex2bn(&bnPtr, hexStr.c_str())) {
    // OpenSSL functions return 0 on error, non-zero on success.
    // Get OpenSSL error string for more details.
    char errBuf[256];
    ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
    throw std::runtime_error("Failed to convert hex string to BIGNUM: " +
                             std::string(errBuf));
  }
  return UniqueBIGNUM(bnPtr); // Wrap the raw pointer in UniqueBIGNUM
}
/******************************************************************************/
// Function to convert BIGNUM to hex string for display
std::string MessageExtractionFacility::BIGNUMToHex(BIGNUM *bn) {
  char *hexChars = BN_bn2hex(bn); // Allocates memory
  if (!hexChars) {
    throw std::runtime_error("Failed to convert BIGNUM to hex string.");
  }
  std::string hexStr(hexChars);
  OPENSSL_free(hexChars); // Free memory allocated by BN_bn2hex
  return hexStr;
}
/******************************************************************************/
// Helper function to convert BIGNUM to a decimal string
std::string MessageExtractionFacility::BIGNUMToDec(BIGNUM *bn) {
  if (!bn) {
    return "";
  }
  char *decChars = BN_bn2dec(bn); // Allocates memory
  if (!decChars) {
    char errBuf[256];
    ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
    throw std::runtime_error("Failed to convert BIGNUM to decimal string: " +
                             std::string(errBuf));
  }
  std::string dec_str(decChars); // Copy to std::string
  OPENSSL_free(decChars);        // Free the allocated C-style string
  return dec_str;
}
/******************************************************************************/