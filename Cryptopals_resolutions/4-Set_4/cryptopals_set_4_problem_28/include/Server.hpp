#ifndef SERVER_HPP
#define SERVER_HPP

#include <memory>
#include <openssl/aes.h>
#include <string>
#include <vector>

#include "./../include/PrintFormat.hpp"
#include "./../include/SHA.hpp"
#include "./../include/SHA1.hpp"

// Define SHA_DIGEST_LENGTH if it is not defined elsewhere.
// SHA-1 produces a 160-bit (20-byte) digest.
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

class Server {
public:
  /* constructor / destructor */
  explicit Server(const bool debugFlag);
  ~Server();

  /* public methods */

  /**
   * @brief Calculates the SHA1 hash using the OpenSSL library
   *
   * This method perform the hash SHA1 of the message using the OpenSSL library
   *
   * @param inputV The characters to be hashed in a vector format
   * @param originalMessage The characters to be hashed in a string format
   * @return The hash SHA1 of the inputV characters
   */
  std::vector<unsigned char>
  hashSHA1WithLibrary(const std::vector<unsigned char> &inputV,
                      const std::string &originalMessage);

  /**
   * @brief Calculates the hash SHA-1 using a custom made library
   *
   * This method perform the hash SHA-1 of the message with a custom made
   * library
   *
   * @param inputV The characters to be hashed in a vector format
   * @param originalMessage The characters to be hashed in a string format
   * @return The hash SHA1 of the inputV characters
   */
  std::vector<unsigned char> hashSHA1(const std::vector<unsigned char> &inputV,
                                      const std::string &originalMessage);

  /**
   * @brief This method does the verification of a given mac and the
   * corresponding message
   *
   * This method does the verification of a given mac and the corresponding
   * message, checking if the message was tampered
   *
   * @param message The message that was hashed
   * @param mac The corresponding mac value of the given message
   * @return The true if the hash(key sender || message) == mac, false otherwise
   */
  bool checkMac(const std::string &message,
                const std::vector<unsigned char> &mac);

private:
  /**
   * @brief This method print the hash value and the original message to be
   * hashed.
   *
   * This method print the hash value and the original message in the specified
   * format.
   *
   * @param originalMessage The characters to be hashed in a string format
   * @param hash The originalMessage hashed in a vector format
   * @param format The format to be used in the print of the hash value (HEX,
   * DECIMAL, ASCII)
   */
  static void printMessage(const std::string &originalMessage,
                           const std::vector<unsigned char> &hash,
                           PrintFormat::Format format);

  /**
   * @brief This method sets the key to be used as a prefix in a hash
   * calculation.
   *
   * This method sets the key to be used as a prefix in a hash calculation,
   * for a given sender of a message
   */
  void setKey(const std::string &message);

  /**
   * @brief This method prepend the key to the input that is going to be hashed
   *
   * This method prepend the key to the input that is going to be hashed
   *
   * @param inputV The input that is going to be hashed
   */
  std::vector<unsigned char>
  prependKey(const std::vector<unsigned char> &inputV);

  /**
   * @brief This method extract the content of a given file
   *
   * This method will extract the content of a given file location
   *
   * @return The content of a file in a vector format
   */
  static std::vector<unsigned char>
  extractFile(const std::string &fileLocation);

  /******************************************************************************/
  /**
   * @brief This method will deal with errors during encryption/decryption
   *
   * This method will deal with errors during encryption/decryption, including
   * printing error messages
   */
  static void handleErrors();

  /**
   * @brief This method will decrypt the ciphertext using aes256 cbc mode
   *
   * This method will decrypt the ciphertext using aes256 cbc mode, using key
   * and iv in the process, returning by reference in the plaintext the result
   *
   * @param ciphertext The input to be decrypted
   * @param key The key to be used in the decryption
   * @param plaintext The plaintext resulting of the decryption
   * @param iv The initialization vector used in the decryption
   */
  static void decrypt(const std::vector<unsigned char> &ciphertext,
                      const std::string &key, std::string &plaintext,
                      unsigned char *iv);
  /**
   * @brief This method will remove the padding PKCDS7
   *
   * This method will remove the padding PKCDS7 from the data, in place
   *
   * @param data The input to be removed the padding, by reference
   */
  static void removePKCS7Padding(std::vector<unsigned char> &data);

  /**
   * @brief This method will convert hexadecimal string to byte vector
   *
   * This method will convert hexadecimal string to byte vector, using zero
   * alignment
   *
   * @param hexStr The input to be converted
   *
   * @return The byte vector resulting of the conversion
   */
  static std::vector<unsigned char> hexToBytes(const std::string &hexStr);

  const bool _debugFlag;
  std::shared_ptr<MyCryptoLibrary::SHA> _sha;
  std::vector<unsigned char> _plaintextV;
  std::string _plaintext;
  std::vector<unsigned char> _hashOpenSSL;
  std::vector<unsigned char> _hash;
  std::vector<unsigned char> _key;
  std::vector<unsigned char> _keyServer;
  unsigned char _iv[AES_BLOCK_SIZE] = {0};
  const std::string _keysFileLocation{
      "./../input/Server_database/symmetric_keys_encrypted_aes.json.enc"};
};

#endif // SERVER_HPP
