#ifndef SERVER_HPP
#define SERVER_HPP

#include <string>
#include <vector>
#include <memory>

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
  /* constructor / destructor*/
  Server();
  ~Server();

  /* public methods */

  /**
   * @brief Calculates the SHA1 hash using the Openssl library
   *
   * This function takes two integers as input and returns their sum.
   *
   * @param inputV The characters to be hashed in a vector format
   * @param originalMessage The characters to be hashed in a string format
   * @return The hash SHA1 of the inputV characters
   */
  std::vector<unsigned char> hashSHA1WithLibrary(const std::vector<unsigned char> &inputV,
    const std::string &originalMessage);
  
  /**
   * @brief Calculates the SHA1 without Openssl library
   *
   * This function takes two integers as input and returns their sum.
   *
   * @param inputV The characters to be hashed in a vector format
   * @param originalMessage The characters to be hashed in a string format
   * @return The hash SHA1 of the inputV characters
   */
  std::vector<unsigned char> hashSHA1(const std::vector<unsigned char> &inputV,
    const std::string &originalMessage);


  /**
   * @brief This method print the hash value and the original message to be hashed.
   *
   * This method print the hash value and the original message in the specified format.
   *
   * @param originalMessage The characters to be hashed in a string format
   * @param hash The originalMessage hashed in a vector format
   * @param format The format to be used in the print of the hash value.
   */
  void printMessage(const std::string& originalMessage, const std::vector<unsigned char> &hash, PrintFormat::Format format);

  void setPlaintext(const int sizePlaintext, bool randomPlaintext, const std::string &plaintext);

  const std::vector<unsigned char> getPlaintextV();
  
  const std::string getPlaintext();

private:
  bool _debugFlag = true;
  std::shared_ptr<MyCryptoLibrary::SHA> _sha;
  std::vector<unsigned char> _plaintextV;
  std::string _plaintext;
  std::vector<unsigned char> _hashOpenSSL;
  std::vector<unsigned char> _hash;
};

#endif // SERVER_HPP
