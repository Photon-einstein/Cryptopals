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

  /**
   * @brief This method will validate if a given message has produces the
   * given message authentication code (MAC)
   *
   * This method will validate if a given message has produces the
   * given message authentication code (MAC), it will perform the following
   * test: SHA1(private server key || msg) == mac
   *
   * @param msg The message to be authenticated
   * @param mac The message authentication code (mac) to be validated in
   * hexadecimal format
   *
   * @return A bool value, true if the mac received matches the
   * mac produced by the server
   */
  bool validateMac(const std::vector<unsigned char> &msg,
                   const std::vector<unsigned char> &mac);

  /**
   * @brief This method will append the padding to the message
   *
   * This method will append the padding according to the requirements
   * of the SHA1 hash
   *
   * @param message The message to be padded
   * @return The message padded
   */
  std::vector<unsigned char> computeSHA1padding(const std::string &message);

private:
  const bool _debugFlag;
  bool _debugFlagExtreme{false};
  std::vector<unsigned char> _keyServer{};
  std::shared_ptr<MyCryptoLibrary::SHA> _sha;
};

#endif // SERVER_HPP
