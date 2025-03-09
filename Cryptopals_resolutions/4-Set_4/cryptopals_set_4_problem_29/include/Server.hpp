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

private:
  const bool _debugFlag;
  std::shared_ptr<MyCryptoLibrary::SHA> _sha;
};

#endif // SERVER_HPP
