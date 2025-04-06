#ifndef SERVER_HPP
#define SERVER_HPP

#include "./../include/MD4.hpp"

#include <memory>
#include <vector>

class Server {
public:
  /* constructor / destructor */
  explicit Server(const bool debugFlag);
  ~Server();

private:
  const bool _debugFlag;
  bool _debugFlagExtreme{false};
  std::vector<unsigned char> _keyServer{};
  std::shared_ptr<MyCryptoLibrary::MessageDigest> _md;
};

#endif // SERVER_HPP
