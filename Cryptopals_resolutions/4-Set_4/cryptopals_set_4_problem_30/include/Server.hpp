#ifndef SERVER_HPP
#define SERVER_HPP

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
};

#endif // SERVER_HPP
