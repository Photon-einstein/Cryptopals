#ifndef SERVER_HPP
#define SERVER_HPP

#include <vector>

class Server {
public:
  /* constructor / destructor */
  explicit Server(const bool debugFlag);
  ~Server();

  /**
   * @brief This method will validate if a given message produces the
   * given message authentication code (MAC)
   *
   * This method will validate if a given message produces the
   * given message authentication code (MAC), it will perform the following
   * test: MD4(private server key || msg) == mac
   *
   * @param msg The message to be authenticated
   * @param mac The message authentication code (mac) to be validated in
   * binary format
   *
   * @return A bool value, true if the mac received matches the
   * mac produced by the server, false otherwise
   */
  bool validateMac(const std::vector<unsigned char> &msg,
                   const std::vector<unsigned char> &mac);

private:
  const bool _debugFlag;
  bool _debugFlagExtreme{false};
};

#endif // SERVER_HPP
