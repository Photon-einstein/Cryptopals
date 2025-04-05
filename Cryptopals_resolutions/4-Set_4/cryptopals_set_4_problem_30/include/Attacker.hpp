#ifndef ATTACKER_HPP
#define ATTACKER_HPP

#include "./../include/MessageFormat.hpp"
#include "./../include/Server.hpp"

#include <memory>

class Attacker {
public:
  /* constructor / destructor*/
  Attacker(const std::shared_ptr<Server> &server, bool debugFlag);
  ~Attacker();

private:
  bool _debugFlag{false};
  const bool _debugFlagExtreme{false};
  const std::string _messageLocation{"./../input/intercepted_url.txt"};
  std::shared_ptr<Server> _server;
  MessageFormat::MessageParsed _msgParsed;
};

#endif // ATTACKER_HPP
