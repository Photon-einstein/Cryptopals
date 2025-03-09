#ifndef ATTACKER_HPP
#define ATTACKER_HPP

#include "./../include/SHA.hpp"
#include "./../include/SHA1.hpp"
#include "./../include/Server.hpp"

class Attacker {
public:
  /* constructor / destructor*/
  Attacker(const std::shared_ptr<Server> &server, bool writeToFile);
  ~Attacker();

private:
  std::shared_ptr<Server> _server;
  std::shared_ptr<MyCryptoLibrary::SHA> _sha;
};

#endif // ATTACKER_HPP
