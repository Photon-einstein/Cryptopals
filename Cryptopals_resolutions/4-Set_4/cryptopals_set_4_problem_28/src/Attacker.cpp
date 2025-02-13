
#include "./../include/Attacker.hpp"

/* constructor / destructor */
Attacker::Attacker(std::shared_ptr<Server>& server) {
  Attacker::setServer(server);
}
/******************************************************************************/
Attacker::~Attacker() {
}
/******************************************************************************/
void Attacker::setServer(std::shared_ptr<Server>& server) {
    _server = server;
  }
  /******************************************************************************/
