#ifndef ATTACKER_H
#define ATTACKER_H

#include "./../include/Server.hpp"

class Attacker {
public:
    /* constructor / destructor*/
    Attacker(std::shared_ptr<Server>& server);
    ~Attacker();

    /* public methods */
    /* setter */
    void setServer(std::shared_ptr<Server>& server);

private:
  std::shared_ptr<Server> _server;
};

#endif // ATTACKER_HPP
