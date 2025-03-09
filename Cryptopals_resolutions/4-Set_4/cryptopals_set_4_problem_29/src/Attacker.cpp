#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>

#include "./../include/Attacker.hpp"

/* constructor / destructor */
Attacker::Attacker(const std::shared_ptr<Server> &server, bool writeToFile) {
  _sha = std::make_shared<MyCryptoLibrary::SHA1>();
}
/******************************************************************************/
Attacker::~Attacker() {}
/******************************************************************************/