#include <fstream>
#include <iostream>
#include <limits.h>
#include <nlohmann/json.hpp>
#include <sstream>

#include "./../include/Attacker.hpp"
#include "./../include/MessageExtractionFacility.hpp"

/* constructor / destructor */
Attacker::Attacker(const std::shared_ptr<Server> &server, bool debugFlag)
    : _debugFlag{debugFlag}, _server{server} {}
/******************************************************************************/
Attacker::~Attacker() {}
/******************************************************************************/
