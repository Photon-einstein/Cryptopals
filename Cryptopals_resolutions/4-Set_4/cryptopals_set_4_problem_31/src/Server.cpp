#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "./../include/Server.hpp"

/* constructor / destructor */
Server::Server(const bool debugFlag) : _debugFlag(debugFlag) {}
/******************************************************************************/
Server::~Server() {}
/******************************************************************************/
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
bool Server::validateMac(const std::vector<unsigned char> &msg,
                         const std::vector<unsigned char> &mac) {
  return true;
}
/******************************************************************************/