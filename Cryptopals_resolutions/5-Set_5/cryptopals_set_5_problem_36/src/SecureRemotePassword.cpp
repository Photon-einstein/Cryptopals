#include <iostream>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

#include "./../include/SecureRemotePassword.hpp"

/* constructor / destructor */
MyCryptoLibrary::SecureRemotePassword::SecureRemotePassword(
    const bool debugFlag)
    : _debugFlag{debugFlag} {
  _srpParametersMap = SrpParametersLoader::loadSrpParameters(
      getSrpParametersFilenameLocation());
}
/******************************************************************************/
MyCryptoLibrary::SecureRemotePassword::~SecureRemotePassword() {}
/******************************************************************************/
/**
 * @brief This method returns the location of the file where the public
 * configurations of the Secure Remote Password protocol are available.
 *
 * @return Filename where the public configurations of the Diffie Hellman key
 * exchange protocol are available.
 */
const std::string &
MyCryptoLibrary::SecureRemotePassword::getSrpParametersFilenameLocation() {
  if (_srpParametersFilename.size() == 0) {
    throw std::runtime_error("Secure Remote Password log | "
                             "getSrpParametersFilenameLocation(): public DH "
                             "parameters filename location is empty.");
  }
  return _srpParametersFilename;
}
/******************************************************************************/
