#include <iostream>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

#include "./../include/SecureRemotePassword.hpp"

/* static fields initialization */
unsigned int MyCryptoLibrary::SecureRemotePassword::_minSizePrivateKey = 256;

/* constructor / destructor */

/**
 * @brief This method will execute the constructor of the SecureRemotePassword
 * object.
 *
 * This method will perform the constructor of the SecureRemotePassword object
 * when a group name is used in its constructor.
 *s
 * @param debugFlag The boolean flag to decide if aggressive prints should be
 * displayed into the standard output, created for troubleshooting purposes.
 */
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
 * @return Filename where the public configurations of the Secure Remote
 * Password protocol are available.
 */
const std::string &
MyCryptoLibrary::SecureRemotePassword::getSrpParametersFilenameLocation() {
  if (_srpParametersFilename.size() == 0) {
    throw std::runtime_error("Secure Remote Password log | "
                             "getSrpParametersFilenameLocation(): public SRP "
                             "parameters filename location is empty.");
  }
  return _srpParametersFilename;
}
/******************************************************************************/
/**
 * @brief This method returns the minimum size of a private key in bits,
 * according to the SRP protocol.
 *
 * @return The minimum size of a private key at the SPP protocol, in bits.
 */
const unsigned int &
MyCryptoLibrary::SecureRemotePassword::getMinSizePrivateKey() {
  if (_minSizePrivateKey <= 0) {
    throw std::runtime_error("Secure Remote Password log | "
                             "getMinSizePrivateKey(): stored minSizePrivateKey "
                             "is invalid");
  }
  return _minSizePrivateKey;
}
/******************************************************************************/
