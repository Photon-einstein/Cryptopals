#ifndef SECURE_REMOTE_PASSWORD_HPP
#define SECURE_REMOTE_PASSWORD_HPP

#include <boost/uuid/uuid.hpp>
#include <memory>
#include <openssl/sha.h>
#include <vector>

#include "MessageExtractionFacility.hpp"
#include "SrpParametersLoader.hpp"

namespace MyCryptoLibrary {

class SecureRemotePassword {
public:
  /* constructor / destructor*/

  /**
   * @brief This method will execute the constructor of the SecureRemotePassword
   * object.
   *
   * This method will perform the constructor of the SecureRemotePassword object
   * when a group name is used in its constructor.
   *s
   * @param debugFlag The boolean flag to decide if aggressive prints should be
   * displayed into the standard output, created for troubleshooting purposes.
   *
   */
  explicit SecureRemotePassword(const bool debugFlag);

  /**
   * @brief This method will perform the destruction of the SecureRemotePassword
   * object.
   *
   * This method will perform the destruction of the SecureRemotePassword
   * object, releasing all the resources and memory used.
   */
  ~SecureRemotePassword();

  /* public methods */

  /**
   * @brief This method returns the location of the file where the public
   * configurations of the Secure Remote Password protocol are available.
   *
   * @return Filename where the public configurations of the Secure Remote
   * Password protocol are available.
   */
  const std::string &getSrpParametersFilenameLocation();

  /**
   * @brief This method returns the minimum size of a private key in bits,
   * according to the SRP protocol.
   *
   * @return The minimum size of a private key at the SPP protocol, in bits.
   */
  const unsigned int &getMinSizePrivateKey();

private:
  /* private methods */

  /* private members */
  bool _debugFlag;
  const std::string _srpParametersFilename{"../input/SrpParameters.json"};
  std::map<unsigned int, SrpParametersLoader::SrpParameters> _srpParametersMap;
  unsigned int _groupId;
  static unsigned int _minSizePrivateKey;
};

} // namespace MyCryptoLibrary

#endif // SECURE_REMOTE_PASSWORD_HPP
