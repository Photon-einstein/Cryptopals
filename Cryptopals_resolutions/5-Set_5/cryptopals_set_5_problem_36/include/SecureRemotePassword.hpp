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
  explicit SecureRemotePassword(const bool debugFlag);
  ~SecureRemotePassword();

  /* public methods */

  /**
   * @brief This method returns the location of the file where the public
   * configurations of the Secure Remote Password protocol are available.
   *
   * @return Filename where the public configurations of the Diffie Hellman key
   * exchange protocol are available.
   */
  const std::string &getSrpParametersFilenameLocation();

private:
  /* private methods */

  /* private members */
  bool _debugFlag;
  const std::string _srpParametersFilename{"../input/SrpParameters.json"};
  std::map<unsigned int, SrpParametersLoader::SrpParameters> _srpParametersMap;
  unsigned int _groupId;
};

} // namespace MyCryptoLibrary

#endif // SECURE_REMOTE_PASSWORD_HPP
