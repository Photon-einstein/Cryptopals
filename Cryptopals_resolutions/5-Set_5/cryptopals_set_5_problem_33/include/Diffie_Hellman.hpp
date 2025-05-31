#ifndef DIFFIE_HELLMAN_HPP
#define DIFFIE_HELLMAN_HPP

#include <boost/uuid/uuid.hpp>
#include <memory>
#include <openssl/sha.h>
#include <vector>

#include "DH_parameters_loader.hpp"
#include "Diffie_Hellman.hpp"
#include "MessageExtractionFacility.hpp"

namespace MyCryptoLibrary {

class Diffie_Hellman {
public:
  /* constructor / destructor*/
  Diffie_Hellman(const bool debugFlag);
  ~Diffie_Hellman();

  /* public methods */
  const std::string getPublicKey();
  const std::string getGroupName();
  const std::string deriveSharedSecret(const std::string &peerPublicKeyHex,
                                       const std::string &serverNonceHex,
                                       const std::string &clientNonceHex);

private:
  /* private methods */
  void generatePrivateKey();
  void generatePublicKey();

  /* private members */
  const std::string _dhParametersFilename{"./../input/dh_parameters.json"};
  DHParametersLoader::DHParameters _dhParameter;
  MessageExtractionFacility::UniqueBIGNUM _p, _g, _privateKey, _publicKey,
      _sharedSecret;
  bool _debugFlag;
};

} // namespace MyCryptoLibrary

#endif // DIFFIE_HELLMAN_HPP
