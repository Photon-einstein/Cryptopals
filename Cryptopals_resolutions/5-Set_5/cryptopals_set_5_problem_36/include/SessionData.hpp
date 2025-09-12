#ifndef SESSION_DATA_HPP
#define SESSION_DATA_HPP

#include "EncryptionUtility.hpp"
#include "SecureRemotePassword.hpp"
#include "SrpParametersLoader.hpp"

struct SessionData {

  /**
   * @brief This method will execute the constructor of the SessionData
   * structure.
   *
   * This method will execute the constructor of the SessionData structure. It
   * will perform all the necessary data initializations.
   *
   * @param groupId The group ID that is going to be used with this client ID
   * session
   * @param salt The salt that is going to be used with this client ID session.
   * @param hash The hash algorithm that is to be used with client ID session.
   * @param debugFlag If true there is be more information in the logs, false
   * otherwise.
   */
  explicit SessionData(const unsigned int groupId, const std::string &salt,
                       const std::string &hash, const bool debugFlag);

  /**
   * @brief This method will perform the destruction of the SessionData
   * structure.
   *
   * This method will perform the destruction of the SessionData structure,
   * releasing all the resources and memory used.
   */
  ~SessionData();

  std::unique_ptr<MyCryptoLibrary::SecureRemotePassword> _secureRemotePassword;
  unsigned int _groupId;
  std::string _salt; // hexadecimal format
  std::string _hash; // (e.g., "SHA-256", "SHA-384", "SHA-512").
  std::string _password;
  std::string _vHex;                // Store the verifier v in hex format
  bool registrationComplete{false}; // Indicates if registration is finished
  std::string _privateKeyHex;
  std::string _publicKeyHex;
  std::string _peerPublicKeyHex;
};

#endif // SESSION_DATA_HPP
