#ifndef SESSION_DATA_HPP
#define SESSION_DATA_HPP

#include "SrpParametersLoader.hpp"
#include "SecureRemotePassword.hpp"
#include "EncryptionUtility.hpp"

struct SessionData {

  /**
   * @brief This method will execute the constructor of the SessionData
   * structure
   */
  explicit SessionData();

  /**
   * @brief This method will perform the destruction of the SessionData
   * structure.
   *
   * This method will perform the destruction of the SessionData structure,
   * releasing all the resources and memory used.
   */
  ~SessionData();

  std::unique_ptr<MyCryptoLibrary::SecureRemotePassword> _secureRemotePassword;
};

#endif // SESSION_DATA_HPP