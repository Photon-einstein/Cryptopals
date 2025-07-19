#include <nlohmann/json.hpp>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "./../include/MallorySessionData.hpp"

/* constructor / destructor */

/**
 * @brief This method will execute the constructor of the MallorySessionData
 * structure.
 *
 * This method will execute the constructor of the MallorySessionData structure
 * used by the MalloryServer object.
 *
 * @param nonceSize The nonce size used in the Diffie Hellman key exchange
 * protocol.
 * @param clientNonceHex The client nonce received in hexadecimal format.
 * @param clientId The client id that is using this session.
 * @param debugFlag The boolean flag to decide if aggressive prints should be
 * displayed into the standard output, created for troubleshooting purposes.
 * @param ivLength The length of the initialization vector (IV) used in the
 * symmetric encryption AES-256-CBC mode, in bytes.
 * @param p The prime p used in the Diffie Hellman key exchange protocol.
 * @param g The generator g used in the Diffie Hellman key exchange protocol.
 *
 * @throw runtime_error if clientId or groupNameDH are empty.
 */
MallorySessionData::MallorySessionData(
    const std::size_t nonceSize, const std::string &clientNonceHex,
    const std::string &clientId, const bool debugFlag,
    const std::size_t ivLength, const std::string &p, const std::string &g)
    : _diffieHellmanAM(
          std::make_unique<MyCryptoLibrary::DiffieHellman>(debugFlag, p, g)),
      _serverNonceHexAM(
          EncryptionUtility::generateCryptographicNonce(nonceSize)),
      _clientNonceHexAM{clientNonceHex}, _clientIdAM{clientId},
      _ivAM{EncryptionUtility::generateRandomIV(ivLength)} {};
/******************************************************************************/
/**
 * @brief This method will perform the destruction of the MallorySessionData
 * object.
 *
 * This method will perform the destruction of the MallorySessionData object,
 * releasing all the resources and memory used.
 */
MallorySessionData::~MallorySessionData() {}
/******************************************************************************/
