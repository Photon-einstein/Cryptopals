#include "./../include/SessionData.hpp"

/**
 * @brief Server's constructor side. This method will execute the constructor
 * of the SessionData structure on the server side.
 *
 * This method will execute the constructor of the SessionData structure used
 * by the Server object.
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
SessionData::SessionData(const std::size_t nonceSize,
                         const std::string &clientNonceHex,
                         const std::string &clientId, const bool debugFlag,
                         const std::size_t ivLength, const std::string &p,
                         const std::string &g)
    : _diffieHellman(
          std::make_unique<MyCryptoLibrary::DiffieHellman>(debugFlag, p, g)),
      _serverNonceHex(EncryptionUtility::generateCryptographicNonce(nonceSize)),
      _clientNonceHex{clientNonceHex}, _clientId{clientId},
      _iv{EncryptionUtility::generateRandomIV(ivLength)} {};
/******************************************************************************/
/**
 * @brief Client's constructor side. This method will execute the constructor
 * of the SessionData structure on the client side.
 *
 * This method will execute the constructor of the SessionData structure used
 * by the client object.
 *
 * @param diffieHellman The DiffieHellman object to be used in this session.
 * @param serverNonceHex The server nonce received in hexadecimal format.
 * @param clientNonceHex The client nonce in hexadecimal format.
 * @param iv The initialization vector (iv) used in the AES-256-CBC mode.
 */
SessionData::SessionData(
    std::unique_ptr<MyCryptoLibrary::DiffieHellman> diffieHellman,
    const std::string &serverNonceHex, const std::string &clientNonceHex,
    const std::vector<uint8_t> &iv)
    : _diffieHellman(std::move(diffieHellman)), _serverNonceHex{serverNonceHex},
      _clientNonceHex{clientNonceHex}, _iv{iv} {};
/******************************************************************************/
/**
 * @brief This method will perform the destruction of the SessionData
 * structure.
 *
 * This method will perform the destruction of the SessionData structure,
 * releasing all the resources and memory used.
 */
SessionData::~SessionData(){};
/******************************************************************************/
