#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <cpr/cpr.h>

#include "DhParametersLoader.hpp"
#include "DiffieHellman.hpp"
#include "MessageExtractionFacility.hpp"

class Client {
public:
  /* constructor / destructor*/
  explicit Client(const std::string &clientId, const bool debugFlag);
  ~Client();

  /* public methods */

  /**
   * @brief This method will perform the Diffie Hellman key exchange protocol
   * with a given server.
   *
   * @param portServerNumber The number of the server to use in this exchange.
   *
   * This method will perform the Diffie Hellman key exchange protocol with
   * a given server, in order to agree on a given symmetric encryption key.
   *
   * @throw runtime_error if portServerNumber < 1024
   */
  void diffieHellmanKeyExchange(const int portServerNumber);

  /**
   * @brief This method will confirm if a given session id is correctly setup.
   *
   * This method will confirm if a given session id is correctly setup on the
   * client side.
   *
   * @return A bool value, true if the sessionId exists, false otherwise.
   */
  bool confirmSessionId(const std::string &sessionId);

  /**
   * @brief This method return the client ID.
   *
   * This method return the client ID of a given client.
   *
   * @return A string, the client ID.
   * @throw runtime_error if the client ID is null.
   */
  const std::string &getClientId() const;

  /**
   * @brief This method will return the production port of the server.
   *
   * This method will return the production port of the server to establish a
   * connection.
   */
  const int getProductionPort() const;

  /**
   * @brief This method will return the test port of the server.
   *
   * This method will return the test port of the server to establish a
   * connection.
   */
  const int getTestPort() const;

private:
  /* private structures */
  struct SessionData {
    std::unique_ptr<MyCryptoLibrary::DiffieHellman> _diffieHellman;
    std::string _serverNonceHex;
    std::string _clientNonceHex;
    std::string _derivedKeyHex;
    std::vector<uint8_t> _iv;

    SessionData(std::unique_ptr<MyCryptoLibrary::DiffieHellman> diffieHellman,
                const std::string &serverNonceHex,
                const std::string &clientNonceHex,
                const std::vector<uint8_t> &iv)
        : _diffieHellman(std::move(diffieHellman)),
          _serverNonceHex{serverNonceHex}, _clientNonceHex{clientNonceHex},
          _iv{iv} {}
  };

  /* private methods */

  /**
   * @brief This method will print the server response to the Diffie Hellman
   * key exchange protocol.
   *
   * This method will print the server response to the Diffie Hellman
   * key exchange protocol. The response is a json text, and it will be printed
   * in a structured way.
   *
   * @param response The response received by the server during the execution
   * of the Diffie Hellman key exchange protocol.
   */
  static void printServerResponse(const cpr::Response &response);

  /**
   * @brief This method will perform the decryption of the ciphertext received
   * by the server and test it against the plaintext data received.
   *
   * This method will perform the decryption of the ciphertext received by
   * the server and test it against the plaintext data received. The test passes
   * if the data matches for every fields.
   *
   * @param ciphertext The ciphertext send by the server as the challenge to
   * check if the Diffie Hellman key exchange protocol was executed successfully
   * by the client.
   * @param key The symmetric key derived by the client in raw bytes, after the
   * conclusion of the Diffie Hellman key exchange protocol.
   * @param iv The initialization vector of the AES-256-CBC mode encryption
   * process, sent by the server, in raw bytes.
   * @param sessionId The unique session ID sent by the server.
   * @param clientId The client ID associated with this connection.
   * @param clientNonce The client nonce associated with this connection, in
   * hexadecimal format.
   * @param serverNonce The server nonce associated with this connection, in
   * hexadecimal format.
   * @param message The conclusion message expected from this protocol (e.g.,
   * "Key exchange complete").
   *
   * @retval true Decryption and validation were successful.
   * @retval false Decryption or validation failed.
   * @return A tuple containing:
   *         - bool: indicating success or failure of validation.
   *         - std::string: the decrypted plaintext message. If decryption
   * fails, this may contain garbage or incomplete data.
   */
  std::tuple<bool, std::string> confirmationServerResponse(
      const std::string &ciphertext, const std::vector<uint8_t> &key,
      const std::vector<uint8_t> &iv, const std::string &sessionId,
      const std::string &clientId, const std::string &clientNonce,
      const std::string &serverNonce, const std::string &message);

  /* private fields */
  std::map<std::string, std::unique_ptr<SessionData>> _diffieHellmanMap;

  const int _portServerProduction{18080};
  const int _portServerTest{18081};

  const std::string _clientId{};
  const std::size_t _nonceSize{16}; // bytes
  const bool _debugFlag;
};

#endif // CLIENT_HPP
