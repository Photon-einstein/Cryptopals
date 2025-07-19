#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <cpr/cpr.h>
#include <openssl/aes.h>

#include "DhParametersLoader.hpp"
#include "DiffieHellman.hpp"
#include "MessageExtractionFacility.hpp"
#include "SessionData.hpp"

class Client {
public:
  /* constructor / destructor*/

  /**
   * @brief This method will execute the constructor of the Client object.
   *
   * This method will perform the constructor of the Client object when a group
   * name is used in its constructor.
   *
   * @param clientId The client id to be used by this client.
   * @param debugFlag The boolean flag to decide if aggressive prints should be
   * displayed into the standard output, created for troubleshooting purposes.
   * @param groupNameDH The group name to be used in the DH key exchange
   * protocol, to get the values of 'p' and 'g'.
   *
   * @throw runtime_error if clientId or groupNameDH are empty.
   */
  explicit Client(const std::string &clientId, const bool debugFlag,
                  const std::string &groupNameDH);

  /**
   * @brief This method will perform the constructor of the Client object.
   *
   * This method will perform the constructor of the Client object when the DH
   * parameters 'p' and 'g' are used.
   *
   * @param clientId The client id to be used by this client.
   * @param debugFlag The boolean flag to decide if aggressive prints should be
   * displayed into the standard output, created for troubleshooting purposes.
   * @param p The prime number p to be used in the DH key exchange protocol.
   * @param g The generator g to be used in the DH key exchange protocol.
   *
   * @throw runtime_error if clientId, p or g are empty.
   */
  explicit Client(const std::string &clientId, const bool debugFlag,
                  const std::string &p, const std::string &g);

  /**
   * @brief This method will perform the destruction of the Client object.
   *
   * This method will perform the destruction of the Client object, releasing
   * all the resources and memory used.
   */
  ~Client();

  /* public methods */

  /**
   * @brief This method will perform the Diffie Hellman key exchange protocol
   * with a given server.
   *
   * This method will perform the Diffie Hellman key exchange protocol with
   * a given server, in order to agree on a given symmetric encryption key.
   *
   * @param portServerNumber The number of the server to use in this exchange.
   *
   * @return A tuple containing:
   *         - bool: indicating success or failure of validation.
   *         - std::string: the decrypted plaintext message. If decryption
   * fails, this may contain garbage or incomplete data.
   *         - std::string: the created session ID
   * @throw runtime_error if portServerNumber < 1024
   */
  const std::tuple<bool, std::string, std::string>
  diffieHellmanKeyExchange(const int portServerNumber);

  /**
   * @brief This method will perform the message exchange route.
   *
   * This method will perform a secure message exchange a with a given server
   * after the Diffie Hellman key exchange protocol has been successfully
   * executed and a valid session created.
   *
   * @param portServerNumber The number of the server to use in this message
   * exchange.
   * @param sessionId The session id to be used in this connection with the
   * server.
   *
   * @return A bool, true if the exchange and validation was successful, failure
   * otherwise.
   *
   * @throw runtime_error if there was an error in the messageExchange.
   */
  const bool messageExchange(const int portServerNumber,
                             const std::string &sessionId);

  /**
   * @brief This method will confirm if a given session id is correctly setup.
   *
   * This method will confirm if a given session id is correctly setup on the
   * client side.
   *
   * @param sessionId The session id to be confirmed.
   *
   * @return A bool value, true if the sessionId exists, false otherwise.
   */
  bool confirmSessionId(const std::string &sessionId) const;

  /**
   * @brief This method sets the server's test port to a new one.
   *
   * This method sets the server's test port to a new one, used only for
   * test purposes.
   *
   * @param portServerTest The port number to be used in the test scenario.
   *
   * @throw runtime_error if the portServerTest is not a valid one.
   */
  void setTestPort(const int portServerTest);

  /**
   * @brief This method returns the client ID.
   *
   * This method returns the client ID of a given client.
   *
   * @return A string, the client ID.
   * @throw runtime_error if the client ID is null.
   */
  const std::string &getClientId() const;

  /**
   * @brief This method will return the server's production port.
   *
   * This method will return the server's production port to establish a
   * connection.
   *
   * @return An int, the server's production port.
   */
  const int getProductionPort() const;

  /**
   * @brief This method will return the server's test port.
   *
   * This method will return the server's test port to establish a
   * connection.
   *
   * @return An int, the server test port.
   */
  const int getTestPort() const;

  /**
   * @brief This method will return the Diffie Hellman's map.
   *
   * This method will return the Diffie Hellman's map of the client.
   *
   * @return A map, the client's DH map.
   */
  std::map<std::string, std::unique_ptr<SessionData>> &getDiffieHellmanMap();

  /**
   * @brief This method does the verification if this entry exists on the client
   * side.
   *
   * This method verify if this entry exists on the client side.
   * These method's arguments are one entry from the endpoint of the server
   * named GET '/sessionsData'.
   *
   * @param sessionId The session id to be verified.
   * @param clientId The client id to be verified for a given session id.
   * @param clientNonce The client nonce to be verified for a given session id.
   * @param serverNonce The server nonce to be verified for a given session id.
   * @param derivedKey The derived key to be verified for a given session id.
   * @param iv The initialization vector to be verified for a given session id.
   *
   * @return Bool value, true if there is a match, false otherwise.
   */
  const bool verifyServerSessionDataEntryEndpoint(
      const std::string &sessionId, const std::string &clientId,
      const std::string &clientNonce, const std::string &serverNonce,
      const std::string &derivedKey, const std::string &iv) const;

  /**
   * @brief This method will print the server response to the Diffie Hellman
   * key exchange protocol.
   *
   * This method will print the server response to the Diffie Hellman key
   * exchange protocol. The response is a json text, and it will be printed in a
   * structured way.
   *
   * @param response The response sent by the server during the execution
   * of the Diffie Hellman key exchange protocol.
   */
  static void printServerResponse(const cpr::Response &response);

private:
  /* private methods */

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
   * @param message The conclusion message expected from this protocol starts
   * with the expected message (e.g. "Key exchange complete").
   *
   * @return A tuple containing:
   *         - bool: indicating success or failure of validation.
   *         - std::string: the decrypted plaintext message. If decryption
   * fails, this may contain garbage or incomplete data.
   */
  std::tuple<bool, std::string, std::string> confirmationServerResponse(
      const std::string &ciphertext, const std::vector<uint8_t> &key,
      const std::vector<uint8_t> &iv, const std::string &sessionId,
      const std::string &clientId, const std::string &clientNonce,
      const std::string &serverNonce, const std::string &message);

  /* private fields */
  std::map<std::string, std::unique_ptr<SessionData>> _diffieHellmanMap;
  const int _portServerProduction{18080};
  int _portServerTest{18081};

  const std::string _clientId{};
  const std::size_t _nonceSize{16};            // bytes
  const std::size_t _ivLength{AES_BLOCK_SIZE}; // bytes
  const bool _debugFlag;
  const std::string _groupNameDH = "";
  const std::string _pHex;
  const std::string _gHex;
};

#endif // CLIENT_HPP
