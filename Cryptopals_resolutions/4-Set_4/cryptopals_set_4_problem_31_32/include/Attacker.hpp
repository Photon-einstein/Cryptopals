#ifndef ATTACKER_HPP
#define ATTACKER_HPP

#include <cpr/cpr.h>
#include <tuple>

class Attacker {
public:
  /* constructor / destructor*/
  Attacker();
  ~Attacker();

  /**
   * @brief This method will try to break HMAC SHA1 signature for any given
   * file.
   *
   * This method will try to break HMAC SHA1 signature for any given
   * file, the signature will be validated on the server side.
   *
   * @param fileName the file that the attacker is trying to find the signature
   *
   * @return bool: true if the attack succeed or false otherwise
   * @return string: the signature cracked in case the attack succeed
   */
  std::tuple<bool, std::string> breakHmacSHA1(const std::string &fileName);

private:
  /**
   * @brief This method will send a request to the server to validate.
   *
   * This method will send a request to the server to validate. It will send the
   * file to access and the signature to grant the access.
   *
   * @return bool value, true if the request response of the server is a 200
   * code success, false otherwise
   * @return cpr::Response curl response from the server
   */
  std::tuple<bool, cpr::Response>
  sendRequest(const std::string &signature, const std::string &fileName) const;

  /**
   * @brief This method will print in a structured way the server response
   *
   * This method will print in a structured way the server response to an
   * attacker curl request.
   */
  static void printServerResponse(const cpr::Response &response);

  const int _portServerProduction{18080};
  const int _portServerTest{18081};
  const int _attackSamples{10};
};

#endif // ATTACKER_HPP
