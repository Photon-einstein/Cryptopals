#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>

#include "./../include/Attacker.hpp"

/* constructor / destructor */
Attacker::Attacker(std::shared_ptr<Server> &server) {
  Attacker::setServer(server);
  _sha = std::make_shared<MyCryptoLibrary::SHA1>();
}
/******************************************************************************/
Attacker::~Attacker() {}
/******************************************************************************/
/**
 * @brief This method sets the server
 *
 * This method sets the server into the attackers data structure
 *
 * @param server The server shared pointer
 */
void Attacker::setServer(std::shared_ptr<Server> &server) { _server = server; }
/******************************************************************************/
/**
 * @brief This method will try to tamper a message
 *
 * This method will try to tamper a message intercepted and
 * deceive the server with another message authentication
 * code (MAC)
 *
 * @param messageLocation The location were the message is located
 * @return The content of the message intercepted by the attacker
 */
bool Attacker::tamperMessageTry() {
  const std::string messageLocation{"./../input/transaction_Alice_to_Bob.json"};
  std::string transactionMessage = Attacker::extractMessage(messageLocation);
  const int newAmount{9000};
  const std::string newRecipient{"Mallory"};
  nlohmann::ordered_json transaction =
      nlohmann::json::parse(transactionMessage);
  const std::string forgedTransactionLocation{
      "./../output/forged_transaction_Alice_to_Mallory.json"};
  std::ofstream outFile(forgedTransactionLocation);
  if (!outFile) {
    const std::string errorMessage = "Attacker log | " +
                                     forgedTransactionLocation +
                                     " file not able to be written";
    throw std::invalid_argument(errorMessage);
  }
  // forge the transaction with new data
  transaction["recipient"] = newRecipient;
  transaction["amount"] = newAmount;
  transaction.erase("hash");
  nlohmann::ordered_json transactionForgedOrdered = {
      {"sender", transaction["sender"]},
      {"recipient", transaction["recipient"]},
      {"amount", transaction["amount"]},
      {"currency", transaction["currency"]}};
  std::string jsonStr = transactionForgedOrdered.dump(4);
  // calculation of a new hash with the forget new data
  std::vector<unsigned char> jsonV(jsonStr.begin(), jsonStr.end());
  std::vector<unsigned char> newHashV = Attacker::_sha->hash(jsonV);
  transactionForgedOrdered["hash"] = Attacker::toHexString(newHashV);
  // write to the output file the forged transaction content
  outFile << transactionForgedOrdered.dump(4);
  outFile.close();
  return Attacker::_server->checkMac(jsonStr, newHashV);
}
/******************************************************************************/
/**
 * @brief This method converts a vector into a string in hex format
 *
 * This method will convert a vector into a string of hexadecimal
 * characters, padded with zero
 *
 * @param data The vector with chars to be converted
 * @return A string containing the chars with hexadecimal format, zero padded
 */
std::string Attacker::toHexString(const std::vector<unsigned char> &data) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0'); // Use hex format and pad with zeros
  for (unsigned char byte : data) {
    ss << std::setw(2)
       << static_cast<int>(byte); // Convert to int to print properly
  }
  return ss.str();
}
/******************************************************************************/
/**
 * @brief This method extract the message intercepted
 *
 * This method will extract the message intercepted in a
 * bank transaction
 *
 * @return A bool value, true if the attack was successful,
 * false otherwise
 */
std::string Attacker::extractMessage(const std::string &messageLocation) {
  std::ifstream file(messageLocation);
  if (!file) {
    const std::string errorMessage =
        "Attacker log | " + messageLocation + " file not found";
    throw std::invalid_argument(errorMessage);
  }
  std::stringstream buffer;
  buffer << file.rdbuf();
  std::string transaction = buffer.str();
  file.close();
  return transaction;
}
/******************************************************************************/