#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../include/Client.hpp"
#include "../include/Server.hpp"

class DiffieHellmanKeyExchangeProtocolTest : public ::testing::Test {
protected:
  // cppcheck-suppress unusedFunction
  void SetUp() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    StartServerOnce();
    _server->clearDiffieHellmanSessionData();
    _mapUsers[_clientId1] =
        std::make_unique<Client>(_clientId1, _debugFlag, _groupNameDH);
    _mapUsers[_clientId2] =
        std::make_unique<Client>(_clientId2, _debugFlag, _groupNameDH);
    _mapUsers[_clientId3] =
        std::make_unique<Client>(_clientId3, _debugFlag, _groupNameDH);
    // set valid test port for testing purpose
    _mapUsers[_clientId1]->setTestPort(_server->getTestPort());
    _mapUsers[_clientId2]->setTestPort(_server->getTestPort());
    _mapUsers[_clientId3]->setTestPort(_server->getTestPort());
  }

  // cppcheck-suppress unusedFunction
  void TearDown() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    // Cleanup (if needed)
    _mapUsers.clear();
  }

  void StartServerOnce() {
    _server->runServerTest();
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
  }

  // cppcheck-suppress unusedStructMember
  const bool _debugFlag{false};
  const std::string _clientId1{"Ana"}, _clientId2{"Eve"}, _clientId3{"Bob"};
  const std::string _groupNameDH{"rfc3526-group-17"};
  std::unique_ptr<Server> _server{std::make_unique<Server>(_debugFlag)};
  std::map<std::string, std::unique_ptr<Client>> _mapUsers;
};

/**
 * @test Test the correctness of the root endpoint of the server.
 * @brief Ensures that the root endpoint is working as expected.
 */
TEST_F(DiffieHellmanKeyExchangeProtocolTest,
       GetRootEndpoint_WithServerRunning_ShouldReturnSuccessStatus) {
  auto response = cpr::Get(cpr::Url{
      "http://localhost:" + std::to_string(_server->getTestPort()) + "/"});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  EXPECT_EQ(jsonResponse["message"].s(),
            "Server log | Root endpoint, server up and running");
}

/**
 * @test Test the correctness of setup of the Diffie Hellman key exchange
 * @brief Ensures that the Diffie Hellman key exchange is completed successfully
 * with one single user attempting to set up the DH key exchange.
 */
TEST_F(DiffieHellmanKeyExchangeProtocolTest,
       DiffieHellmanKeyExchange_WithServerRunning1User_ShouldMatchReference) {
  EXPECT_NO_THROW(_mapUsers[_clientId1]->diffieHellmanKeyExchange(
      _mapUsers[_clientId1]->getTestPort()));
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               "/sessionsData"});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  bool sessionFound{false};
  std::string sessionIdFound{};
  std::string expectedClientId{_mapUsers[_clientId1]->getClientId()};
  for (const std::string &sessionId : jsonResponse.keys()) {
    const crow::json::rvalue &sessionData = jsonResponse[sessionId];
    std::string clientId = sessionData["clientId"].s();
    if (clientId == expectedClientId) {
      sessionFound = true;
      sessionIdFound = sessionId;
      const std::string derivedKey{sessionData["derivedKey"].s()};
      const std::string sessionIdReceived{sessionData["sessionId"].s()};
      const std::string iv{sessionData["iv"].s()};
      const std::string clientNonce{sessionData["clientNonce"].s()};
      const std::string serverNonce{sessionData["serverNonce"].s()};
      EXPECT_EQ(sessionIdReceived, sessionId);
      EXPECT_TRUE(_mapUsers[_clientId1]->verifyServerSessionDataEntryEndpoint(
          sessionIdFound, clientId, clientNonce, serverNonce, derivedKey, iv));
      break;
    }
  }
  EXPECT_TRUE(sessionFound);
  EXPECT_TRUE(_mapUsers[_clientId1]->confirmSessionId(sessionIdFound));
}

/**
 * @test Test the error detection of the Diffie Hellman key exchange protocol.
 * @brief Ensures that the Diffie Hellman key exchange protocol is able to
 * detect errors on small changes in the data used in the protocol.
 */
TEST_F(
    DiffieHellmanKeyExchangeProtocolTest,
    DiffieHellmanKeyExchange_WithServerRunning1UserSlightChangeInTheConfirmationMessageData_ShouldReturnAnError) {
  EXPECT_NO_THROW(_mapUsers[_clientId2]->diffieHellmanKeyExchange(
      _mapUsers[_clientId2]->getTestPort()));
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               "/sessionsData"});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  bool sessionFound{false};
  std::string sessionIdFound{};
  std::string expectedClientId{_mapUsers[_clientId2]->getClientId()};
  for (const std::string &sessionId : jsonResponse.keys()) {
    const crow::json::rvalue &sessionData = jsonResponse[sessionId];
    std::string clientId = sessionData["clientId"].s();
    if (clientId == expectedClientId) {
      sessionFound = true;
      sessionIdFound = sessionId;
      std::string derivedKey{sessionData["derivedKey"].s()};
      std::string sessionIdReceived{sessionData["sessionId"].s()};
      std::string iv{sessionData["iv"].s()};
      std::string clientNonce{sessionData["clientNonce"].s()};
      std::string serverNonce{sessionData["serverNonce"].s()};
      EXPECT_EQ(sessionIdReceived, sessionId);
      EXPECT_TRUE(_mapUsers[_clientId2]->verifyServerSessionDataEntryEndpoint(
          sessionIdFound, clientId, clientNonce, serverNonce, derivedKey, iv));
      sessionIdFound[0] ^= 0x01; // trigger an error
      EXPECT_FALSE(_mapUsers[_clientId2]->verifyServerSessionDataEntryEndpoint(
          sessionIdFound, clientId, clientNonce, serverNonce, derivedKey, iv));
      sessionIdFound[0] ^= 0x01; // reestablish the correct data
      clientId[0] ^= 0x01;       // trigger an error
      EXPECT_FALSE(_mapUsers[_clientId2]->verifyServerSessionDataEntryEndpoint(
          sessionIdFound, clientId, clientNonce, serverNonce, derivedKey, iv));
      clientId[0] ^= 0x01;    // reestablish the correct data
      clientNonce[0] ^= 0x01; // trigger an error
      EXPECT_FALSE(_mapUsers[_clientId2]->verifyServerSessionDataEntryEndpoint(
          sessionIdFound, clientId, clientNonce, serverNonce, derivedKey, iv));
      clientNonce[0] ^= 0x01; // reestablish the correct data
      serverNonce[0] ^= 0x01; // trigger an error
      EXPECT_FALSE(_mapUsers[_clientId2]->verifyServerSessionDataEntryEndpoint(
          sessionIdFound, clientId, clientNonce, serverNonce, derivedKey, iv));
      serverNonce[0] ^= 0x01; // reestablish the correct data
      derivedKey[0] ^= 0x01;  // trigger an error
      EXPECT_FALSE(_mapUsers[_clientId2]->verifyServerSessionDataEntryEndpoint(
          sessionIdFound, clientId, clientNonce, serverNonce, derivedKey, iv));
      derivedKey[0] ^= 0x01; // reestablish the correct data
      iv[0] ^= 0x01;         // trigger an error
      EXPECT_FALSE(_mapUsers[_clientId2]->verifyServerSessionDataEntryEndpoint(
          sessionIdFound, clientId, clientNonce, serverNonce, derivedKey, iv));
      iv[0] ^= 0x01; // reestablish the correct data
      break;
    }
  }
  EXPECT_TRUE(sessionFound);
  EXPECT_TRUE(_mapUsers[_clientId2]->confirmSessionId(sessionIdFound));
}

/**
 * @test Test the correctness of setup of the Diffie Hellman key exchange with
 * several users.
 * @brief Ensures that the Diffie Hellman key exchange is completed successfully
 * with several users sessions established with different clients.
 */
TEST_F(
    DiffieHellmanKeyExchangeProtocolTest,
    DiffieHellmanKeyExchange_WithServerRunningWithSeveralUsers_ShouldMatchReference) {
  EXPECT_NO_THROW(_mapUsers[_clientId1]->diffieHellmanKeyExchange(
      _mapUsers[_clientId1]->getTestPort()));
  EXPECT_NO_THROW(_mapUsers[_clientId1]->diffieHellmanKeyExchange(
      _mapUsers[_clientId1]->getTestPort()));
  EXPECT_NO_THROW(_mapUsers[_clientId2]->diffieHellmanKeyExchange(
      _mapUsers[_clientId2]->getTestPort()));
  EXPECT_NO_THROW(_mapUsers[_clientId2]->diffieHellmanKeyExchange(
      _mapUsers[_clientId2]->getTestPort()));
  EXPECT_NO_THROW(_mapUsers[_clientId2]->diffieHellmanKeyExchange(
      _mapUsers[_clientId2]->getTestPort()));
  EXPECT_NO_THROW(_mapUsers[_clientId3]->diffieHellmanKeyExchange(
      _mapUsers[_clientId3]->getTestPort()));
  EXPECT_NO_THROW(_mapUsers[_clientId3]->diffieHellmanKeyExchange(
      _mapUsers[_clientId3]->getTestPort()));
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               "/sessionsData"});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  int numberSessionsFound{0}, numbersSessionsCreated{7};
  for (const std::string &sessionId : jsonResponse.keys()) {
    const crow::json::rvalue &sessionData = jsonResponse[sessionId];
    const std::string clientId = sessionData["clientId"].s();
    const std::string derivedKey{sessionData["derivedKey"].s()};
    const std::string sessionIdReceived{sessionData["sessionId"].s()};
    const std::string iv{sessionData["iv"].s()};
    const std::string clientNonce{sessionData["clientNonce"].s()};
    const std::string serverNonce{sessionData["serverNonce"].s()};
    EXPECT_EQ(sessionIdReceived, sessionId);
    EXPECT_TRUE(_mapUsers[clientId]->verifyServerSessionDataEntryEndpoint(
        sessionIdReceived, clientId, clientNonce, serverNonce, derivedKey, iv));
    EXPECT_TRUE(_mapUsers[clientId]->confirmSessionId(sessionId));
    ++numberSessionsFound;
  }
  EXPECT_EQ(numbersSessionsCreated, numberSessionsFound);
}
