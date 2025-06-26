#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../include/Client.hpp"
#include "../include/MalloryServer.hpp"
#include "../include/Server.hpp"

class DiffieHellmanKeyExchangeProtocolMITMattackTest : public ::testing::Test {
protected:
  // cppcheck-suppress unusedFunction
  void SetUp() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    StartServerOnce();
    _fakeServer->clearDiffieHellmanSessionData();
    _server->clearDiffieHellmanSessionData();
    _mapUsers[_clientId1] =
        std::make_unique<Client>(_clientId1, _debugFlag, _groupNameDH);
    _mapUsers[_clientId2] =
        std::make_unique<Client>(_clientId2, _debugFlag, _groupNameDH);
    _mapUsers[_clientId3] =
        std::make_unique<Client>(_clientId3, _debugFlag, _groupNameDH);
  }

  // cppcheck-suppress unusedFunction
  void TearDown() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    // Cleanup (if needed)
    _mapUsers.clear();
  }

  void StartServerOnce() {
    _fakeServer->runServerTest();
    _server->runServerTest();
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
  }

  // cppcheck-suppress unusedStructMember
  const bool _debugFlag{false}, _testFlag{true};
  const std::string _clientId1{"Alice"}, _clientId2{"Bob"}, _clientId3{"John"};
  const std::string _groupNameDH{"rfc3526-group-17"};
  std::unique_ptr<MalloryServer> _fakeServer{
      std::make_unique<MalloryServer>(_debugFlag, _testFlag)};
  std::unique_ptr<Server> _server{std::make_unique<Server>(_debugFlag)};
  std::map<std::string, std::unique_ptr<Client>> _mapUsers;
};

/**
 * @test Test the correctness of the root endpoint of the fake server.
 * @brief Ensures that the root endpoint is working as expected on the fake
 * server.
 */
TEST_F(DiffieHellmanKeyExchangeProtocolMITMattackTest,
       GetRootEndpoint_WithFakeServerRunning_ShouldReturnSuccessStatus) {
  auto response = cpr::Get(cpr::Url{
      "http://localhost:" + std::to_string(_fakeServer->getTestPort()) + "/"});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  EXPECT_EQ(jsonResponse["message"].s(),
            "Mallory Server log | Root endpoint, server up and running");
}

/**
 * @test Test the correctness of MITM attack with one client
 * @brief Ensures that the MITM attack is successful with one single client
 * attempting to set up the DH key exchange, asserting that he remains oblivious
 * to a third party interception of the session with a fake server.
 * The message exchange is tested if if can be forwarded transparently by means
 * of a man in the middle attack.
 */
TEST_F(
    DiffieHellmanKeyExchangeProtocolMITMattackTest,
    DiffieHellmanKeyExchange_WithMalloryServerRunning1User_ShouldDeceiveClient) {
  const std::tuple<bool, std::string, std::string> keyExchangeResult =
      _mapUsers[_clientId1]->diffieHellmanKeyExchange(
          _mapUsers[_clientId1]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult));
  const std::string newSessionId = std::get<2>(keyExchangeResult);
  auto response = cpr::Get(cpr::Url{
      "http://localhost:" + std::to_string(_fakeServer->getTestPort()) +
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
    if (clientId == expectedClientId && sessionId == newSessionId) {
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
  EXPECT_TRUE(_mapUsers[_clientId1]->messageExchange(
      _mapUsers[_clientId1]->getTestPort(), sessionIdFound));
}

/**
 * @test Test the error detection of the Diffie Hellman key exchange protocol
 * during a MITM attack.
 * @brief Ensures that the Diffie Hellman key exchange protocol is able to
 * detect errors on small changes in the data used in the protocol when a MITM
 * attack has been performed as well.
 */
TEST_F(
    DiffieHellmanKeyExchangeProtocolMITMattackTest,
    DiffieHellmanKeyExchange_WithFakeServerRunning1UserSlightChangeInTheConfirmationMessageData_ShouldReturnAnError) {
  const std::tuple<bool, std::string, std::string> keyExchangeResult =
      _mapUsers[_clientId2]->diffieHellmanKeyExchange(
          _mapUsers[_clientId2]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult));
  const std::string newSessionId = std::get<2>(keyExchangeResult);
  auto response = cpr::Get(cpr::Url{
      "http://localhost:" + std::to_string(_fakeServer->getTestPort()) +
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
    if (clientId == expectedClientId && newSessionId == sessionId) {
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
 * @test Test the correctness of MITM attack with several clients at the same
 * time
 * @brief Ensures that the MITM attack is successful with several clients
 * attempting to set up the DH key exchange, asserting that he remains oblivious
 * to a third party interception of the session with a fake server.
 */
TEST_F(
    DiffieHellmanKeyExchangeProtocolMITMattackTest,
    DiffieHellmanKeyExchange_WithFakeServerRunningWithSeveralUsers_ShouldDeceiveClients) {
  const std::tuple<bool, std::string, std::string> keyExchangeResult1 =
      _mapUsers[_clientId1]->diffieHellmanKeyExchange(
          _mapUsers[_clientId1]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult1));
  std::set<std::string> sessionsIdsSet;
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult1));

  const std::tuple<bool, std::string, std::string> keyExchangeResult2 =
      _mapUsers[_clientId1]->diffieHellmanKeyExchange(
          _mapUsers[_clientId1]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult2));
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult2));

  const std::tuple<bool, std::string, std::string> keyExchangeResult3 =
      _mapUsers[_clientId2]->diffieHellmanKeyExchange(
          _mapUsers[_clientId2]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult3));
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult3));

  const std::tuple<bool, std::string, std::string> keyExchangeResult4 =
      _mapUsers[_clientId2]->diffieHellmanKeyExchange(
          _mapUsers[_clientId2]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult4));
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult4));

  const std::tuple<bool, std::string, std::string> keyExchangeResult5 =
      _mapUsers[_clientId2]->diffieHellmanKeyExchange(
          _mapUsers[_clientId2]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult5));
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult5));

  const std::tuple<bool, std::string, std::string> keyExchangeResult6 =
      _mapUsers[_clientId3]->diffieHellmanKeyExchange(
          _mapUsers[_clientId3]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult6));
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult6));

  const std::tuple<bool, std::string, std::string> keyExchangeResult7 =
      _mapUsers[_clientId3]->diffieHellmanKeyExchange(
          _mapUsers[_clientId3]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult7));
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult7));

  auto response = cpr::Get(cpr::Url{
      "http://localhost:" + std::to_string(_fakeServer->getTestPort()) +
      "/sessionsData"});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  int numberSessionsFound{0}, numbersSessionsCreated{7};
  for (const std::string &sessionId : jsonResponse.keys()) {
    EXPECT_TRUE(sessionsIdsSet.count(sessionId) == 1);
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

/**
 * @test Test the correctness of MITM attack with one client with parameter
 * injection MITM attack
 * @brief Ensures that the MITM attack is successful with one single client
 * attempting to set up the DH key exchange, asserting that he remains oblivious
 * to a third party interception of the session with a fake server when a
 * parameter injection is performed on the fake server side.
 */
TEST_F(
    DiffieHellmanKeyExchangeProtocolMITMattackTest,
    DiffieHellmanKeyExchange_WithMalloryServerRunning1UserWithParameterInjection_ShouldDeceiveClient) {
  _fakeServer->setParameterInjectionFlag(true);
  const std::tuple<bool, std::string, std::string> keyExchangeResult =
      _mapUsers[_clientId1]->diffieHellmanKeyExchange(
          _mapUsers[_clientId1]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult));
  const std::string newSessionId = std::get<2>(keyExchangeResult);
  auto response = cpr::Get(cpr::Url{
      "http://localhost:" + std::to_string(_fakeServer->getTestPort()) +
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
    if (clientId == expectedClientId && sessionId == newSessionId) {
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
 * @test Test the error detection of the Diffie Hellman key exchange protocol
 * during a MITM attack with parameter injection.
 * @brief Ensures that the Diffie Hellman key exchange protocol is able to
 * detect errors on small changes in the data used in the protocol when a MITM
 * attack with parameter injection has been performed as well.
 */
TEST_F(
    DiffieHellmanKeyExchangeProtocolMITMattackTest,
    DiffieHellmanKeyExchange_WithFakeServerRunning1UserSlightChangeInTheConfirmationMessageDataWithParameterInjection_ShouldReturnAnError) {
  _fakeServer->setParameterInjectionFlag(true);
  const std::tuple<bool, std::string, std::string> keyExchangeResult =
      _mapUsers[_clientId2]->diffieHellmanKeyExchange(
          _mapUsers[_clientId2]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult));
  const std::string newSessionId = std::get<2>(keyExchangeResult);
  auto response = cpr::Get(cpr::Url{
      "http://localhost:" + std::to_string(_fakeServer->getTestPort()) +
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
    if (clientId == expectedClientId && newSessionId == sessionId) {
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
 * @test Test the correctness of MITM attack with parameter injection with
 * several clients at the same time.
 * @brief Ensures that the MITM attack with parameter injection is successful
 * with several clients attempting to set up the DH key exchange, asserting that
 * he remains oblivious to a third party interception of the session with a fake
 * server.
 */
TEST_F(
    DiffieHellmanKeyExchangeProtocolMITMattackTest,
    DiffieHellmanKeyExchange_WithFakeServerRunningWithSeveralUsersWithParameterInjection_ShouldDeceiveClients) {
  _fakeServer->setParameterInjectionFlag(true);
  const std::tuple<bool, std::string, std::string> keyExchangeResult1 =
      _mapUsers[_clientId1]->diffieHellmanKeyExchange(
          _mapUsers[_clientId1]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult1));
  std::set<std::string> sessionsIdsSet;
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult1));

  const std::tuple<bool, std::string, std::string> keyExchangeResult2 =
      _mapUsers[_clientId1]->diffieHellmanKeyExchange(
          _mapUsers[_clientId1]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult2));
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult2));

  const std::tuple<bool, std::string, std::string> keyExchangeResult3 =
      _mapUsers[_clientId2]->diffieHellmanKeyExchange(
          _mapUsers[_clientId2]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult3));
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult3));

  const std::tuple<bool, std::string, std::string> keyExchangeResult4 =
      _mapUsers[_clientId2]->diffieHellmanKeyExchange(
          _mapUsers[_clientId2]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult4));
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult4));

  const std::tuple<bool, std::string, std::string> keyExchangeResult5 =
      _mapUsers[_clientId2]->diffieHellmanKeyExchange(
          _mapUsers[_clientId2]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult5));
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult5));

  const std::tuple<bool, std::string, std::string> keyExchangeResult6 =
      _mapUsers[_clientId3]->diffieHellmanKeyExchange(
          _mapUsers[_clientId3]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult6));
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult6));

  const std::tuple<bool, std::string, std::string> keyExchangeResult7 =
      _mapUsers[_clientId3]->diffieHellmanKeyExchange(
          _mapUsers[_clientId3]->getTestPort());
  EXPECT_TRUE(std::get<0>(keyExchangeResult7));
  sessionsIdsSet.insert(std::get<2>(keyExchangeResult7));

  auto response = cpr::Get(cpr::Url{
      "http://localhost:" + std::to_string(_fakeServer->getTestPort()) +
      "/sessionsData"});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  int numberSessionsFound{0}, numbersSessionsCreated{7};
  for (const std::string &sessionId : jsonResponse.keys()) {
    EXPECT_TRUE(sessionsIdsSet.count(sessionId) == 1);
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
