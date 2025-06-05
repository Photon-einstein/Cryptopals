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
  }

  // cppcheck-suppress unusedFunction
  void TearDown() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    // Cleanup (if needed)
  }

  void StartServerOnce() {
    _server->runServerTest();
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
  }

  // cppcheck-suppress unusedStructMember
  const bool _debugFlag{false};
  const std::string _clientId1{"Ana"}, _clientId2{"Eve"}, _clientId3{"Bob"};
  std::unique_ptr<Server> _server{std::make_unique<Server>(_debugFlag)};
  std::unique_ptr<Client> _client1{
      std::make_unique<Client>(_clientId1, _debugFlag)};
  std::unique_ptr<Client> _client2{
      std::make_unique<Client>(_clientId2, _debugFlag)};
  std::unique_ptr<Client> _client3{
      std::make_unique<Client>(_clientId3, _debugFlag)};
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
 */
TEST_F(DiffieHellmanKeyExchangeProtocolTest,
       DiffieHellmanKeyExchange_WithServerRunning_ShouldNotThrow) {
  EXPECT_NO_THROW(_client1->diffieHellmanKeyExchange(_client1->getTestPort()));
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               "/sessionsData"});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  bool sessionFound{false};
  std::string sessionIdFound{};
  std::string expectedClientId{_client1->getClientId()};
  std::cout << response.text << std::endl;
  for (const std::string &sessionId : jsonResponse.keys()) {
    const crow::json::rvalue &sessionData = jsonResponse[sessionId];
    std::string clientId = sessionData["clientId"].s();
    if (clientId == expectedClientId) {
      sessionFound = true;
      sessionIdFound = sessionId;
      EXPECT_TRUE(sessionData["derivedKey"].s().size());
      EXPECT_TRUE(sessionData["sessionId"].s().size());
      EXPECT_TRUE(sessionData["iv"].s().size());
      EXPECT_TRUE(sessionData["clientNonce"].s().size());
      EXPECT_TRUE(sessionData["serverNonce"].s().size());
      break;
    }
  }
  EXPECT_TRUE(sessionFound);
  EXPECT_TRUE(_client1->confirmSessionId(sessionIdFound));
}