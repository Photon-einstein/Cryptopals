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
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
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
