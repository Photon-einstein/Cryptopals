#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../include/Client.hpp"
#include "../include/MalloryServer.hpp"

class DiffieHellmanKeyExchangeProtocolMITMattackTest : public ::testing::Test {
protected:
  // cppcheck-suppress unusedFunction
  void SetUp() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    StartServerOnce();
    _fakeServer->clearDiffieHellmanSessionData();
    _mapUsers[_clientId1] = std::make_unique<Client>(_clientId1, _debugFlag);
    _mapUsers[_clientId2] = std::make_unique<Client>(_clientId2, _debugFlag);
    _mapUsers[_clientId3] = std::make_unique<Client>(_clientId3, _debugFlag);
  }

  // cppcheck-suppress unusedFunction
  void TearDown() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    // Cleanup (if needed)
    _mapUsers.clear();
  }

  void StartServerOnce() {
    _fakeServer->runServerTest();
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
  }

  // cppcheck-suppress unusedStructMember
  const bool _debugFlag{false};
  const std::string _clientId1{"Alice"}, _clientId2{"Bob"}, _clientId3{"John"};
  std::unique_ptr<MalloryServer> _fakeServer{
      std::make_unique<MalloryServer>(_debugFlag)};
  std::map<std::string, std::unique_ptr<Client>> _mapUsers;
};

/**
 * @test Test the correctness of the root endpoint of the fake server.
 * @brief Ensures that the root endpoint is working as expected on the fake
 * server.
 */
TEST_F(DiffieHellmanKeyExchangeProtocolMITMattackTest,
       GetRootEndpoint_WithServerRunning_ShouldReturnSuccessStatus) {
  auto response = cpr::Get(cpr::Url{
      "http://localhost:" + std::to_string(_fakeServer->getTestPort()) + "/"});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  EXPECT_EQ(jsonResponse["message"].s(),
            "Mallory Server log | Root endpoint, server up and running");
}
