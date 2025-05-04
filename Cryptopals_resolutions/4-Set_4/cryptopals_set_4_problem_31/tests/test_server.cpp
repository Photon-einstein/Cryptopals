#include <gtest/gtest.h>

#include <cpr/cpr.h>
#include <crow.h>
#include <vector>

#include "../include/Server.hpp"

class ServerTest : public ::testing::Test {
protected:
  // cppcheck-suppress unusedFunction
  void SetUp() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    _server = std::make_unique<Server>(_debugFlag);
    StartServerOnce();
  }

  // cppcheck-suppress unusedFunction
  void TearDown() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    // Cleanup (if needed)
    _server->getApp().stop();
  }

  void StartServerOnce() {
    _server->runServerTest();
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  }

  std::unique_ptr<Server> _server;
  const bool _debugFlag{false};
  const std::string _portTest = std::to_string(18081);
};

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

/**
 * @test Test that the server has his root endpoint running
 *
 * Test that the server has his root endpoint running. The server
 * root endpoint should be available
 *
 * Should return success code
 */
TEST_F(ServerTest, rootEndpoint_ServerRunning_ShouldReturnSuccessStatus) {
  cpr::Response response =
      cpr::Get(cpr::Url{"http://localhost:" + _portTest + "/"});
  ASSERT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  EXPECT_EQ(jsonResponse["message"].s(),
            "Root endpoint, Server up and running");
}

/**
 * @test Test that the server can validate a given signature with hmac
 * @brief Test that the server can validate a given signature with hmac,
 * performing the following test: HMAC-SHA1(key server || msg) == mac,
 * good weather scenario
 *
 * Should return success code with a matching signature
 */
TEST_F(ServerTest,
       signatureVerificationEndpoint_ValidSignature_ShouldReturnSuccessStatus) {
  std::string fileName = "foo";
  std::string correctSignature = "a039502c73f8bc0873a10af0ef49497b8918b062";
  cpr::Response response = cpr::Get(
      cpr::Url{"http://localhost:" + _portTest + "/test"},
      cpr::Parameters{{"file", fileName}, {"signature", correctSignature}});
  ASSERT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  EXPECT_EQ(jsonResponse["file"].s(), fileName);
  EXPECT_EQ(jsonResponse["signature"].s(),
            std::string("0x") + correctSignature);
  EXPECT_TRUE(jsonResponse["verified"].b());
}

/**
 * @test Test that the server can validate a given signature with hmac
 * @brief Test that the server can validate a given signature with hmac,
 * performing the following test: HMAC-SHA1(key server || msg) == mac,
 * bad weather scenario
 *
 * Should return error code with an invalid signature
 */
TEST_F(ServerTest,
       signatureVerificationEndpoint_InvalidSignature_ShouldReturnErrorStatus) {
  std::string fileName = "foo";
  std::string correctSignature = "a039502c73f8bc0873a10af0ef49497b8918b06";
  correctSignature[0] ^= 0x01; // 1 bit flip
  cpr::Response response = cpr::Get(
      cpr::Url{"http://localhost:" + _portTest + "/test"},
      cpr::Parameters{{"file", fileName}, {"signature", correctSignature}});
  ASSERT_EQ(response.status_code, 401);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  EXPECT_EQ(jsonResponse["error"].s(),
            "Invalid signature. HMAC verification failed.");
}
