#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <fmt/core.h>
#include <string>
#include <vector>

#include "../include/Client.hpp"
#include "../include/EncryptionUtility.hpp"
#include "../include/Server.hpp"
#include "../include/SrpParametersLoader.hpp"

class SecureRemotePasswordProtocolTest : public ::testing::Test {
protected:
  // cppcheck-suppress unusedFunction
  void SetUp() override {
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    StartServerOnce();
    _server->clearSecureRemotePasswordMap();
    _mapUsers[_clientId1] = std::make_unique<Client>(_clientId1, _debugFlag);
    _mapUsers[_clientId2] = std::make_unique<Client>(_clientId2, _debugFlag);
    _mapUsers[_clientId3] = std::make_unique<Client>(_clientId3, _debugFlag);
    // set valid test port for testing purpose
    _mapUsers[_clientId1]->setTestPort(_server->getTestPort());
    _mapUsers[_clientId2]->setTestPort(_server->getTestPort());
    _mapUsers[_clientId3]->setTestPort(_server->getTestPort());
    _srpParametersMap = SrpParametersLoader::loadSrpParameters(
        _server->getSrpParametersFilenameLocation());
    _minSaltSizesMap = EncryptionUtility::getMinSaltSizes();
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
  std::map<std::string, std::unique_ptr<Client>> _mapUsers;
  std::map<unsigned int, SrpParametersLoader::SrpParameters> _srpParametersMap;
  std::map<std::string, unsigned int> _minSaltSizesMap;
};

/**
 * @test Test the correctness of the root endpoint of the server.
 * @brief Ensures that the root endpoint is working as expected.
 */
TEST_F(SecureRemotePasswordProtocolTest,
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
 * @test Test the correctness of the /srp/register/init endpoint of the server.
 * @brief Ensures that the /srp/register/init endpoint is working as expected.
 * The scenario tested is the following one:
 * - only a valid user ID is provided by a given client;
 * - the request group ID is not provided, so it is expected that the server
 * provides a valid and expected one on the reply message.
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    GetGroupsDataEndpoint_WithValidClientIdAndNoRequestedGroupIdProvided_ShouldMatchReference) {
  std::string requestBody = fmt::format(
      R"({{
        "clientId": "{}"
    }})",
      _mapUsers[_clientId1]->getClientId());
  const unsigned int minGroupIdExpected{1}, maxGroupIdExpected{7};
  cpr::Response response =
      cpr::Post(cpr::Url{std::string("http://localhost:") +
                         std::to_string(_server->getTestPort()) +
                         std::string("/srp/register/init")},
                cpr::Header{{"Content-Type", "application/json"}},
                cpr::Body{requestBody});
  EXPECT_EQ(response.status_code, 201);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  const unsigned long int extractedGroupId{jsonResponse["groupId"].u()};
  ASSERT_TRUE(jsonResponse);
  EXPECT_EQ(jsonResponse["clientId"].s(), _mapUsers[_clientId1]->getClientId());
  EXPECT_GE(extractedGroupId, minGroupIdExpected);
  EXPECT_LE(extractedGroupId, maxGroupIdExpected);
  EXPECT_EQ(jsonResponse["groupName"].s(),
            _srpParametersMap[extractedGroupId]._groupName);
  EXPECT_EQ(jsonResponse["primeN"].s(),
            _srpParametersMap[extractedGroupId]._nHex);
  EXPECT_EQ(jsonResponse["generatorG"].u(),
            _srpParametersMap[extractedGroupId]._g);
  EXPECT_EQ(jsonResponse["sha"].s(),
            _srpParametersMap[extractedGroupId]._hashName);
  EXPECT_GE(
      jsonResponse["salt"].s().size() * 2,
      _minSaltSizesMap[jsonResponse["sha"].s()]); // salt is received in
                                                  // hexadecimal format, salt
                                                  // sizes is in bytes
}

/**
 * @test Test the correctness of the /srp/register/init endpoint of the server.
 * @brief Ensures that the /srp/register/init endpoint is working as expected.
 * The scenario tested is the following one:
 * - a valid user ID is provided by a given client;
 * - the request group ID provided is less than the minimum required by the
 * server;
 * - the expected result should be a group ID at least with the minimum required
 * value defined at the server level.
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    GetGroupsDataEndpoint_WithValidClientIdRequestedGroupIdLessThanDefaultValue_ShouldMatchReference) {
  const unsigned int minGroupIdExpected{1}, maxGroupIdExpected{7};
  const unsigned int defaultGroupId = _server->getDefaultGroupId();
  EXPECT_GE(defaultGroupId, minGroupIdExpected);
  EXPECT_LE(defaultGroupId, maxGroupIdExpected);
  const unsigned int providedGroupId{defaultGroupId - 1};
  std::string requestBody = fmt::format(
      R"({{
        "clientId": "{}",
        "requestedGroup": {}
    }})",
      _mapUsers[_clientId1]->getClientId(), providedGroupId);
  cpr::Response response =
      cpr::Post(cpr::Url{std::string("http://localhost:") +
                         std::to_string(_server->getTestPort()) +
                         std::string("/srp/register/init")},
                cpr::Header{{"Content-Type", "application/json"}},
                cpr::Body{requestBody});
  EXPECT_EQ(response.status_code, 201);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  const unsigned long int extractedGroupId{jsonResponse["groupId"].u()};
  ASSERT_TRUE(jsonResponse);
  EXPECT_EQ(jsonResponse["clientId"].s(), _mapUsers[_clientId1]->getClientId());
  EXPECT_GE(extractedGroupId, defaultGroupId);
  EXPECT_GE(extractedGroupId, minGroupIdExpected);
  EXPECT_LE(extractedGroupId, maxGroupIdExpected);
  EXPECT_EQ(jsonResponse["groupName"].s(),
            _srpParametersMap[extractedGroupId]._groupName);
  EXPECT_EQ(jsonResponse["primeN"].s(),
            _srpParametersMap[extractedGroupId]._nHex);
  EXPECT_EQ(jsonResponse["generatorG"].u(),
            _srpParametersMap[extractedGroupId]._g);
  EXPECT_EQ(jsonResponse["sha"].s(),
            _srpParametersMap[extractedGroupId]._hashName);
  EXPECT_GE(
      jsonResponse["salt"].s().size() * 2,
      _minSaltSizesMap[jsonResponse["sha"].s()]); // salt is received in
                                                  // hexadecimal format, salt
                                                  // sizes is in bytes
}

/**
 * @test Test the correctness of the /srp/register/init endpoint of the server.
 * @brief Ensures that the /srp/register/init endpoint is working as expected.
 * The scenario tested is the following one:
 * - a valid user ID is provided by a given client;
 * - the request group ID provided is equal to the minimum required by the
 * server;
 * - the expected result should be a group ID at least with the minimum required
 * value defined at the server level.
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    GetGroupsDataEndpoint_WithValidClientIdRequestedGroupIdEqualsDefaultValue_ShouldMatchReference) {
  const unsigned int minGroupIdExpected{1}, maxGroupIdExpected{7};
  const unsigned int defaultGroupId = _server->getDefaultGroupId();
  EXPECT_GE(defaultGroupId, minGroupIdExpected);
  EXPECT_LE(defaultGroupId, maxGroupIdExpected);
  const unsigned int providedGroupId{defaultGroupId};
  std::string requestBody = fmt::format(
      R"({{
        "clientId": "{}",
        "requestedGroup": {}
    }})",
      _mapUsers[_clientId1]->getClientId(), providedGroupId);
  cpr::Response response =
      cpr::Post(cpr::Url{std::string("http://localhost:") +
                         std::to_string(_server->getTestPort()) +
                         std::string("/srp/register/init")},
                cpr::Header{{"Content-Type", "application/json"}},
                cpr::Body{requestBody});
  EXPECT_EQ(response.status_code, 201);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  const unsigned long int extractedGroupId{jsonResponse["groupId"].u()};
  ASSERT_TRUE(jsonResponse);
  EXPECT_EQ(jsonResponse["clientId"].s(), _mapUsers[_clientId1]->getClientId());
  EXPECT_EQ(extractedGroupId, providedGroupId);
  EXPECT_GE(extractedGroupId, minGroupIdExpected);
  EXPECT_LE(extractedGroupId, maxGroupIdExpected);
  EXPECT_EQ(jsonResponse["groupName"].s(),
            _srpParametersMap[extractedGroupId]._groupName);
  EXPECT_EQ(jsonResponse["primeN"].s(),
            _srpParametersMap[extractedGroupId]._nHex);
  EXPECT_EQ(jsonResponse["generatorG"].u(),
            _srpParametersMap[extractedGroupId]._g);
  EXPECT_EQ(jsonResponse["sha"].s(),
            _srpParametersMap[extractedGroupId]._hashName);
  EXPECT_GE(
      jsonResponse["salt"].s().size() * 2,
      _minSaltSizesMap[jsonResponse["sha"].s()]); // salt is received in
                                                  // hexadecimal format, salt
                                                  // sizes is in bytes
}

/**
 * @test Test the correctness of the /srp/register/init endpoint of the server.
 * @brief Ensures that the /srp/register/init endpoint is working as expected.
 * The scenario tested is the following one:
 * - a valid user ID is provided by a given client;
 * - the request group ID provided is greater then the minimum required by
 * the server;
 * - the expected result should be a group ID greater than the minimum required
 * value defined at the server level.
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    GetGroupsDataEndpoint_WithValidClientIdRequestedGroupIdGreaterThanDefaultValue_ShouldMatchReference) {
  const unsigned int minGroupIdExpected{1}, maxGroupIdExpected{7};
  const unsigned int defaultGroupId = _server->getDefaultGroupId();
  EXPECT_GE(defaultGroupId, minGroupIdExpected);
  EXPECT_LE(defaultGroupId, maxGroupIdExpected);
  const unsigned int providedGroupId{defaultGroupId + 1};
  std::string requestBody = fmt::format(
      R"({{
        "clientId": "{}",
        "requestedGroup": {}
    }})",
      _mapUsers[_clientId1]->getClientId(), providedGroupId);
  cpr::Response response =
      cpr::Post(cpr::Url{std::string("http://localhost:") +
                         std::to_string(_server->getTestPort()) +
                         std::string("/srp/register/init")},
                cpr::Header{{"Content-Type", "application/json"}},
                cpr::Body{requestBody});
  EXPECT_EQ(response.status_code, 201);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  const unsigned long int extractedGroupId{jsonResponse["groupId"].u()};
  ASSERT_TRUE(jsonResponse);
  EXPECT_EQ(jsonResponse["clientId"].s(), _mapUsers[_clientId1]->getClientId());
  EXPECT_GE(extractedGroupId, defaultGroupId);
  EXPECT_GE(extractedGroupId, minGroupIdExpected);
  EXPECT_LE(extractedGroupId, maxGroupIdExpected);
  EXPECT_EQ(jsonResponse["groupName"].s(),
            _srpParametersMap[extractedGroupId]._groupName);
  EXPECT_EQ(jsonResponse["primeN"].s(),
            _srpParametersMap[extractedGroupId]._nHex);
  EXPECT_EQ(jsonResponse["generatorG"].u(),
            _srpParametersMap[extractedGroupId]._g);
  EXPECT_EQ(jsonResponse["sha"].s(),
            _srpParametersMap[extractedGroupId]._hashName);
  EXPECT_GE(
      jsonResponse["salt"].s().size() * 2,
      _minSaltSizesMap[jsonResponse["sha"].s()]); // salt is received in
                                                  // hexadecimal format, salt
                                                  // sizes is in bytes
}

/**
 * @test Test the correctness of the /srp/register/init endpoint of the server.
 * @brief Ensures that the /srp/register/init endpoint is working as expected.
 * The scenario tested is the following one:
 * - a valid user ID is provided by a given client;
 * - the request group ID provided is less than the minimum group id that
 * exists;
 * - the expected result should be a group ID equals to the minimum required
 * value defined at the server level.
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    GetGroupsDataEndpoint_WithValidClientIdRequestedGroupIdInvalid_ShouldMatchReference) {
  const unsigned int minGroupIdExpected{1}, maxGroupIdExpected{7};
  const unsigned int defaultGroupId = _server->getDefaultGroupId();
  EXPECT_GE(defaultGroupId, minGroupIdExpected);
  EXPECT_LE(defaultGroupId, maxGroupIdExpected);
  const unsigned int providedInvalidGroupId{0};
  std::string requestBody = fmt::format(
      R"({{
        "clientId": "{}",
        "requestedGroup": {}
    }})",
      _mapUsers[_clientId1]->getClientId(), providedInvalidGroupId);
  cpr::Response response =
      cpr::Post(cpr::Url{std::string("http://localhost:") +
                         std::to_string(_server->getTestPort()) +
                         std::string("/srp/register/init")},
                cpr::Header{{"Content-Type", "application/json"}},
                cpr::Body{requestBody});
  EXPECT_EQ(response.status_code, 201);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  const unsigned long int extractedGroupId{jsonResponse["groupId"].u()};
  ASSERT_TRUE(jsonResponse);
  EXPECT_EQ(jsonResponse["clientId"].s(), _mapUsers[_clientId1]->getClientId());
  EXPECT_EQ(extractedGroupId, defaultGroupId);
  EXPECT_GE(extractedGroupId, minGroupIdExpected);
  EXPECT_LE(extractedGroupId, maxGroupIdExpected);
  EXPECT_EQ(jsonResponse["groupName"].s(),
            _srpParametersMap[extractedGroupId]._groupName);
  EXPECT_EQ(jsonResponse["primeN"].s(),
            _srpParametersMap[extractedGroupId]._nHex);
  EXPECT_EQ(jsonResponse["generatorG"].u(),
            _srpParametersMap[extractedGroupId]._g);
  EXPECT_EQ(jsonResponse["sha"].s(),
            _srpParametersMap[extractedGroupId]._hashName);
  EXPECT_GE(
      jsonResponse["salt"].s().size() * 2,
      _minSaltSizesMap[jsonResponse["sha"].s()]); // salt is received in
                                                  // hexadecimal format, salt
                                                  // sizes is in bytes
}

/**
 * @test Test the correctness of the /srp/register/init endpoint of the server.
 * @brief Ensures that the /srp/register/init endpoint is working as expected.
 * The scenario tested is the following one:
 * - only an invalid user ID is provided by a given client;
 * - the expected result should be a 400 error code with error message ending in
 * "ClientId is null"
 */
TEST_F(SecureRemotePasswordProtocolTest,
       GetGroupsDataEndpoint_WithInvalidClientId_ShouldThrowAnError) {
  const std::string invalidClientId{};
  std::string requestBody = fmt::format(
      R"({{
        "clientId": "{}"
    }})",
      invalidClientId);
  cpr::Response response =
      cpr::Post(cpr::Url{std::string("http://localhost:") +
                         std::to_string(_server->getTestPort()) +
                         std::string("/srp/register/init")},
                cpr::Header{{"Content-Type", "application/json"}},
                cpr::Body{requestBody});
  EXPECT_EQ(response.status_code, 400);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  EXPECT_THAT(std::string(jsonResponse["message"].s()),
              ::testing::EndsWith("ClientId is null"));
}

/**
 * @test Test the correctness of the /srp/register/init endpoint of the server.
 * @brief Ensures that the /srp/register/init endpoint is working as expected.
 * The scenario tested is the following one:
 * - a bad request, without any client id provided;
 * - the expected result should be a 404 error code with error message ending in
 * "ClientId not found"
 */
TEST_F(SecureRemotePasswordProtocolTest,
       GetGroupsDataEndpoint_WithBadRequest_ShouldThrowAnError) {
  const std::string invalidClientId{};
  std::string requestBody = fmt::format(
      R"({{
    }})",
      invalidClientId);
  cpr::Response response =
      cpr::Post(cpr::Url{std::string("http://localhost:") +
                         std::to_string(_server->getTestPort()) +
                         std::string("/srp/register/init")},
                cpr::Header{{"Content-Type", "application/json"}},
                cpr::Body{requestBody});
  EXPECT_EQ(response.status_code, 404);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  EXPECT_THAT(std::string(jsonResponse["message"].s()),
              ::testing::EndsWith("key 'clientId' not found"));
}

/**
 * @test Test the correctness of the registration method at the client side.
 * @brief Test the correctness of the registration method at the client side.
 * Scenario:
 * - valid portServerNumber provided;
 * - no groupId provided, should use the default one.
 * Should succeed in the registration step.
 */
TEST_F(SecureRemotePasswordProtocolTest,
       Registration_WithValidPortNumberAndDefaultGroupId_ShouldReturnSuccess) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  // Check that the users array contains the expected username
  bool found = false;
  for (const auto &user : jsonResponse["users"]) {
    if (user.s() == _clientId1) {
      found = true;
      break;
    }
  }
  EXPECT_FALSE(found) << "Expected username '" << _clientId1
                      << "' to not be found in registered users list in the "
                         "beginning of the test.";
  const bool registrationReturnValue{_mapUsers[_clientId1]->registration(
      _mapUsers[_clientId1]->getTestPort())};
  EXPECT_TRUE(registrationReturnValue);
  response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  // Check that the users array contains the expected username
  found = false;
  for (const auto &user : jsonResponse["users"]) {
    if (user.s() == _clientId1) {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Expected username '" << _clientId1
                     << "' not found in registered users list.";
}

/**
 * @test Test the correctness of the registration method at the client side.
 * @brief Test the correctness of the registration method at the client side.
 * Scenario:
 * - valid portServerNumber provided;
 * - groupId provided, invalid one, bellow minimum bound.
 * Should succeed in the registration step.
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    Registration_WithValidPortNumberAndInvalidGroupIdLessThanMinimum_ShouldReturnSuccess) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  // Check that the users array contains the expected username
  bool found = false;
  for (const auto &user : jsonResponse["users"]) {
    if (user.s() == _clientId1) {
      found = true;
      break;
    }
  }
  EXPECT_FALSE(found) << "Expected username '" << _clientId1
                      << "' to not be found in registered users list in the "
                         "beginning of the test.";
  const unsigned int groupId{_srpParametersMap.rbegin()->first - 1};
  const bool registrationReturnValue{_mapUsers[_clientId1]->registration(
      _mapUsers[_clientId1]->getTestPort(), groupId)};
  EXPECT_TRUE(registrationReturnValue);
  response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  // Check that the users array contains the expected username
  found = false;
  for (const auto &user : jsonResponse["users"]) {
    if (user.s() == _clientId1) {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Expected username '" << _clientId1
                     << "' not found in registered users list.";
}

/**
 * @test Test the correctness of the registration method at the client side.
 * @brief Test the correctness of the registration method at the client side.
 * Scenario:
 * - valid portServerNumber provided;
 * - groupId provided, valid one.
 * Should succeed in the registration step.
 */
TEST_F(SecureRemotePasswordProtocolTest,
       Registration_WithValidPortNumberAndValidGroupId_ShouldReturnSuccess) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  // Check that the users array contains the expected username
  bool found = false;
  for (const auto &user : jsonResponse["users"]) {
    if (user.s() == _clientId1) {
      found = true;
      break;
    }
  }
  EXPECT_FALSE(found) << "Expected username '" << _clientId1
                      << "' to not be found in registered users list in the "
                         "beginning of the test.";
  const unsigned int groupId{_srpParametersMap.begin()->first};
  const bool registrationReturnValue{_mapUsers[_clientId1]->registration(
      _mapUsers[_clientId1]->getTestPort(), groupId)};
  EXPECT_TRUE(registrationReturnValue);
  response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  // Check that the users array contains the expected username
  found = false;
  for (const auto &user : jsonResponse["users"]) {
    if (user.s() == _clientId1) {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Expected username '" << _clientId1
                     << "' not found in registered users list.";
}

/**
 * @test Test the correctness of the registration method at the client side.
 * @brief Test the correctness of the registration method at the client side.
 * Scenario:
 * - valid portServerNumber provided;
 * - groupId provided, invalid one, above maximum bound.
 * Should succeed in the registration step.
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    Registration_WithValidPortNumberAndInvalidGroupIdGreaterThanMaximum_ShouldReturnSuccess) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  // Check that the users array contains the expected username
  bool found = false;
  for (const auto &user : jsonResponse["users"]) {
    if (user.s() == _clientId1) {
      found = true;
      break;
    }
  }
  EXPECT_FALSE(found) << "Expected username '" << _clientId1
                      << "' to not be found in registered users list in the "
                         "beginning of the test.";
  const unsigned int groupId{_srpParametersMap.rbegin()->first + 1};
  const bool registrationReturnValue{_mapUsers[_clientId1]->registration(
      _mapUsers[_clientId1]->getTestPort(), groupId)};
  EXPECT_TRUE(registrationReturnValue);
  response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  // Check that the users array contains the expected username
  found = false;
  for (const auto &user : jsonResponse["users"]) {
    if (user.s() == _clientId1) {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Expected username '" << _clientId1
                     << "' not found in registered users list.";
}

/**
 * @test Test the correctness of the registration method at the client side.
 * @brief Test the correctness of the registration method at the client side.
 * Scenario:
 * - invalid portServerNumber provided;
 * Should fail in the registration step.
 */
TEST_F(SecureRemotePasswordProtocolTest,
       Registration_WithInvalidPortNumber_ShouldReturnAnError) {
  const unsigned int invalidPortNumber{80};
  const bool registrationReturnValue{
      _mapUsers[_clientId1]->registration(invalidPortNumber)};
  EXPECT_FALSE(registrationReturnValue);
}
