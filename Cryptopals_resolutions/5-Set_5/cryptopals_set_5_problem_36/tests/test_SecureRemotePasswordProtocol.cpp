#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <fmt/core.h>
#include <string>
#include <vector>

#include "../include/Client.hpp"
#include "../include/EncryptionUtility.hpp"
#include "../include/SecureRemotePassword.hpp"
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
        MyCryptoLibrary::SecureRemotePassword::
            getSrpParametersFilenameLocation());
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
  cpr::Response response = cpr::Get(cpr::Url{
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
 * - the request group ID provided is less than the minimum group ID that
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
 * - a bad request, without any client ID provided;
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
 *
 * The scenario should succeed in the registration step.
 */
TEST_F(SecureRemotePasswordProtocolTest,
       Registration_WithValidPortNumberAndDefaultGroupId_ShouldReturnSuccess) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseBefore = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseBefore);
  // Check that the users array contains the expected username
  bool found = std::any_of(
      jsonResponseBefore["users"].begin(), jsonResponseBefore["users"].end(),
      [&](const auto &user) { return user.s() == _clientId1; });
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
  crow::json::rvalue jsonResponseAfter = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseAfter);
  // Check that the users array contains the expected username
  found = false;
  unsigned int counterTimesUser{0};
  for (const auto &user : jsonResponseAfter["users"]) {
    if (user.s() == _clientId1) {
      found = true;
      ++counterTimesUser;
    }
  }
  EXPECT_TRUE(found);
  EXPECT_EQ(counterTimesUser, 1)
      << "Expected username '" << _clientId1
      << "' to be found in registered users list only one time.";
}

/**
 * @test Test the correctness of the registration method at the client side.
 * @brief Test the correctness of the registration method at the client side.
 * Scenario:
 * - valid portServerNumber provided;
 * - groupId provided, invalid one, below minimum bound.
 *
 * The scenario should succeed in the registration step.
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    Registration_WithValidPortNumberAndInvalidGroupIdLessThanMinimum_ShouldReturnSuccess) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseBefore = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseBefore);
  // Check that the users array contains the expected username
  bool found = std::any_of(
      jsonResponseBefore["users"].begin(), jsonResponseBefore["users"].end(),
      [&](const auto &user) { return user.s() == _clientId1; });
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
  crow::json::rvalue jsonResponseAfter = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseAfter);
  // Check that the users array contains the expected username
  found = false;
  unsigned int counterTimesUser{0};
  for (const auto &user : jsonResponseAfter["users"]) {
    if (user.s() == _clientId1) {
      found = true;
      ++counterTimesUser;
    }
  }
  EXPECT_TRUE(found);
  EXPECT_EQ(counterTimesUser, 1)
      << "Expected username '" << _clientId1
      << "' to be found in registered users list only one time.";
}

/**
 * @test Test the correctness of the registration method at the client side.
 * @brief Test the correctness of the registration method at the client side.
 * Scenario:
 * - valid portServerNumber provided;
 * - groupId provided is a valid one.
 *
 * The scenario should succeed in the registration step.
 */
TEST_F(SecureRemotePasswordProtocolTest,
       Registration_WithValidPortNumberAndValidGroupId_ShouldReturnSuccess) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseBefore = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseBefore);
  // Check that the users array contains the expected username
  bool found = std::any_of(
      jsonResponseBefore["users"].begin(), jsonResponseBefore["users"].end(),
      [&](const auto &user) { return user.s() == _clientId1; });
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
  crow::json::rvalue jsonResponseAfter = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseAfter);
  // Check that the users array contains the expected username
  found = false;
  unsigned int counterTimesUser{0};
  for (const auto &user : jsonResponseAfter["users"]) {
    if (user.s() == _clientId1) {
      found = true;
      ++counterTimesUser;
    }
  }
  EXPECT_TRUE(found);
  EXPECT_EQ(counterTimesUser, 1)
      << "Expected username '" << _clientId1
      << "' to be found in registered users list only one time.";
}

/**
 * @test Test the correctness of the registration method at the client side.
 * @brief Test the correctness of the registration method at the client side.
 * Scenario:
 * - valid portServerNumber provided;
 * - groupId provided, invalid one, above maximum bound.
 *
 * The scenario should succeed in the registration step.
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    Registration_WithValidPortNumberAndInvalidGroupIdGreaterThanMaximum_ShouldReturnSuccess) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseBefore = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseBefore);
  // Check that the users array contains the expected username
  bool found = std::any_of(
      jsonResponseBefore["users"].begin(), jsonResponseBefore["users"].end(),
      [&](const auto &user) { return user.s() == _clientId1; });
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
  crow::json::rvalue jsonResponseAfter = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseAfter);
  // Check that the users array contains the expected username
  found = false;
  unsigned int counterTimesUser{0};
  for (const auto &user : jsonResponseAfter["users"]) {
    if (user.s() == _clientId1) {
      found = true;
      ++counterTimesUser;
    }
  }
  EXPECT_TRUE(found);
  EXPECT_EQ(counterTimesUser, 1)
      << "Expected username '" << _clientId1
      << "' to be found in registered users list only one time.";
}

/**
 * @test Test the correctness of the registration method at the client side.
 * @brief Test the correctness of the registration method at the client side.
 * Scenario:
 * - invalid portServerNumber provided;
 *
 * The scenario should fail in the registration step.
 */
TEST_F(SecureRemotePasswordProtocolTest,
       Registration_WithInvalidPortNumber_ShouldReturnAnError) {
  const unsigned int invalidPortNumber{80};
  const bool registrationReturnValue{
      _mapUsers[_clientId1]->registration(invalidPortNumber)};
  EXPECT_FALSE(registrationReturnValue);
}

/**
 * @test Test the correctness of the registration method at the client and
 * server side.
 * @brief Test the correctness of the registration method at the client and
 * server side.
 * Scenario:
 * - Client 1 completes the registration process with the server;
 * - Client 1 attempts the registration process with the server a second time,
 * it should return an error message, as it has already registered once;
 * - A post request with a registration/init is attempted for the same client
 * ID.
 *
 * The server is expected to return an error;
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    Registration_ClientAttemptsRegisterMoreThanOnceWithPostRequestAsWell_ShouldReturnErrorMessageAtTheSecondAttempt) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseBefore = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseBefore);
  // Check that the users array contains the expected username
  bool found = std::any_of(
      jsonResponseBefore["users"].begin(), jsonResponseBefore["users"].end(),
      [&](const auto &user) { return user.s() == _clientId1; });
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
  crow::json::rvalue jsonResponseAfter = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseAfter);
  // Check that the users array contains the expected username
  found = std::any_of(jsonResponseAfter["users"].begin(),
                      jsonResponseAfter["users"].end(),
                      [&](const auto &user) { return user.s() == _clientId1; });
  EXPECT_TRUE(found) << "Expected username '" << _clientId1
                     << "' to be found in registered users list in the "
                        "beginning of the test.";
  const bool registrationReturnValueSecondTime{
      _mapUsers[_clientId1]->registration(_mapUsers[_clientId1]->getTestPort(),
                                          groupId)};
  EXPECT_FALSE(registrationReturnValueSecondTime)
      << "Expected second registration of the username '" << _clientId1
      << "' to fail.";
  response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseAfterSecondRegister =
      crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseAfterSecondRegister);
  // Check that the users array contains the expected username
  found = false;
  unsigned int counterTimesUser{0};
  for (const auto &user : jsonResponseAfterSecondRegister["users"]) {
    if (user.s() == _clientId1) {
      found = true;
      ++counterTimesUser;
    }
  }
  EXPECT_TRUE(found);
  EXPECT_EQ(counterTimesUser, 1)
      << "Expected username '" << _clientId1
      << "' to be found in registered users list only one time.";
  std::string requestBody = fmt::format(
      R"({{
        "clientId": "{}"
    }})",
      _mapUsers[_clientId1]->getClientId());
  response = cpr::Post(cpr::Url{std::string("http://localhost:") +
                                std::to_string(_server->getTestPort()) +
                                std::string("/srp/register/init")},
                       cpr::Header{{"Content-Type", "application/json"}},
                       cpr::Body{requestBody});
  EXPECT_EQ(response.status_code, 409);
  crow::json::rvalue jsonResponse = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponse);
  EXPECT_THAT(std::string(jsonResponse["message"].s()),
              ::testing::EndsWith("Conflict, client is already registered"));
}

/**
 * @test Test the correctness of the registration method at the client and
 * server side.
 * @brief Test the correctness of the registration method at the client  and
 * server side. Scenario:
 * - Client 1 completes the registration process with the server;
 * - Client 1 attempts the registration process with the server a second time,
 * it should return an error message, as it has already registered once.
 * - A post request with a registration/init is attempted for the same client
 * ID.
 *
 * The server is expected to return an error;
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    Registration_SeveralClientsAttemptToRegister_ShouldBeRegisteredAtTheServerWithSuccess) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseBefore = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseBefore);
  // Check that the users array contains the expected username
  std::map<std::string, bool> mapTrackClientRegistrationsBefore;
  mapTrackClientRegistrationsBefore[_clientId1] = false;
  mapTrackClientRegistrationsBefore[_clientId2] = false;
  mapTrackClientRegistrationsBefore[_clientId3] = false;
  for (const auto &user : jsonResponseBefore["users"]) {
    if (mapTrackClientRegistrationsBefore.find(user.s()) !=
        mapTrackClientRegistrationsBefore.end()) {
      mapTrackClientRegistrationsBefore[user.s()] = true;
    }
  }
  EXPECT_FALSE(mapTrackClientRegistrationsBefore[_clientId1])
      << "Expected username '" << _clientId1
      << "' to not be found in registered users list in the "
         "beginning of the test.";
  EXPECT_FALSE(mapTrackClientRegistrationsBefore[_clientId2])
      << "Expected username '" << _clientId2
      << "' to not be found in registered users list in the "
         "beginning of the test.";
  EXPECT_FALSE(mapTrackClientRegistrationsBefore[_clientId3])
      << "Expected username '" << _clientId3
      << "' to not be found in registered users list in the "
         "beginning of the test.";
  // registration client 1
  const bool registrationReturnValue1{_mapUsers[_clientId1]->registration(
      _mapUsers[_clientId1]->getTestPort())};
  EXPECT_TRUE(registrationReturnValue1);
  // registration client 2
  const bool registrationReturnValue2{_mapUsers[_clientId2]->registration(
      _mapUsers[_clientId1]->getTestPort())};
  EXPECT_TRUE(registrationReturnValue2);
  // registration client 3
  const bool registrationReturnValue3{_mapUsers[_clientId3]->registration(
      _mapUsers[_clientId1]->getTestPort())};
  EXPECT_TRUE(registrationReturnValue3);
  // check the registration on the server side of all the clients
  response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseAfter = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseAfter);
  // Check that the users array contains the expected username
  std::map<std::string, unsigned int> mapTrackClientRegistrationsAfter;
  mapTrackClientRegistrationsAfter[_clientId1] = 0;
  mapTrackClientRegistrationsAfter[_clientId2] = 0;
  mapTrackClientRegistrationsAfter[_clientId3] = 0;
  for (const auto &user : jsonResponseAfter["users"]) {
    if (mapTrackClientRegistrationsAfter.find(user.s()) !=
        mapTrackClientRegistrationsAfter.end()) {
      ++mapTrackClientRegistrationsAfter[user.s()];
    }
  }
  EXPECT_EQ(mapTrackClientRegistrationsAfter[_clientId1], 1)
      << "Expected username '" << _clientId1
      << "' to be found in registered users list after the registration one "
         "time";
  EXPECT_EQ(mapTrackClientRegistrationsAfter[_clientId2], 1)
      << "Expected username '" << _clientId2
      << "' to be found in registered users list after the registration one "
         "time";
  EXPECT_EQ(mapTrackClientRegistrationsAfter[_clientId3], 1)
      << "Expected username '" << _clientId3
      << "' to be found in registered users list after the registration one "
         "time";
}

/**
 * @test Test the correctness of the entire SRP protocol.
 * @brief Test the correctness of the entire SRP protocol, namely,
 * the client attempts to register and then to perform an authentication.
 *  Scenario:
 * - Client 1 completes the registration process with the server;
 * - Client 1 attempts the authentication with the server.
 *
 * This scenario is expected to be successful without any error.
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    Authentication_OneClientsAttemptsToAuthenticate_ShouldBeAuthenticatedAtTheServerWithSuccess) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseBefore = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseBefore);
  // Check that the users array contains the expected username
  bool found = std::any_of(
      jsonResponseBefore["users"].begin(), jsonResponseBefore["users"].end(),
      [&](const auto &user) { return user.s() == _clientId1; });
  EXPECT_FALSE(found) << "Expected username '" << _clientId1
                      << "' to not be found in registered users list in the "
                         "beginning of the test.";
  // registration client 1
  const bool registrationReturnValue1{_mapUsers[_clientId1]->registration(
      _mapUsers[_clientId1]->getTestPort())};
  EXPECT_TRUE(registrationReturnValue1);
  // check the registration on the server side of all the clients
  response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseAfter = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseAfter);
  // Check that the users array contains the expected username
  unsigned int registrationClientCounter = std::count_if(
      jsonResponseAfter["users"].begin(), jsonResponseAfter["users"].end(),
      [&](const auto &user) { return user.s() == _clientId1; });
  ASSERT_EQ(registrationClientCounter, 1);
  // authentication client 1
  const bool authenticationReturnValue1{_mapUsers[_clientId1]->authentication(
      _mapUsers[_clientId1]->getTestPort())};
  EXPECT_TRUE(authenticationReturnValue1);
}

/**
 * @test Test the correctness of the entire SRP protocol.
 * @brief Test the correctness of the entire SRP protocol, namely,
 * several client attempt to register and then to perform an authentication.
 *  Scenario:
 * - Client 1, 2 and 3 complete the registration process with the server;
 * - Client 1, 2 and 3 attempts the authentication with the server.
 *
 * This scenario is expected to be successful without any error.
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    Authentication_SeveralClientsAttemptsToAuthenticate_ShouldBeAuthenticatedAtTheServerWithSuccess) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseBefore = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseBefore);
  // Check that the users array does not contain the expected username
  // before registration
  std::map<std::string, bool> mapTrackClientRegistrationsBefore;
  mapTrackClientRegistrationsBefore[_clientId1] = false;
  mapTrackClientRegistrationsBefore[_clientId2] = false;
  mapTrackClientRegistrationsBefore[_clientId3] = false;
  for (const auto &user : jsonResponseBefore["users"]) {
    if (mapTrackClientRegistrationsBefore.find(user.s()) !=
        mapTrackClientRegistrationsBefore.end()) {
      mapTrackClientRegistrationsBefore[user.s()] = true;
    }
  }
  EXPECT_FALSE(mapTrackClientRegistrationsBefore[_clientId1])
      << "Expected username '" << _clientId1
      << "' to not be found in registered users list in the "
         "beginning of the test.";
  EXPECT_FALSE(mapTrackClientRegistrationsBefore[_clientId2])
      << "Expected username '" << _clientId2
      << "' to not be found in registered users list in the "
         "beginning of the test.";
  EXPECT_FALSE(mapTrackClientRegistrationsBefore[_clientId3])
      << "Expected username '" << _clientId3
      << "' to not be found in registered users list in the "
         "beginning of the test.";
  // registration client 1
  const bool registrationReturnValue1{_mapUsers[_clientId1]->registration(
      _mapUsers[_clientId1]->getTestPort())};
  EXPECT_TRUE(registrationReturnValue1);
  // registration client 2
  const bool registrationReturnValue2{_mapUsers[_clientId2]->registration(
      _mapUsers[_clientId2]->getTestPort())};
  EXPECT_TRUE(registrationReturnValue2);
  // registration client 3
  const bool registrationReturnValue3{_mapUsers[_clientId3]->registration(
      _mapUsers[_clientId3]->getTestPort())};
  EXPECT_TRUE(registrationReturnValue3);
  // check the registration on the server side of all the clients
  response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseAfter = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseAfter);
  // Check that the users array contains the expected username
  std::map<std::string, unsigned int> mapTrackClientRegistrationsAfter;
  mapTrackClientRegistrationsAfter[_clientId1] = 0;
  mapTrackClientRegistrationsAfter[_clientId2] = 0;
  mapTrackClientRegistrationsAfter[_clientId3] = 0;
  for (const auto &user : jsonResponseAfter["users"]) {
    if (mapTrackClientRegistrationsAfter.find(user.s()) !=
        mapTrackClientRegistrationsAfter.end()) {
      ++mapTrackClientRegistrationsAfter[user.s()];
    }
  }
  EXPECT_EQ(mapTrackClientRegistrationsAfter[_clientId1], 1)
      << "Expected username '" << _clientId1
      << "' to be found in registered users list after the registration one "
         "time";
  EXPECT_EQ(mapTrackClientRegistrationsAfter[_clientId2], 1)
      << "Expected username '" << _clientId2
      << "' to be found in registered users list after the registration one "
         "time";
  EXPECT_EQ(mapTrackClientRegistrationsAfter[_clientId3], 1)
      << "Expected username '" << _clientId3
      << "' to be found in registered users list after the registration one "
         "time";
  // authentication client 1
  const bool authenticationReturnValue1{_mapUsers[_clientId1]->authentication(
      _mapUsers[_clientId1]->getTestPort())};
  EXPECT_TRUE(authenticationReturnValue1);
  // authentication client 2
  const bool authenticationReturnValue2{_mapUsers[_clientId2]->authentication(
      _mapUsers[_clientId2]->getTestPort())};
  EXPECT_TRUE(authenticationReturnValue2);
  // authentication client 3
  const bool authenticationReturnValue3{_mapUsers[_clientId3]->authentication(
      _mapUsers[_clientId3]->getTestPort())};
  EXPECT_TRUE(authenticationReturnValue3);
}

/**
 * @test Test the correctness of the entire SRP protocol, on a bad flow
 * scenario.
 * @brief Test the correctness of the entire SRP protocol, namely,
 * the client attempts to authenticate without having performed previous
 * registration. Scenario:
 * - Client 1 does not complete a registration.
 * - Client 1 attempts the authentication with the server.
 *
 * The scenario is expected to not have a successful authentication.
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    Authentication_OneClientsAttemptsToAuthenticateWithoutRegistration_ShouldReturnError) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseBefore = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseBefore);
  // Check that the users array does not contain the expected username
  // before registration
  bool found = false;
  for (const auto &user : jsonResponseBefore["users"]) {
    if (user.s() == _clientId1) {
      found = true;
    }
  }
  EXPECT_FALSE(found) << "Expected username '" << _clientId1
                      << "' to not be found in registered users list in the "
                         "beginning of the test.";
  // no registration client 1
  // authentication client 1
  const bool authenticationReturnValue1{_mapUsers[_clientId1]->authentication(
      _mapUsers[_clientId1]->getTestPort())};
  EXPECT_FALSE(authenticationReturnValue1);
}

/**
 * @test Test the correctness of the entire SRP protocol, on a bad flow
 * scenario.
 * @brief Test the correctness of the entire SRP protocol, namely,
 * the client attempts to authenticate without having performed previous
 * registration. Scenario:
 * - Client 1, 2 and 3 don't complete a registration.
 * - Client 1, 2 and 3 attempts the authentication with the server.
 *
 * The scenario is expected to not have a successful authentication at all
 * clients.
 */
TEST_F(
    SecureRemotePasswordProtocolTest,
    Authentication_ThreeClientsAttemptsToAuthenticateWithoutRegistration_ShouldReturnError) {
  auto response = cpr::Get(
      cpr::Url{"http://localhost:" + std::to_string(_server->getTestPort()) +
               std::string("/srp/registered/users")});
  EXPECT_EQ(response.status_code, 200);
  crow::json::rvalue jsonResponseBefore = crow::json::load(response.text);
  ASSERT_TRUE(jsonResponseBefore);
  // Check that the users array does not contain the expected username
  // before registration
  std::map<std::string, bool> mapTrackClientRegistrationsBefore;
  mapTrackClientRegistrationsBefore[_clientId1] = false;
  mapTrackClientRegistrationsBefore[_clientId2] = false;
  mapTrackClientRegistrationsBefore[_clientId3] = false;
  for (const auto &user : jsonResponseBefore["users"]) {
    if (mapTrackClientRegistrationsBefore.find(user.s()) !=
        mapTrackClientRegistrationsBefore.end()) {
      mapTrackClientRegistrationsBefore[user.s()] = true;
    }
  }
  EXPECT_FALSE(mapTrackClientRegistrationsBefore[_clientId1])
      << "Expected username '" << _clientId1
      << "' to not be found in registered users list in the "
         "beginning of the test.";
  EXPECT_FALSE(mapTrackClientRegistrationsBefore[_clientId2])
      << "Expected username '" << _clientId2
      << "' to not be found in registered users list in the "
         "beginning of the test.";
  EXPECT_FALSE(mapTrackClientRegistrationsBefore[_clientId3])
      << "Expected username '" << _clientId3
      << "' to not be found in registered users list in the "
         "beginning of the test.";
  // no registration client 1, 2 and 3
  // authentication client 1
  const bool authenticationReturnValue1{_mapUsers[_clientId1]->authentication(
      _mapUsers[_clientId1]->getTestPort())};
  EXPECT_FALSE(authenticationReturnValue1);
  // authentication client 2
  const bool authenticationReturnValue2{_mapUsers[_clientId2]->authentication(
      _mapUsers[_clientId2]->getTestPort())};
  EXPECT_FALSE(authenticationReturnValue2);
  // authentication client 3
  const bool authenticationReturnValue3{_mapUsers[_clientId3]->authentication(
      _mapUsers[_clientId3]->getTestPort())};
  EXPECT_FALSE(authenticationReturnValue3);
}
