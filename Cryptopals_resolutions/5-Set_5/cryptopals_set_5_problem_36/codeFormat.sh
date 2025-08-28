#!/bin/bash

# include files
clang-format -i ./include/Client.hpp ./include/EncryptionUtility.hpp ./include/MessageExtractionFacility.hpp ./include/SecureRemotePassword.hpp ./include/Server.hpp ./include/SrpParametersLoader.hpp ./include/SessionData.hpp

# src files
clang-format -i ./src/Client.cpp ./src/EncryptionUtility.cpp ./src/MessageExtractionFacility.cpp ./src/SecureRemotePassword.cpp ./src/Server.cpp ./src/SessionData.cpp ./src/SrpParametersLoader.cpp ./src/runClient1.cpp ./src/runServer.cpp

# test files
clang-format -i ./tests/test_Client.cpp ./tests/test_SHA256.cpp ./tests/test_SHA384.cpp ./tests/test_SHA512.cpp ./tests/test_SecureRemotePasswordProtocol.cpp ./tests/test_Server.cpp ./tests/test_SessionData.cpp ./tests/test_srpParametersLoader.cpp
