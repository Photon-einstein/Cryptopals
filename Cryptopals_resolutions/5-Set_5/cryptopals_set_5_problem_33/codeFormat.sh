#!/bin/bash

# include files
clang-format -i ./include/Client.hpp ./include/DhParametersLoader.hpp  ./include/DiffieHellman.hpp ./include/EncryptionUtility.hpp ./include/MessageExtractionFacility.hpp ./include/Server.hpp ./include/SessionData.hpp

# src files
clang-format -i ./src/Client.cpp ./src/DhParametersLoader.cpp ./src/DiffieHellman.cpp ./src/EncryptionUtility.cpp ./src/MessageExtractionFacility.cpp ./src/Server.cpp ./src/runClient1.cpp ./src/runClient2.cpp ./src/runClient3.cpp ./src/runServer.cpp

# test files
clang-format -i ./tests/test_dhParametersLoader.cpp ./tests/test_diffieHellman.cpp ./tests/test_diffieHellmanProtocol.cpp