#!/bin/bash

# include files
clang-format -i ./include/Attacker.hpp ./include/HMAC_SHA1.hpp ./include/HMAC.hpp ./include/MessageExtractionFacility.hpp ./include/Server.hpp ./include/SHA.hpp ./include/SHA1.hpp
# src files
clang-format -i ./src/Attacker.cpp ./src/HMAC_SHA1.cpp ./src/HMAC.cpp ./src/MessageExtractionFacility.cpp ./src/SHA.cpp ./src/SHA1.cpp ./src/Server.cpp ./src/run_attacker.cpp ./src/run_server.cpp
# test files
clang-format -i ./tests/test_hmac_sha1.cpp ./tests/test_server.cpp ./tests/test_sha1.cpp