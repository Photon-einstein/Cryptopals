#!/bin/bash

# include files
clang-format -i ./include/Client.hpp ./include/Diffie_Hellman.hpp ./include/MessageExtractionFacility.hpp ./include/Server.hpp

# src files
clang-format -i ./src/Client.cpp ./src/Diffie_Hellman.cpp ./src/MessageExtractionFacility.cpp ./src/Server.cpp ./src/run_client.cpp ./src/run_server.cpp

# test files
