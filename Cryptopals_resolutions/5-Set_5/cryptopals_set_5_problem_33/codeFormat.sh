#!/bin/bash

# include files
clang-format -i ./include/Client.hpp ./include/DhParametersLoader.hpp  ./include/DiffieHellman.hpp ./include/MessageExtractionFacility.hpp ./include/Server.hpp

# src files
clang-format -i ./src/Client.cpp ./src/DhParametersLoader.cpp ./src/DiffieHellman.cpp ./src/MessageExtractionFacility.cpp ./src/Server.cpp ./src/runClient.cpp ./src/runServer.cpp

# test files
