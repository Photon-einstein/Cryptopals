#!/bin/bash

# include files
clang-format -i ./include/MessageExtractionFacility.hpp ./include/Server.hpp

# src files
clang-format -i ./src/MessageExtractionFacility.cpp ./src/Server.cpp ./src/run_server.cpp

# test files
