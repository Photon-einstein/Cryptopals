#!/bin/bash
rm ./build/*
g++ -c ./src/Function.cpp -o ./build/Function.o
g++ -c ./src/RandomPrefixWorker.cpp -o ./build/RandomPrefixWorker.o
g++ -Wall -std=c++17 ./src/cryptopals_set_2_problem_14.cpp  ./build/Function.o ./build/RandomPrefixWorker.o -o ./build/cryptopals_set_2_problem_14.o -lcrypto
./build/cryptopals_set_2_problem_14.o
