#!/bin/bash
n=$(ls "./build" | wc -l)
if (( $n > 0 ));
then
    rm -r ./build/*
fi

g++ -c ./src/Server.cpp -o ./build/Server.o
g++ -c ./src/MT19937.cpp -o ./build/MT19937.o
g++ -Wall -std=c++17 ./src/cryptopals_set_3_problem_21.cpp ./build/Server.o ./build/MT19937.o -o ./build/cryptopals_set_3_problem_21.exe -lcrypto
./build/cryptopals_set_3_problem_21.exe
