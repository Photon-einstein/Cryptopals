#!/bin/bash
n=$(ls "./build" | wc -l)
if (( $n > 0 ));
then
    rm -r ./build/*
fi

g++ -c ./src/Function.cpp -o ./build/Function.o
g++ -c ./src/Server.cpp -o ./build/Server.o
g++ -c ./src/Attacker.cpp -o ./build/Attacker.o
g++ -Wall -std=c++17 ./src/cryptopals_set_3_problem_19.cpp  ./build/Function.o ./build/Server.o ./build/Attacker.o -o ./build/cryptopals_set_3_problem_19.exe -lcrypto
./build/cryptopals_set_3_problem_19.exe
