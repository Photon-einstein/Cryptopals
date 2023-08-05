#!/bin/bash
n=$(ls "./build" | wc -l)
if (( $n > 0 ));
then
    rm -r ./build/*
fi

g++ -c -Wextra ./src/Server.cpp -o ./build/Server.o
g++ -c -Wextra ./src/Attacker.cpp -o ./build/Attacker.o
g++ -c -Wextra ./src/Function.cpp -o ./build/Function.o
g++ -c -Wextra ./src/AesEcbMachine.cpp -o ./build/AesEcbMachine.o
g++ -c -Wextra ./src/AesCtrMachine.cpp -o ./build/AesCtrMachine.o
g++ -Wextra -std=c++17 ./src/cryptopals_set_4_problem_25.cpp ./build/Server.o ./build/Attacker.o ./build/Function.o ./build/AesEcbMachine.o ./build/AesCtrMachine.o -o ./build/cryptopals_set_4_problem_25.exe -lcrypto
./build/cryptopals_set_4_problem_25.exe
