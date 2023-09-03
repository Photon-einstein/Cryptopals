#!/bin/bash
n=$(ls "./build" | wc -l)
if (( $n > 0 ));
then
    rm -r ./build/*
fi

g++ -c -Wextra ./src/Server.cpp -o ./build/Server.o
g++ -c -Wextra ./src/Attacker.cpp -o ./build/Attacker.o
g++ -c -Wextra ./src/Function.cpp -o ./build/Function.o
g++ -c -Wextra ./src/AesCbcMachine.cpp -o ./build/AesCbcMachine.o
g++ -c -Wextra ./src/Pad.cpp -o ./build/Pad.o
g++ -c -Wextra ./src/PadPKCS_7.cpp -o ./build/padPKCS_7.o
g++ -Wextra -std=c++17 ./src/cryptopals_set_4_problem_27.cpp ./build/Server.o ./build/Attacker.o ./build/Function.o ./build/AesCbcMachine.o ./build/Pad.o ./build/padPKCS_7.o -o ./build/cryptopals_set_4_problem_27.exe -lcrypto
./build/cryptopals_set_4_problem_27.exe
