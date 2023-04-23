#!/bin/bash
n=$(ls "./build" | wc -l)
if (( $n > 0 ));
then
    rm -r ./build/*
fi

g++ -c ./src/Function.cpp -o ./build/Function.o
g++ -c ./src/Pad.cpp -o ./build/Pad.o
g++ -c ./src/PadPKCS_7.cpp -o ./build/PadPKCS_7.o
g++ -c ./src/Server.cpp -o ./build/Server.o
g++ -Wall -std=c++17 ./src/cryptopals_set_2_problem_16.cpp  ./build/Function.o ./build/Pad.o ./build/PadPKCS_7.o ./build/Server.o -o ./build/cryptopals_set_2_problem_16.exe -lcrypto
./build/cryptopals_set_2_problem_16.exe
