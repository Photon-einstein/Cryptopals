# Cryptopals

### Prerequisites
Before begin, ensure that you have the following installed:

* CMake (version 3.10 or later)
* A C++ compiler that supports C++17 (e.g., GCC, g++)
* OpenSSL (if the problem uses it)

### Intro
This repository contains my resolutions of the set of problems of the Cryptopals challenges.  
These challenges serve as a way for me to dive deep into the cryptography world.


### To compile and run the program if the problem has a bash script:
To test each program just compile and run using the following bash script in the command line:

```bash
bash cryptopals_set_<set_number>_problem_<problem_number>
```

### To compile and run the program if the problem has a CMakeLists.txt file:

Create a build directory and move into it

```bash
mkdir build
cd build
```

Configure the project with CMake

```bash
cmake ..
```

Build the executable:

```bash
make
```

Run the executable:

```bash
./build/cryptopals_set_<set_number>_problem_<problem_number>
```


### Example:
![Screenshot from 2023-04-11 00-00-41](https://user-images.githubusercontent.com/31144077/231015131-8d4f6e9b-bb12-4175-b113-296e174567b0.png)
