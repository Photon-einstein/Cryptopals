### To compile and run the program if the problem has a CMakeLists.txt file:

Create a build directory and move into it

```bash
mkdir build
cd build
```

Configure the poject with CMake

```bash
cmake ..
```

Build the executable:

```bash
make
```

Run the server side:

```bash
./build/server_main
```

Run the attacker side:

```bash
./build/attacker_main
```

### Demonstration of the project

In this video it is shown the last 5 minutes of the attack performed against  
a server with a timing leak of 5ms in the compare function

[![Watch the video with the solution demo](http://img.youtube.com/vi/6iz8u3MrVDQ/0.jpg)](https://www.youtube.com/watch?v=6iz8u3MrVDQ)