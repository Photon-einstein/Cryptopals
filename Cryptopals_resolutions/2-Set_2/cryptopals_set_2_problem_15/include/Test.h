#ifndef Test_H
#define Test_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <string>
#include <math.h>
#include <ctype.h>
#include <assert.h>
#include <vector>
#include <iostream>
#include <cstddef>
#include <unordered_map>
#include <bits/stdc++.h>
#include <cctype>
#include <fstream>
#include <random>
#include <map>
#include <algorithm> // for copy() and assign()
#include <iterator> // for back_inserter
#include <string.h>
#include <string>
#include <memory>

#include "./../include/Pad.h"

class Test {
public:
    /* constructor / destructor*/
    Test(std::shared_ptr<Pad> pad);
    ~Test();

    /* setter */
    bool addTest(const std::string& s);

    /* this function runs the tests on the string stored at the vector _strings,
    in the end it will return true if the tests passed or false otherwise */
    bool runTests();

    /* this function does the print of the vector of chars, in the end it just
    returns */
    void printVector(const std::vector<unsigned char> &v);

private:
  std::vector<std::string> _strings;
  std::shared_ptr<Pad> _pad=nullptr;
};

#endif
