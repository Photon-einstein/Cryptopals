#ifndef MT19937_H
#define MT19937_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctime>
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
#include <memory>

const bool debugFlag = true;

class MT19937 {
public:
    /* Create a length n array to store the state of the generator */
    MT19937(std::time_t seed);

    ~MT19937();

    /* initialize the generator from the seed */
    void seedMt(int seed);

    /* Extract a tempered value based on MT[index] calling twist() every n numbers */
    unsigned int extractNumber();


private:
    /* Generate the next n values from the series x_i */
    void twist();

private:
    const unsigned int _w = 32;
    static const unsigned int _n = 624;
    const unsigned int _m = 397;
    const unsigned int _r = 31;
    const unsigned int _a = 0x9908b0dfUL;
    const unsigned int _u = 11;
    const unsigned int _d = 0x7fffffffUL;
    const unsigned int _s = 7;
    const unsigned int _b = 0x9d2c5680UL;
    const unsigned int _t = 15;
    const unsigned int _c = 0xefc60000UL;
    const unsigned int _l = 18;
    const unsigned int _f = 1812433253;

    std::uint32_t _upperMask;
    std::uint32_t _lowerMask;

    std::array<std::uint32_t, _n> _mt;
    std::size_t _index;

};

#endif
