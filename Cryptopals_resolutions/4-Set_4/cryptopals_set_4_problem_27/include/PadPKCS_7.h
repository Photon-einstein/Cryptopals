#ifndef PADPKCS_7_H
#define PADPKCS_7_H

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

#include "./../include/Pad.h"

class PadPKCS_7 : public Pad {
public:
    /* constructor / destructor*/
    PadPKCS_7(int blockSize);
    ~PadPKCS_7();

    /* public methods */
    
    /* this function makes the padding using PKCS#7 format, in the end it will return
    the padding result by reference in the v vector and by value true if all ok or
    false otherwise */
    virtual bool pad(std::vector<unsigned char> &v);

    /* this function makes the unpadding using PKCS#7 format, in the end it will return
    the unpadding result by reference in the v vector and by value true if all ok or
    false otherwise */
    virtual bool unpad(std::vector<unsigned char> &v);

    /* this function does the check of the padding PadPKCS_7, in the end it
    returns true if the padding is ok or throws and exception if the padding is
    not ok */
    virtual bool testPadding(std::vector<unsigned char> &v);

private:

};

#endif
