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
#include <memory>
#include <sstream>
#include <cmath>
#include <stdexcept>
#include <climits>

#include "./../include/Function.h"

/* this function makes the fulling of the string s based on the content of the
vector v */
void Function::convertVectorBytesToString(const std::vector<unsigned char> &v, std::string &s) {
  int i, size = v.size();
  s.clear();
  for (i = 0; i < size; ++i) {
    s+=v[i];
  }
  return;
}
/******************************************************************************/
