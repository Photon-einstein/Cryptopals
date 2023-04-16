#include <fstream>
#include <sstream>
#include <cmath>
#include <iostream>
#include <algorithm>
#include <bits/stdc++.h>

#include "./../include/Function.h"

/* this function makes the conversion from a string into a vector of bytes,
in the end it just returns*/
void Function::convertStringToVectorBytes(const std::string &s, std::vector<unsigned char> &v) {
  int i, size = s.size();
  v.clear();
  for (i = 0; i < size; ++i) {
    v.emplace_back(s[i]);
  }
  return;
}
/******************************************************************************/
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
