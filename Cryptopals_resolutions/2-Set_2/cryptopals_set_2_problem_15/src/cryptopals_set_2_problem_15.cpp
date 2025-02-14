#include <algorithm> // for copy() and assign()
#include <assert.h>
#include <bits/stdc++.h>
#include <cctype>
#include <cstddef>
#include <ctype.h>
#include <fstream>
#include <iostream>
#include <iterator> // for back_inserter
#include <map>
#include <math.h>
#include <memory>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <time.h>
#include <unordered_map>
#include <vector>

#include "./../include/Function.h"
#include "./../include/Pad.h"
#include "./../include/PadPKCS_7.h"
#include "./../include/Test.h"

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::shared_ptr<Pad> p = std::make_shared<PadPKCS_7>(blockSize);
  Test t = Test(p);
  std::vector<std::string> v;
  int i;
  v.push_back("ICE ICE BABY\x04\x04\x04\x04");
  v.push_back("ICE ICE BABY\x05\x05\x05\x05");
  v.push_back("ICE ICE BABY\x01\x02\x03\x04");
  for (i = 0; i < (int)v.size(); ++i) {
    t.addTest(v[i]);
  }
  t.runTests();
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
