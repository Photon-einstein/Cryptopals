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

// To compile: $ g++ -Wall -std=c++17 cryptopals_set_2_problem_13.cpp -o cryptopals_set_2_problem_13 -lcrypto

const unsigned int blockSize = 16; /* AES block size: 16 bytes = 128 bits */
const bool debugFlag = true, debugFlagExtreme = false;

typedef struct {
  std::string property;
  std::string value;
} jsonData;

/* this function makes the conversion of the string s into json format, updating
the map m, in the end it will return true if all went ok or false otherwise */
bool parseRoutineToJsonFormat(const std::string &s, std::vector<jsonData> &v);

/* this function makes the print of the json struture in the map m, in the end
returns true if all ok or false otherwise */
bool printJsonFormat(const std::string &structuredCookie, std::vector<jsonData> &v);

/* this function makes the encoding of a user email, this encoder does not allow
the characters '&' and '=' in that email so it will escape that characters,
it will return the encoded string by reference and if all went ok it will return
true if all ok or false otherwise */
bool profileEncoder(const std::string &email, std::string &encodedStringOutput);

/* this function makes the random filling of a key of size = blockSize, in the
end it returns true if all ok or false otherwise */
bool keyFilling(const int blockSize, std::string &key);

int main (void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */
  std::string structuredCookie = "foo=bar&baz=qux&zap=zazzle";
  std::vector<jsonData> v;
  bool b;
  std::string nastyEmail = "foo@bar.com&role=admin", encodedStringOutput="";
  std::string key;
  unsigned char *keyV;
  unsigned char *iv;
  int i;
  /*step 1: test parse routine */
  b = parseRoutineToJsonFormat(structuredCookie, v);
  if (b == false) {
    perror("There was a problem in the function 'parseRoutineToJsonFormat'.");
    exit(1);
  }
  b = printJsonFormat(structuredCookie, v);
  if (b == false) {
    perror("There was a problem in the function 'printJsonFormat'.");
    exit(1);
  }
  /* step 2: encode a user profile */
  b = profileEncoder(nastyEmail, encodedStringOutput);
  if (b == false) {
    std::cout<<"There was a problem in the function 'profileEncoder'.";
    exit(1);
  }
  std::cout<<"\nEncoded email='"<<nastyEmail<<"' with role user as: '"<<encodedStringOutput<<"'."<<std::endl;
  /* step 3: key generation */
  b = keyFilling(blockSize, key);
  if (b == false) {
    perror("\nThere was an error in the function 'keyFilling'.");
    exit(1);
  }
  /* step 4: prepare keyV and iv for later on do the
  encrypt: plaintext || unknown-string with random key in the next step */
  keyV = (unsigned char *) calloc(2*blockSize+1, sizeof(unsigned char));
  iv = (unsigned char *) calloc(2*blockSize+1, sizeof(unsigned char));
  if (keyV == nullptr || iv == nullptr) {
    perror("There was a problem in the memory allocation.");
    exit(1);
  }
  for (i = 0; i < (int)key.size(); ++i) {
    keyV[i] = key[i];
  }
  std::cout<<"To be continued :)"<<std::endl;
  /* free memory */
  free(keyV);
  free(iv);
  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/
/* this function makes the conversion of the string s into json format, updating
the map m, in the end it will return true if all went ok or false otherwise */
bool parseRoutineToJsonFormat(const std::string &s, std::vector<jsonData> &v) {
  if (s.size() == 0) {
    return false;
  }
  std::stringstream ss1(s);
  char del1 = '&', del2 = '=';
  std::string word, aux="";
  std::vector<std::string> param;
  int i;
  jsonData data;
  for(i = 0; i < 2; ++i) {
    param.push_back(aux);
  }
  while (ss1.eof() == false) {
     getline(ss1, word, del1);
     std::stringstream ss2(word);
     data.property.clear();
     data.value.clear();
     for(i = 0; i < 2; ++i) {
       param[i].clear();
       if(ss2.eof() == true) {
         return false;
       }
       getline(ss2, param[i], del2);
     }
    /* map update */
    if (param[0].size() == 0 || param[1].size() == 1) {
      return false;
    }
    data.property = param[0];
    data.value = param[1];
    v.push_back(data);
  }
  /* if it reaches here then all was ok */
  return true;
}
/******************************************************************************/
/* this function makes the print of the json struture in the map m, in the end
returns true if all ok or false otherwise */
bool printJsonFormat(const std::string &structuredCookie, std::vector<jsonData> &v) {
  if (v.size() == 0) {
    return false;
  }
  int i, size = v.size();
  std::cout<<"Structured cookie '"<<structuredCookie<<"' converted to json format as:"<<std::endl;
  for(i = 0; i < size; ++i) {
    if(v[i].property.size() == 0 || v[i].value.size() == 0) {
      return false;
    }
    if (i == 0) {
      std::cout<<"{"<<std::endl;
      std::cout<<"\t"<<v[i].property<<": '"<<v[i].value<<"'";
    } else {
      std::cout<<",\n\t"<<v[i].property<<": '"<<v[i].value<<"'";
    }
  }
  std::cout<<"\n}"<<std::endl;
  return true;
}
/******************************************************************************/
/* this function makes the encoding of a user email, this encoder does not allow
the characters '&' and '=' in that email so it will escape that characters,
it will return the encoded string by reference and if all went ok it will return
true if all ok or false otherwise */
bool profileEncoder(const std::string &email, std::string &encodedStringOutput) {
  if (email.size() == 0) {
    return false;
  }
  std::random_device rd;   // non-deterministic generator
  std::mt19937 gen(rd());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist(0,255); // distribute results between 0 and 255 inclusive
  std::string emailAux, del="\\";
  int i, size = email.size();
  /* string sanitization, RFC 5322 to validate email, not done here */
  for(i = 0; i < size; ++i) {
    if (email[i] != '&' && email[i] != '=') {
      emailAux+=email[i];
    } else {
      emailAux+=del+email[i];
    }
  }
  if (emailAux.size() == 0) {
    return false;
  }
  /* encode string */
  encodedStringOutput.clear();
  encodedStringOutput = "email="+emailAux+"&uid="+std::to_string(dist(gen))+"&role="+"user";
  return true;
}
/******************************************************************************/
/* this function makes the random filling of a key of size = blockSize, in the
end it returns true if all ok or false otherwise */
bool keyFilling(const int blockSize, std::string &key) {
  if (blockSize < 1) {
    return false;
  }
  key.clear();
  std::random_device rd;   // non-deterministic generator
  std::mt19937 gen(rd());  // to seed mersenne twister.
  std::uniform_int_distribution<> dist1(0,255); // distribute results between 0 and 25r inclusive
  int i;
  printf("\nKey generated: ");
  for (i = 0; i < blockSize; ++i) {
    key.push_back(dist1(gen));
    if (debugFlag == true) {
      printf("%.2x ", (unsigned char)key[i]);
    }
  }
  printf("\n");
  return true;
}
/******************************************************************************/
