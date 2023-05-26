#include <stdexcept>

#include "./../include/Server.h"
#include "./../include/Function.h"
#include "./../include/Attacker.h"

/* constructor / destructor */
Attacker::Attacker(std::shared_ptr<Server>& server, const int blockSize) {
  Attacker::setBlockSize(blockSize);
  Attacker::setServer(server);
}
/******************************************************************************/
Attacker::~Attacker() {
}
/******************************************************************************/
/* setters */
void Attacker::setBlockSize(int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument("Bad blockSize | blockSize cannot be less than 1");
  }
  _blockSize = blockSize;
}
/******************************************************************************/
void Attacker::setServer(std::shared_ptr<Server>& server) {
  _server = server;
}
/******************************************************************************/
/* this function will get the cyphertext from the server, one string from
encryption */
void Attacker::setFullCyphertextFromServer() {
  int i, size;
  _fullCiphertextV = _server->getStringsAsciiEncrypted();
  size = _fullCiphertextV.size();
  if (debugFlag == true) {
    std::cout<<"\n\n\n\nCyphertext read at the attacker:"<<std::endl;
    for (i = 0; i < size; ++i) {
      std::cout<<_fullCiphertextV[i]<<std::endl;
    }
  }
  return;
}
/******************************************************************************/
/* this function will calculate the minimum length at the vector of strings
_fullCyphertextV and update the field _minSizeEncryptionString accordingly */
void Attacker::setMinSizeEncryptionString() {
  int i, minSize = INT_MAX, size = _fullCiphertextV.size();
  for (i = 0; i < size; ++i) {
    if (minSize > _fullCiphertextV[i].size()) {
      minSize = _fullCiphertextV[i].size();
    }
  }
  /* update field of interest */
  _minSizeEncryptionString = minSize;
  _maxKeySize = minSize;
  if (debugFlag == true) {
    std::cout<<"\nMin size encryption string is "<<_minSizeEncryptionString<<" bytes."<<std::endl;
  }
  return;
}
/******************************************************************************/
/* this function will fill the vector _encryptedBytesAsciiTrimmedToMinSizeEncryptionString
from the vector _fullCyphertextV, taken into consideration the value of the
_minSizeEncryptionString calculated previously */
void Attacker::setEncryptedBytesAsciiTrimmedToMinSizeEncryptionString() {
  if (_minSizeEncryptionString == minSizeEncryptionStringNotSetFlag || _minSizeEncryptionString <= 0) {
    throw std::invalid_argument("Bad _minSizeEncryptionString | _minSizeEncryptionString must be initialized to a positive number.");
  }
  int i, j, nStrings = _fullCiphertextV.size();
  for (i = 0; i < nStrings; ++i) {
    for (j = 0; j < _minSizeEncryptionString; ++j) {
      _encryptedBytesAsciiTrimmedToMinSizeEncryptionString.emplace_back(_fullCiphertextV[i][j]);
    }
  }
  if (debugFlag == true) {
    std::cout<<"\n\n\n\nCyphertext trimmed to minimum size read at the attacker (hex):"<<std::endl;
    for (i = 0; i < _encryptedBytesAsciiTrimmedToMinSizeEncryptionString.size(); ++i) {
      printf(" %.2x", _encryptedBytesAsciiTrimmedToMinSizeEncryptionString[i]);
      if ((i+1) % _minSizeEncryptionString == 0 && i != 0) {
        std::cout<<std::endl;
      }
    }
  }
}
/******************************************************************************/
/* this function will decrypt the encrypted text that the server hands out
to the attacker, in the end this function should return the decrypted strings
up to the minimum size of the pool of ciphertext already calculated previously,
in the end it will update the vector and return true if all ok or false
otherwise, it will also pass the key size in the end by reference */
bool Attacker::decryptMinSizeEncryptedStrings(std::vector<std::string> &decryptedStrings, int *sizeKey) {
  if (sizeKey == nullptr) {
    return false;
  }
  std::vector<struct keyId> keyL;
  std::vector<unsigned char> key, decryptedTextV;
  std::string resS;
  bool b;
  /* work to do */
  Attacker::setFullCyphertextFromServer();
  Attacker::setMinSizeEncryptionString();
  Attacker::setEncryptedBytesAsciiTrimmedToMinSizeEncryptionString();
  /* do study of the key length */
  Attacker::getKeyLengthProfileSorted(_encryptedBytesAsciiTrimmedToMinSizeEncryptionString,
    keyL, _minKeySize, _maxKeySize);
  key = Attacker::getKey(_encryptedBytesAsciiTrimmedToMinSizeEncryptionString, keyL, &b);
  if (b == false) {
    perror("There was a problem in the function 'getKey'.");
    return false;
  }
  /* decrypt file with best key found */
  b = Attacker::decryptText(_encryptedBytesAsciiTrimmedToMinSizeEncryptionString,
    key, decryptedTextV);
  if (b == false) {
    printf("\nThere was a problem in the function 'decryptText'.");
    return false;
  }
  /* parse decrypted text in key lenght string sizes */
  Attacker::parseDecryptedStrings(decryptedTextV, decryptedStrings, key.size());
  *sizeKey = key.size();
  return true;
}
/******************************************************************************/
/* this function makes fulling of the vector keyL for every length of the key,
orders the vector in ascending order by the editDistance and returns true if all
ok, false otherwise */
bool Attacker::getKeyLengthProfileSorted(std::vector<unsigned char> &encryptedBytesAsciiFullText,
    std::vector<struct keyId> &keyL, int minKeySizeVal, int maxKeySizeVal) {
  if (minKeySizeVal > maxKeySizeVal || encryptedBytesAsciiFullText.size() == 0) {
    return false;
  }
  int sizeFullText = encryptedBytesAsciiFullText.size(), nSlices, sliceSize, i, j, k;
  std::vector<unsigned char> slice1, slice2;
  unsigned char c1, c2;
  bool b;
  double score;
  std::string s1,s2;
  struct keyId key;
  for (i = minKeySizeVal; i <= maxKeySizeVal; ++i) {
    sliceSize = 2*i;
    nSlices = sizeFullText/sliceSize;
    /* reset key values */
    key.keyLength = i;
    key.editDistance = 0;
    score = 0;
    for (j = 0; j < nSlices; ++j) {
      /* slices fulling */
      slice1.clear();
      slice2.clear();
      for (k = 0; k < i; ++k) {
        c1 = encryptedBytesAsciiFullText[k+j*sliceSize];
        c2 = encryptedBytesAsciiFullText[k+j*sliceSize+i];
        slice1.emplace_back(c1);
        slice2.emplace_back(c2);
      }
      /* slice calculation */
      Function::convertVectorBytesToString(slice1, s1);
      Function::convertVectorBytesToString(slice2, s2);
      score+=(double)calcHammingDistance(slice1, slice2, &b)/i;
      if (b == false) {
        std::cout<<"There was an error in the function calcHammingDistance."<<std::endl;
        return false;
      }
    }
    /* normalization by the number of slices */
    key.editDistance = score/nSlices;
    /* update keyL vector */
    keyL.emplace_back(key);
  }
  /* sort the keyL vector by the value of editDistance, in ascending order */
  std::sort(keyL.begin(), keyL.end());
  if (debugFlag == true) {
    /* print sort vector */
    std::cout<<"\nKeySize and edit distance (Hamming distance) in decreasing order of the second.\n"<<std::endl;
    for (i = 0; i < (int)keyL.size(); ++i) {
      std::cout<<"Keysize = "<<keyL[i].keyLength<<"\t | \teditDistance = "<<keyL[i].editDistance<<std::endl;
    }
    /* print sort vector */
    std::cout<<"\nValid KeySize and edit distance (Hamming distance) considered for the search.\n"<<std::endl;
    for (i = 0; i < validKeyPoolSearch; ++i) {
      std::cout<<"Keysize = "<<keyL[i].keyLength<<"\t | \teditDistance = "<<keyL[i].editDistance<<std::endl;
    }
  }
  return true;
}
/******************************************************************************/
/* this function makes the calculation of the hamming distance between v1 and
v2, if there is an error it returns b = false, true otherwise by reference */
int Attacker::calcHammingDistance(const std::vector<unsigned char> &v1, const
    std::vector<unsigned char> &v2, bool *b) {
  if (v1.size() != v2.size()) {
    *b = false;
    return 0;
  }
  std::vector<unsigned char> xorRes;
  int i, size = v1.size(), hammingDistance=0, n;
  for(i = 0; i < size; ++i) {
    xorRes.emplace_back(v1[i]^v2[i]);
    n=Attacker::calcBitsOn(xorRes[i]);
    hammingDistance+=n;
  }
  *b=true;
  return hammingDistance;
}
/******************************************************************************/
/* this function makes the calculation of the bits on in the char c, in the end
it just returns that number */
int Attacker::calcBitsOn(unsigned char c) {
  int nBitsOn=0, i, numberBitsOnByte=8;
  for (i = 0; i < numberBitsOnByte; ++i) {
    if ((c & 1) == 1) {
      ++nBitsOn;
    }
    c>>=1;
  }
  return nBitsOn;
}
/******************************************************************************/
/* this function return the key for this cypertext encryptedBytesAscii, using the
data provided in the keyL vector, if all goes ok it will return b = true by
reference, false otherwise */
std::vector<unsigned char> Attacker::getKey(std::vector<unsigned char> &encryptedBytesAscii,
    std::vector<struct keyId> &keyL, bool *b) {
  std::vector<std::vector<unsigned char>> dataParsedInKeySize;
  std::vector<std::vector<lineChangedId>> keySol;
  std::vector<lineChangedId> auxLineChangedIdVector;
  lineChangedId auxLineChangedIdElement={};
  bestKeyId keySolId={};
  keySolId.keySize = -1;
  int i, j;
  bool b2;
  double valMaxRatioLettersSpaceMean;
  std::unordered_map<char, float> englishLetterFrequency = {{'a',8.2e-2},{'b',1.5e-2},
    {'c',2.8e-2},{'d',4.3e-2},{'e',13.0e-2},{'f',2.2e-2},{'g',2.0e-2},{'h',6.1e-2},
    {'i',7.0e-2},{'j',0.15e-2},{'k',0.77e-2},{'l',4.0e-2},{'m',2.4e-2},{'n',6.7e-2},
    {'o',7.5e-2},{'p',1.9e-2},{'q',0.095e-2},{'r',6.0e-2},{'s',6.3e-2},{'t',9.1e-2},
    {'u',2.8e-2},{'v',0.98e-2},{'w',2.4e-2},{'x',0.15e-2},{'y',2.0e-2},{'z',0.074e-2}};
  if (encryptedBytesAscii.size() < _maxKeySize) {
    std::cout<<"Size of cypertext = "<<encryptedBytesAscii.size()<<std::endl;
    std::cout<<"Size of maxKeySize = "<<_maxKeySize<<std::endl;
    *b = false;
    return keySolId.key;
  }
  /* get data parsed in keysize from cyphertext */
  for (i = 0; i < validKeyPoolSearch; ++i) {
    dataParsedInKeySize.clear();
    dataParsedInKeySize = Attacker::getDataParseInKeySize(encryptedBytesAscii, keyL[i].keyLength, &b2);
    if (b2 == false) {
      *b = false;
      return keySolId.key;
    }
    /* keySol memory allocation and test */
    keySol.emplace_back(auxLineChangedIdVector);
    valMaxRatioLettersSpaceMean = 0;
    for (j = 0; j < keyL[i].keyLength; ++j) {
      keySol[i].emplace_back(auxLineChangedIdElement);
      b2 = Attacker::testCharactersXor(keySol[i][j], englishLetterFrequency, dataParsedInKeySize[j]);
      if (b2 == false) {
        perror("There was an error in the function 'testCharactersXor'.");
        *b = false;
        return keySolId.key;
      }
      valMaxRatioLettersSpaceMean+=keySol[i][j].charId.valMaxRatioLettersSpace;
    }
    /* normalization of valMaxRatioLettersSpace */
    valMaxRatioLettersSpaceMean/=keyL[i].keyLength;
    /* test best key for length keyL[i].keyLength */
    if (keySolId.keySize == -1 || valMaxRatioLettersSpaceMean > keySolId.valMaxRatioLettersSpaceMean) {
      /* we need to update the key */
      keySolId.keySize = keyL[i].keyLength;
      keySolId.valMaxRatioLettersSpaceMean = valMaxRatioLettersSpaceMean;
      keySolId.key.clear();
      for (j = 0; j < keyL[i].keyLength; ++j) {
        keySolId.key.emplace_back(keySol[i][j].charId.charMinDeviation);
      }
    }
  }
  std::cout<<"\nBest key was found with size = "<<keySolId.keySize<<": '";
  for (j = 0; j < keySolId.keySize; ++j) {
    if (j != 0) {
      printf(" ");
    }
    printf("%.2x", keySolId.key[j]);
  }
  printf("'\n");
  /* if all went well in this function */
  *b = true;
  return keySolId.key;
}
/******************************************************************************/
/* this function makes the parsing of the cypertext according to the key length,
in the end it returns the cypertext parsed acording to each byte of the key length,
if all went well it returns true by reference in b, or false otherwise */
std::vector<std::vector<unsigned char>> Attacker::getDataParseInKeySize(std::vector<unsigned char>
    &encryptedBytesAscii, int keySize, bool *b) {
  std::vector<std::vector<unsigned char>> v;
  std::vector<unsigned char> aux;
  int i, size = encryptedBytesAscii.size(), j;
  /* parameters testing */
  if ((int)encryptedBytesAscii.size() < keySize) {
    *b = false;
    return v;
  }
  /* vector v fulling */
  for (i = 0; i < keySize; ++i) {
    v.emplace_back(aux);
  }
  /* cypertext parsing */
  for (i = 0; i < size; ++i) {
    v[i%keySize].emplace_back(encryptedBytesAscii[i]);
  }
  if (debugFlagExtreme == true) {
    std::cout<<"\ndataParsedInKeySize for keySize = "<<keySize<<std::endl;
    for(i = 0; i < keySize; ++i) {
      std::cout<<"Key byte: "<<i+1<<std::endl;
      size = v[i].size();
      for (j = 0; j < size; ++j) {
        printf("%.2x ", v[i][j]);
      }
      std::cout<<std::endl;
    }
  }
  *b = true;
  return v;
}
/******************************************************************************/
/* this function for a given line in binary, it will do a xor test with a single
english alphabet character, determine the best fit, based on the max ratio of
english letters and spaces, and if this is the best fit it will also update
the structure lineChangedId, in the end it returns true if no error or false
otherwise */
bool Attacker::testCharactersXor(lineChangedId &lineChangedIdData, std::unordered_map<char,
    float> &englishLetterFrequency, std::vector<unsigned char> &lineReadBinary) {
  if (lineReadBinary.size() == 0) {
    perror("\nlineReadBinary has size 0, error.");
    return false;
  }
  int i, xorPossibleKeys=pow(2,8);
  bool b;
  double deviation, ratioLetters;
  std::vector<unsigned char> xorTest;
  std::string xorTestString;
  int *freqXorChar = (int*)calloc(numberEnglishLetters, sizeof (int));
  if (freqXorChar == nullptr) {
    perror("\nfreqXorChar calloc failed.");
    return false;
  }
  /* xor test */
  for (i = 0; i < xorPossibleKeys; ++i) {
    /* reset structures */
    xorTest.clear();
    memset(freqXorChar, 0, numberEnglishLetters*sizeof(int));
    xorTestString.clear();
    /* xor */
    Attacker::xorFunction(lineReadBinary, i, xorTest);
    /* calculate frequency data */
    b = Attacker::calcFrequencyData(xorTest, freqXorChar);
    if (b == false) {
      perror("\nThere was an error in the function 'calcFrequencyData'");
      return false;
    }
    deviation = Attacker::deviationCalc(englishLetterFrequency, freqXorChar, &b);
    if (b == false) {
      perror("\nThere was an error in the function 'deviationCalc'");
      exit(1);
    }
    ratioLetters = Attacker::ratioCalc(xorTest, &b);
    if (b == false) {
      perror("\nThere was an error in the function 'ratioCalc'");
      exit(1);
    }
    if (ratioLetters > lineChangedIdData.charId.valMaxRatioLettersSpace) {
      lineChangedIdData.lineChangedBinaryEncoded.clear();
      lineChangedIdData.lineChangedBinaryEncoded = lineReadBinary;
      lineChangedIdData.lineChangedBinaryDecoded.clear();
      lineChangedIdData.lineChangedBinaryDecoded = xorTest;
      lineChangedIdData.lineChangedBinaryDecodedString.clear();
      Function::convertVectorBytesToString(lineChangedIdData.lineChangedBinaryDecoded,
        lineChangedIdData.lineChangedBinaryDecodedString);
      lineChangedIdData.charId.valMinDeviation = deviation;
      lineChangedIdData.charId.charMinDeviation = i;
      lineChangedIdData.charId.valMaxRatioLettersSpace = ratioLetters;
    }
  }
  /* free memory */
  memset(freqXorChar, 0, numberEnglishLetters*sizeof(int));
  free(freqXorChar);
  freqXorChar = nullptr;
  /* return no error status */
  return true;
}
/******************************************************************************/
/* this function makes the calculation of the frequency of the characters that
resulted from the xor, in the end it returns true if no error or false otherwise */
bool Attacker::calcFrequencyData(const std::vector<unsigned char> &xorTest, int *freqXorChar) {
  if (freqXorChar == nullptr) {
    return false;
  }
  int i, size = xorTest.size();
  unsigned char testChar;
  for (i = 0; i < size; ++i) {
    testChar = tolower(xorTest[i]);
    if (testChar >= 'a' && testChar <= 'z') {
      ++freqXorChar[testChar-'a'];
    }
  }
  return true;
}
/******************************************************************************/
/* this function makes the xor calculation of: sRes = s1 xor c, if there is a
error it returns false */
void Attacker::xorFunction(const std::vector<unsigned char> &vS1, const unsigned char c,
    std::vector<unsigned char> &vRes) {
  int size = vS1.size(), i;
  for (i = 0; i < size; ++i) {
    vRes.emplace_back(vS1[i]^c);
  }
  return;
}
/******************************************************************************/
/* this function makes the calculation of the deviation from the english letter
frequency, and then it returns the deviation and sets flag to true if no error
or to false if otherwise */
double Attacker::deviationCalc(std::unordered_map<char, float> &englishLetterFrequency,
      int *freqXorChar, bool *flag) {
  if (freqXorChar == nullptr || flag == nullptr) {
    *flag = false;
    return 0;
  }
  int nSamples=0, i;
  double deviation=0;
  for (i = 0; i < numberEnglishLetters; ++i) {
    nSamples+=freqXorChar[i];
  }
  for (i = 0; i < numberEnglishLetters; ++i) {
    deviation+=fabs(static_cast<double>(freqXorChar[i])/nSamples-englishLetterFrequency['a'+i]);
  }
  *flag = true;
  return deviation;
}
/******************************************************************************/
/* this function makes the calculation of the ratio between all the english
and spaces compared to the length of the message, and sets flag to true if no
error or to false if otherwise */
double Attacker::ratioCalc(const std::vector<unsigned char> &xorTest, bool *flag) {
  if (xorTest.size() == 0) {
    *flag = false;
    return 0;
  }
  int i, size = xorTest.size(), nLettersAndSpaces=0;
  for (i = 0; i < size; ++i) {
    if (xorTest[i] == ' ' || (tolower(xorTest[i]) >= 'a' && tolower(xorTest[i]) <= 'z')) {
      ++nLettersAndSpaces;
    }
  }
  *flag = true;
  return static_cast<double>(nLettersAndSpaces)/size;
}
/******************************************************************************/
/* this function makes the decryption of the cypertext using the key to decrypt,
the encryption & decryption process was a repeated XOR with a given key, if there
are no errors it will return true, false otherwise */
bool Attacker::decryptText(const std::vector<unsigned char> &encryptedBytesAsciiFullText,
      const std::vector<unsigned char> &key, std::vector<unsigned char> &decryptedText) {
  if (encryptedBytesAsciiFullText.size() == 0 || key.size() == 0) {
    return false;
  }
  int i, size = encryptedBytesAsciiFullText.size(), sizeKey = key.size();
  for (i = 0; i < size; i++) {
    decryptedText.emplace_back(encryptedBytesAsciiFullText[i]^key[i%sizeKey]);
  }
  return true;
}
/******************************************************************************/
/* this function will parse the decryptedTextV vector, into strings of up to size
keyLength, stored at the vector decryptedStrings, in the end the function will
just return */
void Attacker::parseDecryptedStrings(const std::vector<unsigned char> &decryptedTextV,
    std::vector<std::string> &decryptedStrings, const int keyLength) {
  int size = decryptedTextV.size(), nStrings, i, j;
  std::string s;
  decryptedStrings.clear();
  if (size % keyLength == 0) {
    nStrings = size / keyLength;
  } else {
    nStrings = size / keyLength + 1;
  }
  for (i = 0; i < nStrings; ++i, s.clear()) {
    for (j = 0; j < keyLength; ++j) {
      s.push_back(decryptedTextV[keyLength*i+j]);
    }
    decryptedStrings.emplace_back(s);
  }
  return;
}
/******************************************************************************/
