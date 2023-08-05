#include <stdexcept>
#include <chrono>
#include <thread>

#include "./../include/Server.h"
#include "./../include/Function.h"

/* constructor / destructor */
Server::Server(const std::string inputFilePath, const std::string aesEcbKey) {
  bool b;
  std::string ciphertext;
  std::string plaintext;
  Server::setBlockSize(blockSize);
  Server::getDecodeDataFromFile(inputFilePath);
  _aesEcbMachine = std::make_shared<AesEcbMachine>(aesEcbKey, _blockSize);
  _aesCtrMachine = std::make_shared<AesCtrMachine>(_blockSize);
  _plaintext = _aesEcbMachine->decryption(_inputBytesAsciiFullTextV, &b);
  Function::convertStringToVectorBytes(_plaintext, _plaintextV);
  if (b == false) {
    perror("Error at the function 'AesEcbMachine::aesEcbDecryption'");
  }
  if (debugFlagExtreme == true) {
    std::cout<<"\n\nServer log | Ascii data read from file, after decryption of AES-ECB mode:\n\n'"
      <<_plaintext<<"'.\n"<<std::endl;
  }
  _aesCtrMachine->saveIVCtrMode();
  ciphertext = _aesCtrMachine->encryption(_plaintextV, &b);
  Function::convertStringToVectorBytes(ciphertext, _ciphertextV);
  if (b == false) {
    perror("Error at the function 'AesCtrMachine::encryption'");
  }
}
/******************************************************************************/
Server::~Server() {
}
/******************************************************************************/
std::vector<unsigned char> Server::getCiphertext() {
  return _ciphertextV;
}
/******************************************************************************/
/* this function will test if plaintext matches the _plaintextV from the
server, and it will return if matches, false otherwise */
bool Server::testRecoveredPlaintext(const std::vector<unsigned char> &plaintextV) {
  if (plaintextV.size() != _plaintextV.size()) {
    return false;
  }
  unsigned int i, size = _plaintextV.size();
  for (i = 0; i < size; ++i) {
    if (plaintextV[i] != _plaintextV[i]) {
      return false;
    }
  }
  return true;
}
/******************************************************************************/
/* this function will decrypt the ciphertext, replace the plaintext by the
newText starting at the offset position, and then encrypt again, returning
the new ciphertext by reference in the same vector ciphertext, if all went
ok it will return true, false otherwise */
bool Server::editCiphertextAPI(std::vector<unsigned char> &ciphertextV, unsigned int
  offset, const std::vector<unsigned char> &newTextV) {
  std::string plaintext, ciphertext;
  bool b;
  std::vector<unsigned char> plaintextV;
  unsigned int i, size = newTextV.size();
  _aesCtrMachine->restoreIVCtrMode();
  plaintext = _aesCtrMachine->decryption(_ciphertextV, &b);
  if (b == false) {
    perror("Error at the function 'AesCtrMachine::aesCtrDecryption'");
    return true;
  }
  /* fill content before offset */
  plaintextV.clear();
  for (i = 0; i < offset; ++i) {
    plaintextV.push_back(plaintext[i]);
  }
  /* fill content after offset */
  for (i = 0; i < size; ++i) {
    plaintextV.push_back(newTextV[i]);
  }
  _aesCtrMachine->restoreIVCtrMode();
  /* encrypt again the new plaintext */
  ciphertext = _aesCtrMachine->encryption(plaintextV, &b);
  Function::convertStringToVectorBytes(ciphertext, ciphertextV);
  if (b == false) {
    perror("Error at the function 'AesCtrMachine::encryption'");
    return false;
  }
  return true;
}
/******************************************************************************/
/* this function will return true if the attacker returns the same plaintext
as the server has it in the database, false otherwise */
bool Server::testEqualRecoveredPlaintext(const std::string plaintextAttacker) {
  bool b;
  (_plaintext == plaintextAttacker) ? b = true : b = false;
  return b;
}
/******************************************************************************/
/* this function reads the data from the file with the name inputFileName, then
it does the base64 to ascii convertion, afterwards it return the converted data
in a vector by reference and returns true if all went ok or false otherwise */
void Server::getDecodeDataFromFile(const std::string inputFileName) {
  if (inputFileName.size() == 0) {
    throw std::invalid_argument("Bad 'inputFilePath' | file path cannot be empty");
  }
  std::ifstream inputFile;
  inputFile.open(inputFileName, std::ios::in);
  std::map<unsigned char, int> base64IndexMap;
  std::map<unsigned char, int>::iterator it;
  std::vector<unsigned char> inputBytesAscii;
  std::vector<unsigned char> lineReadBase64Vector, lineReadBase64VectorFullText;
  std::string lineReadBase64;
  int i, size;
  bool b;
  /* rest of the work to be done */
  if (!inputFile) {
    throw std::invalid_argument("File failed to be opened.");
  } else if (debugFlagExtreme == true) {
    std::cout<<"Server log | The file 'cryptopals_set_4_problem_25_dataset.txt' was sucessfully opened.\n"<<std::endl;
  }
  /* base64IndexMap */
  for(i = 0; i < (int)base64CharsDecoder.size(); ++i) {
    base64IndexMap[base64CharsDecoder[i]] = i;
  }
  /* data read and conversion to ascii */
  while(inputFile.good() == true) {
    lineReadBase64.clear();
    lineReadBase64Vector.clear();
    inputBytesAscii.clear();
    std::getline(inputFile, lineReadBase64);
    Function::convertStringToVectorBytes(lineReadBase64, lineReadBase64Vector);
    b = Server::decodeBase64ToByte(lineReadBase64Vector, base64IndexMap, inputBytesAscii);
    if (b == false) {
      throw std::invalid_argument("There was an error in the function 'decodeBase64ToByte'.");
    }
    /* pass data read line by line into the full vector data */
    size = inputBytesAscii.size();
    for(i = 0; i < size; ++i) {
      _inputBytesAsciiFullTextV.emplace_back(inputBytesAscii[i]);
    }
    /* pass data input data read line by line into the full vector data */
    size = lineReadBase64Vector.size();
    for(i = 0; i < size; ++i) {
      lineReadBase64VectorFullText.emplace_back(lineReadBase64Vector[i]);
    }
  }
  inputFile.close();
  return;
}
/******************************************************************************/
/* this function does the decode from base64 into bytes, returning the
result in a vector of unsigned char by reference, if all is ok it will be also
returned true, false otherwise */
bool Server::decodeBase64ToByte(const std::vector<unsigned char> &sV, std::map<unsigned char, int>
  &base64IndexMap, std::vector<unsigned char> &encryptedBytesAscii) {
  if (sV.size() % 4 != 0) {
    return false;
  }
  int sizeString = sV.size(), i, j, k, validInputLetters=0;
  int validOutputLetters=0;
  unsigned char c, mapBase64Index[4]={0};
  encryptedBytesAscii.clear();
  /* convert from base64 into bytes taking as input 4 base64 chars at each step */
  for (i = 0; i < sizeString; i+=4) {
    /* valid letters count, meaning different from '=' base64char */
    for (j = i, validInputLetters = 0; j < i+4; ++j) {
      if (sV[j] != '=') {
        ++validInputLetters;
      }
    }
    /* convertion from base64 char into index of the base64 alphabet */
    for(j = i, k = 0; j < i+validInputLetters; ++j, ++k) {
      mapBase64Index[k] = base64IndexMap[(unsigned char)sV[j]];
    }
    /* valid input letters converted to valid output letters */
    validOutputLetters = validInputLetters-1;
    for (j = 0; j < validOutputLetters; ++j) {
      if (j == 0) {
        /* 765432 | 10 */
        c = ( (mapBase64Index[0] & 0x3F) << 2 ) | ( (mapBase64Index[1] & 0x3F) >> 4 );
      } else if (j == 1) {
        /* 7654 | 3210 */
        c = ( (mapBase64Index[1] & 0x3F) << 4 ) | ( (mapBase64Index[2] & 0x3F) >> 2 );
      } else if (j == 2) {
        /* 76 | 543210 */
        c = ( (mapBase64Index[2] & 0x3F) << 6 ) | ( (mapBase64Index[3] & 0x3F) >> 0 );
      }
      encryptedBytesAscii.emplace_back(c);
    }
  }
  return true;
}
/******************************************************************************/
/* setters */
void Server::setBlockSize(int blockSize) {
  if (blockSize < 1) {
    throw std::invalid_argument("Bad blockSize | blockSize cannot be less than 1");
  }
  _blockSize = blockSize;
}
/******************************************************************************/
/* getters */
int Server::getBlockSize() {
  return _blockSize;
}
/******************************************************************************/
