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
void Attacker::setIV(std::vector<unsigned char> ivV) {
  _ivV.clear();
  copy(ivV.begin(), ivV.end(), back_inserter(_ivV));
}
/******************************************************************************/
/* this function tries to interact with the server by his interface and it
will then try to decrypt the session token, if sucessfull it will return the
session token by reference and set returnValue to true, false otherwise, it
will also return true if all went without errors, false otherwise */
bool Attacker::attackCbcBlockCypherMode(std::string &possibleSessionTokenObtained, bool *returnValue) {
  if (returnValue == nullptr) {
    return false;
  }
  std::vector<unsigned char> ciphertextV, auxCiphertextV, auxCiphertextVMem, ivV, decryptedPlaintextVector;
  bool flag, retVal;
  int nBlocks, i, j, k, w, index, testValidPad, maxTest = pow(2, numberOfBitsInOneByte), count=0;
  unsigned char paddingNumber, decryptedPlaintextChar, c;
  std::string plaintext;
  /* work */
  flag = _server->encryptionSessionTokenAesCbcMode(ciphertextV, ivV);
  if (flag == false) {
    perror("There was an error in the function 'encryptionSessionTokenAesCbcMode'.");
    return false;
  }
  Attacker::setIV(ivV);
  /* test cipher size */
  if (ciphertextV.size() % _blockSize != 0) {
    perror("Bad Session token size | session token size must be a multiple of blockSize after padding.");
    return false;
  }
  nBlocks = ciphertextV.size() / _blockSize;
  if (debugFlag == true) {
    std::cout<<"'ciphertextV' has a size of "<<nBlocks<<" blocks | "<<ciphertextV.size()<<" bytes.\n"<<std::endl;
  }
  /* insert int auxCiphertextV all blocks except last block */
  copy(ciphertextV.begin(), ciphertextV.end(), back_inserter(auxCiphertextV));
  /* copy auxCiphertextV into auxCiphertextVMem */
  copy(auxCiphertextV.begin(), auxCiphertextV.end(), back_inserter(auxCiphertextVMem));
  /* decrypt ciphertext one byte at a time */
  for (i = 0; i < nBlocks; ++i) {
    for (j = 0; j < _blockSize; ++j) {
      paddingNumber = j+1;
      index = auxCiphertextV.size()-j-_blockSize-1;
      printf("\n---> Index = %d | Decryption = %d \n", index, index+_blockSize);
      /* update auxCiphertextV to the right: Ci-blockSize XOR Ci'-blockSize = Pi XOR paddingNumber */
      for (k = index+1, w = 0; k < auxCiphertextV.size()-_blockSize; ++k, ++w) {
        auxCiphertextV[k] = auxCiphertextVMem[k] ^ decryptedPlaintextVector[w] ^ paddingNumber;
      }
      for(testValidPad = 0; testValidPad < maxTest; ++testValidPad) {
        /* get valid Ci-blockSize' */
        auxCiphertextV[index] = auxCiphertextVMem[index]^testValidPad;
        flag = _server->decryptAndCheckPaddingInSessionTokenAesCbcMode(auxCiphertextV, &retVal);
        if (flag == false) {
          perror("There was an error in the function 'decryptAndCheckPaddingInSessionTokenAesCbcMode'.");
          return false;
        }
        /* test last byte, exclude last bytes as: x02 | x02 as false positive */
        if (j == 0 && retVal == true) {
          auxCiphertextV[index-1] = auxCiphertextVMem[index-1]^0x1;
          flag = _server->decryptAndCheckPaddingInSessionTokenAesCbcMode(auxCiphertextV, &retVal);
          if (flag == false) {
            perror("There was an error in the function 'decryptAndCheckPaddingInSessionTokenAesCbcMode'.");
            return false;
          }
          if (retVal ==  false) {
            /* in this case we got a false positive, do nothing in this case */
            continue;
          }
        }
        if (retVal == true && debugFlag == true) {
          std::cout<<"We got a valid tampered ciphertext at block "<<nBlocks-i<<", byte "<<_blockSize-j<<
            " with a delta tampered value of "<<testValidPad;
          printf(" | delta tampered value = x%.2x | auxCiphertextV = x%.2x.\n", (unsigned char)testValidPad, auxCiphertextV[index]);
        }
        if (retVal == true) {
          /* perform rest of the decryption action, insert decrypted plaintext */
          /* pi = paddingNumber XOR Ci-blockSize XOR Ci'-blockSize */
          decryptedPlaintextChar = paddingNumber^testValidPad;
          if (debugFlag == true) {
            printf("Decrypted plaintext: (hex)'%.2x' | (char)'%c'.\n\n", decryptedPlaintextChar, decryptedPlaintextChar);
          }
        }
      }
      decryptedPlaintextVector.insert(decryptedPlaintextVector.begin(), decryptedPlaintextChar);
    }
    /* extract right most block from the auxCiphertextV and auxCiphertextVMem */
    for (j = 0; j < _blockSize; ++j) {
      auxCiphertextV.pop_back();
      auxCiphertextVMem.pop_back();
    }
    /* reset the state of the current last block in auxCiphertextV vector */
    for (j = 0; j < _blockSize; ++j) {
      auxCiphertextV[auxCiphertextV.size()-1-j] = auxCiphertextVMem[auxCiphertextV.size()-1-j];
    }
    if (debugFlag == true) {
      std::cout<<"Size of 'auxCiphertextV' after block round number "<<i+1<<": "<<auxCiphertextV.size()<<" bytes."<<std::endl;
    }
    /* if auxCiphertextV already with only 1 block, add IV vector to the beginning */
    if (auxCiphertextV.size() == _blockSize) {
      /* prepend IV into auxCiphertextV */
      auxCiphertextV.clear();
      copy(_ivV.begin(), _ivV.end(), std::back_inserter(auxCiphertextV));
      copy(auxCiphertextVMem.begin(), auxCiphertextVMem.end(), std::back_inserter(auxCiphertextV));
      /* copy new auxCiphertextV into auxCiphertextVMem */
      auxCiphertextVMem.clear();
      copy(auxCiphertextV.begin(), auxCiphertextV.end(), std::back_inserter(auxCiphertextVMem));
    }
  }
  /* prepare output */
  if (_server->_pad->testPadding(decryptedPlaintextVector) == false) {
    perror("There was an error in the function 'testPadding' | the decrypted text does not have a valid padding.");
    return false;
  }
  if (_server->_pad->unpad(decryptedPlaintextVector) == false) {
    perror("There was an error in the function 'unpad' | the decrypted text does not have a valid padding.");
    return false;
  }
  Function::convertVectorBytesToString(decryptedPlaintextVector, possibleSessionTokenObtained);
  return true;
}
/******************************************************************************/
