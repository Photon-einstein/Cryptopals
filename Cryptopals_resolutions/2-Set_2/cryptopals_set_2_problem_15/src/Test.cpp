#include <stdexcept>

#include "./../include/Function.h"
#include "./../include/Pad.h"
#include "./../include/PadPKCS_7.h"
#include "./../include/Test.h"

/* constructor / destructor */
Test::Test(std::shared_ptr<Pad> pad) { _pad = pad; }
/******************************************************************************/
Test::~Test() {}
/******************************************************************************/
/* setter */
bool Test::addTest(const std::string &s) {
  if (s.size() == 0) {
    return false;
  }
  _strings.emplace_back(s);
  return true;
}
/******************************************************************************/
/* this function runs the tests on the string stored at the vector _strings,
in the end it will return true if the tests passed or false otherwise */
bool Test::runTests() {
  int i, size = _strings.size();
  std::vector<unsigned char> aux;
  bool flag;
  for (i = 0; i < size; ++i) {
    std::cout << "\nTest " << i + 1 << ":" << std::endl;
    std::cout << "Padded string: ";
    aux.clear();
    Function::convertStringToVectorBytes(_strings[i], aux);
    Test::printVector(aux);
    /* test pad */
    try {
      flag = _pad->testPadding(aux);
      if (flag == true) {
        std::cout << "Padding Ok." << std::endl;
      }
    } catch (const std::exception &ex) {
      std::cerr << ex.what() << std::endl;
    }
    /* unpad */
    _pad->unpad(aux);
    std::cout << "Unpadded string: ";
    Test::printVector(aux);
  }
  return true;
}
/******************************************************************************/
/* this function does the print of the vector of chars, in the end it just
returns */
void Test::printVector(const std::vector<unsigned char> &v) {
  printf("'");
  int i, size = v.size();
  for (i = 0; i < size; ++i) {
    if ((v[i] >= 'a' && v[i] <= 'z') || (v[i] >= 'A' && v[i] <= 'Z') ||
        v[i] == ' ' || v[i] == '?' || v[i] == '!' || v[i] == '.' ||
        v[i] == ',') {
      printf("%c", v[i]);
    } else {
      printf("x%.2x", v[i]);
    }
  }
  printf("'\n");
  return;
}
/******************************************************************************/
