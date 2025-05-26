#ifndef DIFFIE_HELLMAN_HPP
#define DIFFIE_HELLMAN_HPP

#include <memory>
#include <vector>

namespace MyCryptoLibrary {

class Diffie_Hellman {
public:
  /* constructor / destructor*/
  Diffie_Hellman();
  ~Diffie_Hellman();

  /* public methods */

private:
  int p;
  int g;
  int privatekey;
  int publicKey;
};

} // namespace MyCryptoLibrary

#endif // DIFFIE_HELLMAN_HPP
