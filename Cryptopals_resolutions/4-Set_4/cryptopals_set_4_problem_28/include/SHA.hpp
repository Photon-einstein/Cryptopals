#ifndef SHA_H
#define SHA_H

#include <vector>

namespace MyCryptoLibrary {

  class SHA {
  public:
      /* constructor / destructor*/
      SHA();
      ~SHA();

      /* public methods */
      virtual std::vector<unsigned char> hash(const std::vector<unsigned char> &inputV) = 0;

  };

}

#endif
