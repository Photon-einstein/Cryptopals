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
      /**
       * @brief Calculates a given hash
       *
       * This virtual method calculates a given hash of a plaintext in inputV
       *
       * @return The hash of inputV in a vector format
       */
      virtual std::vector<unsigned char> hash(const std::vector<unsigned char> &inputV) = 0;

  };

}

#endif
