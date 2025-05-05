#ifndef ATTACKER_HPP
#define ATTACKER_HPP

class Attacker {
public:
  /* constructor / destructor*/
  Attacker(bool debugFlag);
  ~Attacker();

  /**
   * @brief This method will try to break HMAC SHA1 signature for any given 
   * file.
   * 
   * This method will try to break HMAC SHA1 signature for any given 
   * file, the signature will be validated on the server side.
   */
  void breakHmacSHA1();



private:
  bool _debugFlag;
  const int _portServerProduction{18080};
  const int _portServerTest{18081};

};

#endif // ATTACKER_HPP
