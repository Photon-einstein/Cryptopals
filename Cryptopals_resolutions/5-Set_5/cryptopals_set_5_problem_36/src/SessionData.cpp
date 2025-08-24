#include "./../include/SessionData.hpp"

/**
 * @brief This method will execute the constructor of the SessionData
 * structure.
 *
 * This method will execute the constructor of the SessionData structure. It
 * will perform all the necessary data initializations.
 *
 * @param groupId The group ID that is going to be used with this client ID
 * session
 * @param salt The salt that is going to be used with this client ID session.
 * @param hash The hash algorithm that is to be used with  this client ID
 * session.
 */
SessionData::SessionData(const unsigned int groupId, const std::string &salt,
                         const std::string &hash) {
  if (groupId <= 0 || salt.empty() || hash.empty()) {
    throw std::runtime_error("SessionData log | constructor(): "
                             "Invalid input parameters given.");
  }
  _groupId = groupId;
  _salt = salt;
  _hash = hash;
};
/******************************************************************************/
/**
 * @brief This method will perform the destruction of the SessionData
 * structure.
 *
 * This method will perform the destruction of the SessionData structure,
 * releasing all the resources and memory used.
 */
SessionData::~SessionData(){};
/******************************************************************************/
