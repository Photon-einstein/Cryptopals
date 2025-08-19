#ifndef SRP_PARAMETERS_LOADER_HPP
#define SRP_PARAMETERS_LOADER_HPP

#include <map>
#include <string>
#include <vector>

namespace SrpParametersLoader {

struct SrpParameters {
  unsigned int _groupId;
  unsigned int _sizeBits;
  std::string _pHex;
  unsigned int _g;
  std::string _groupName;
  std::string _hashName;
};

/**
 * @brief This method extracts the content of a given file.
 *
 * This method will extract the content of a given file that contain
 * the public configurations of the Secure Remote Password protocol.
 *
 * @param filename The file address where the public configurations of
 * the Secure Remote Password protocol are.
 *
 * @return The file content in a structured dictionary.
 */
std::map<unsigned int, SrpParameters>
loadSrpParameters(const std::string &filename);

}; // namespace SrpParametersLoader

#endif // SRP_PARAMETERS_LOADER_HPP