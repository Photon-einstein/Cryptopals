#ifndef DH_PARAMETERS_LOADER_HPP
#define DH_PARAMETERS_LOADER_HPP

#include <map>
#include <string>
#include <vector>

namespace SrpParametersLoader {

struct SrpParameters {
  std::string _groupName;
  std::string _pHex;
  std::string _gHex;
  std::string _description;
  std::string _notes;
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
std::map<std::string, SrpParameters>
loadSrpParameters(const std::string &filename);

}; // namespace SrpParametersLoader

#endif // SRP_PARAMETERS_LOADER_HPP