#ifndef DH_PARAMETERS_LOADER_HPP
#define DH_PARAMETERS_LOADER_HPP

#include <map>
#include <string>
#include <vector>

namespace DHParametersLoader {

struct DHParameters {
  std::string groupName;
  std::string pHex;
  std::string gHex;
  std::string description;
  std::string notes;
};

/**
 * @brief This method extracts the content of a given file
 *
 * This method will extract the content of a given file
 *
 * @return The file content in a string format
 */
std::map<std::string, DHParameters>
loadDhParameters(const std::string &filename);

}; // namespace DHParametersLoader

#endif // DH_PARAMETERS_LOADER_HPP