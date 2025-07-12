#ifndef DH_PARAMETERS_LOADER_HPP
#define DH_PARAMETERS_LOADER_HPP

#include <map>
#include <string>
#include <vector>

namespace DhParametersLoader {

struct DhParameters {
  std::string _groupName;
  std::string _pHex;
  std::string _gHex;
  std::string _description;
  std::string _notes;
};

/**
 * @brief This method extracts the content of a given file.
 *
 * This method will extract the content of a given file that contains
 * the public configurations of the Diffie Hellman key exchange protocol.
 *
 * @param filename The file address where the public configurations of
 * the Diffie Hellman key Exchange protocol are.
 *
 * @return The file content in a structured dictionary.
 */
std::map<std::string, DhParameters>
loadDhParameters(const std::string &filename);

}; // namespace DhParametersLoader

#endif // DH_PARAMETERS_LOADER_HPP