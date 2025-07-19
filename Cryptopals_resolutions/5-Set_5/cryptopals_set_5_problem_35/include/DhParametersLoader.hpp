#ifndef DH_PARAMETERS_LOADER_HPP
#define DH_PARAMETERS_LOADER_HPP

#include <map>
#include <string>
#include <vector>

namespace DhParametersLoader {

/**
 * @brief This structure that holds all the information regarding the Diffie
 * Hellman parameters.
 *
 * @param _groupName The group name regarding this DH parameter.
 * @param _pHex The prime p regarding this DH parameter in hexadecimal format.
 * @param _gHex The generator g regarding this DH parameter in hexadecimal
 * format.
 * @param _description The description of this Diffie Hellman parameter.
 * @param _notes The notes or comments regarding this Diffie Hellman parameter.
 */
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
 *
 * @throw runtime_error if it was not possible to open the file or the JSON
 * parsing failed.
 */
std::map<std::string, DhParameters>
loadDhParameters(const std::string &filename);

}; // namespace DhParametersLoader

#endif // DH_PARAMETERS_LOADER_HPP