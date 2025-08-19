#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>

#include "./../include/SrpParametersLoader.hpp"

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
std::map<unsigned int, SrpParametersLoader::SrpParameters>
SrpParametersLoader::loadSrpParameters(const std::string &filename) {
  std::ifstream file(filename);
  if (!file.is_open()) {
    throw std::runtime_error("SrpParametersLoader log | loadSrpParameters(): "
                             "Could not open SRP parameters file: '" +
                             filename + "'.");
  }
  nlohmann::json j;
  try {
    file >> j;
  } catch (const nlohmann::json::parse_error &e) {
    throw std::runtime_error("SrpParametersLoader log | loadSrpParameters(): "
                             "Failed to parse JSON file: " +
                             std::string(e.what()));
  }
  std::map<unsigned int, SrpParametersLoader::SrpParameters> paramsMap;
  if (j.contains("srpGroups") && j["srpGroups"].is_array()) {
    for (const auto &group : j["srpGroups"]) {
      if (group.contains("groupId") && group.contains("sizeBits") &&
          group.contains("primeN") && group.contains("generatorG")) {
        SrpParametersLoader::SrpParameters params;
        params._groupId = group["groupId"].get<unsigned int>();
        params._sizeBits = group["sizeBits"].get<unsigned int>();
        if (group["primeN"].is_array()) {
          std::string primeConcat;
          for (const auto &chunk : group["primeN"]) {
            primeConcat += chunk.get<std::string>();
          }
          params._pHex = primeConcat;
        } else {
          params._pHex = group["primeN"].get<std::string>();
        }
        params._g = group["generatorG"].get<unsigned int>();
        params._groupName = group["name"].get<std::string>();
        params._hashName = group["hash"].get<std::string>();
        paramsMap[group["groupId"].get<unsigned int>()] = params;
      } else {
        std::cerr << "SrpParametersLoader log | loadSrpParameters(): "
                     "Warning: Skipping malformed SRP group entry in JSON."
                  << std::endl;
      }
    }
  } else {
    throw std::runtime_error(
        "SrpParametersLoader log | loadSrpParameters(): "
        "JSON file does not contain a 'srp_parameters' array.");
  }
  return paramsMap;
}
