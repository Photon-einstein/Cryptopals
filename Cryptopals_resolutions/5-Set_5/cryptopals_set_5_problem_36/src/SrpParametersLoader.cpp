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
std::map<std::string, SrpParametersLoader::SrpParameters>
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
  std::map<std::string, SrpParametersLoader::SrpParameters> paramsMap;
  if (j.contains("dh_parameters") && j["dh_parameters"].is_array()) {
    for (const auto &group : j["dh_parameters"]) {
      if (group.contains("name") && group.contains("p") &&
          group.contains("g")) {
        SrpParametersLoader::SrpParameters params;
        params._groupName = group["name"].get<std::string>();
        params._pHex = group["p"].get<std::string>();
        params._gHex = group["g"].get<std::string>();
        // Optional fields
        if (group.contains("description")) {
          params._description = group["description"].get<std::string>();
        }
        if (group.contains("notes")) {
          params._notes = group["notes"].get<std::string>();
        }
        paramsMap[group["name"].get<std::string>()] = params;
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
