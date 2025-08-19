#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>

#include "./../include/DhParametersLoader.hpp"

/**
 * @brief This method extracts the content of a given file.
 *
 * This method will extract the content of a given file that contain
 * the public configurations of the Diffie Hellman key exchange protocol.
 *
 * @param filename The file address where the public configurations of
 * the Diffie Hellman key Exchange protocol are.
 *
 * @return The file content in a structured dictionary.
 */
std::map<std::string, DhParametersLoader::DhParameters>
DhParametersLoader::loadDhParameters(const std::string &filename) {
  std::ifstream file(filename);
  if (!file.is_open()) {
    throw std::runtime_error("DhParametersLoader log | loadDhParameters(): "
                             "Could not open DH parameters file: '" +
                             filename + "'.");
  }
  nlohmann::json j;
  try {
    file >> j;
  } catch (const nlohmann::json::parse_error &e) {
    throw std::runtime_error("DhParametersLoader log | loadDhParameters(): "
                             "Failed to parse JSON file: " +
                             std::string(e.what()));
  }
  std::map<std::string, DhParametersLoader::DhParameters> paramsMap;
  if (j.contains("dh_parameters") && j["dh_parameters"].is_array()) {
    for (const auto &group : j["dh_parameters"]) {
      if (group.contains("name") && group.contains("p") &&
          group.contains("g")) {
        DhParametersLoader::DhParameters params;
        params._groupName = group["name"].get<std::string>();
        if (group["p"].is_array()) {
          std::string primeConcat;
          for (const auto &chunk : group["p"]) {
            primeConcat += chunk.get<std::string>();
          }
          params._pHex = primeConcat;
        } else {
          params._pHex = group["p"].get<std::string>();
        }
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
        std::cerr << "DhParametersLoader log | loadDhParameters(): "
                     "Warning: Skipping malformed DH group entry in JSON."
                  << std::endl;
      }
    }
  } else {
    throw std::runtime_error(
        "DhParametersLoader log | loadDhParameters(): "
        "JSON file does not contain a 'dh_parameters' array.");
  }
  return paramsMap;
}
