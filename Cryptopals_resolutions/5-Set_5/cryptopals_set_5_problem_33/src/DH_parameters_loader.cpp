#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>

#include "./../include/DH_parameters_loader.hpp"

std::map<std::string, DHParametersLoader::DHParameters>
DHParametersLoader::loadDhParameters(const std::string &filename) {
  std::ifstream file(filename);
  if (!file.is_open()) {
    throw std::runtime_error("DHParametersLoader log | loadDhParameters(): "
                             "Could not open DH parameters file: " +
                             filename);
  }
  nlohmann::json j;
  try {
    file >> j;
  } catch (const nlohmann::json::parse_error &e) {
    throw std::runtime_error("DHParametersLoader log | loadDhParameters(): "
                             "Failed to parse JSON file: " +
                             std::string(e.what()));
  }
  std::map<std::string, DHParametersLoader::DHParameters> paramsMap;
  if (j.contains("dh_parameters") && j["dh_parameters"].is_array()) {
    for (const auto &group : j["dh_parameters"]) {
      if (group.contains("name") && group.contains("p") &&
          group.contains("g")) {
        DHParametersLoader::DHParameters params;
        params.groupName = group["name"].get<std::string>();
        params.pHex = group["p"].get<std::string>();
        params.gHex = group["g"].get<std::string>();
        // Optional fields
        if (group.contains("description")) {
          params.description = group["description"].get<std::string>();
        }
        if (group.contains("notes")) {
          params.notes = group["notes"].get<std::string>();
        }
        paramsMap[group["name"].get<std::string>()] = params;
      } else {
        std::cerr << "DHParametersLoader log | loadDhParameters(): "
                     "Warning: Skipping malformed DH group entry in JSON."
                  << std::endl;
      }
    }
  } else {
    throw std::runtime_error(
        "DHParametersLoader log | loadDhParameters(): "
        "JSON file does not contain a 'dh_parameters' array.");
  }
  return paramsMap;
}
