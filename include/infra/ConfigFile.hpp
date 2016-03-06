#pragma once

#include <string>
#include <map>

class ConfigFile {
	std::map<std::string, std::string> content_;

public:
	ConfigFile(std::string const& configFile);
	std::string const& Value(std::string const& section, std::string const& entry) const;
};

