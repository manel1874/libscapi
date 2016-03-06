#pragma once

#include <string>
#include <boost/move/utility.hpp>
//#include <boost/log/sources/logger.hpp>
//#include <boost/log/sources/record_ostream.hpp>
//#include <boost/log/sources/global_logger_storage.hpp>
//#include <boost/log/utility/setup/file.hpp>
//#include <boost/log/utility/setup/common_attributes.hpp>
//
//namespace logging = boost::log;
//namespace src = boost::log::sources;
//namespace keywords = boost::log::keywords;
//
//BOOST_LOG_INLINE_GLOBAL_LOGGER_DEFAULT(my_logger, src::logger_mt);

using namespace std;

class Logger {
public:
	static void configure_logging() {
		//logging::add_file_log("sample.log");
		//logging::add_common_attributes();
	};
	
	static void log(string message) {
		//cout << message << endl;
		//src::logger_mt& lg = my_logger::get();
		//BOOST_LOG(lg) << message;
	};
};
