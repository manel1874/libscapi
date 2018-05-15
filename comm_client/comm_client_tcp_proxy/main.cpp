
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <iostream>
#include <string>

#include <log4cpp/Category.hh>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/SimpleLayout.hh>
#include <log4cpp/RollingFileAppender.hh>
#include <log4cpp/SimpleLayout.hh>
#include <log4cpp/BasicLayout.hh>
#include <log4cpp/PatternLayout.hh>

typedef struct __client
{
	unsigned int id;
	unsigned int count;
	std::string conf_file;

	__client()
	: id((unsigned int)-1), count((unsigned int)-1)
	{}
}client_t;

typedef struct __service
{
	std::string svc_ip;
	u_int16_t svc_port;

	__service()
	: svc_port((u_int16_t)-1)
	{}
}service_t;

typedef struct __log
{
	std::string file;
	std::string directory;
	size_t max_files;
	size_t max_size;
	int level;

	__log()
	: file("comm_client_tcp_proxy.log"), directory("./"), max_files(2), max_size(5*1024*1024), level(500)
	{}
}log_t;

void get_options(int argc, char *argv[], client_t & clnt, service_t & svc, log_t & log);
void show_usage(const char * prog);
void init_log(const log_t & log);
void serve(const service_t & svc, const client_t & clnt);

int main(int argc, char *argv[])
{
	client_t clnt;
	service_t svc;
	log_t log;
	get_options(argc, argv, clnt, svc, log);
	init_log(log);
	serve(svc, clnt);
	return 0;
}


void get_options(int argc, char *argv[], client_t & clnt, service_t & svc, log_t & log)
{
	if(argc == 1)
	{
		show_usage(argv[0]);
		exit(0);
	}
	int opt;
	while ((opt = getopt(argc, argv, "hi:c:f:a:p:x:d:s:z:l:")) != -1)
	{
		switch (opt)
		{
		case 'h':
			show_usage(argv[0]);
			exit(0);
		case 'i':
			clnt.id = (unsigned int)strtol(optarg, NULL, 10);
			break;
		case 'c':
			clnt.count = (unsigned int)strtol(optarg, NULL, 10);
			break;
		case 'f':
			clnt.conf_file = optarg;
			break;
		case 'a':
			svc.svc_ip = optarg;
			break;
		case 'p':
			svc.svc_port = (u_int16_t)strtol(optarg, NULL, 10);
			break;
		case 'x':
			log.file = optarg;
			break;
		case 'd':
			log.directory = optarg;
			break;
		case 's':
			log.max_files = (size_t)strtol(optarg, NULL, 10);
			break;
		case 'z':
			log.max_size = (size_t)strtol(optarg, NULL, 10);
			break;
		case 'l':
			log.level = (int)strtol(optarg, NULL, 10);
			break;
		default:
			std::cerr << "Invalid program arguments." << std::endl;
			show_usage(argv[0]);
			exit(__LINE__);
		}
	}
}

void show_usage(const char * prog)
{//hi:c:f:a:p:x:d:s:z:l:
	std::cout << "Usage:" << std::endl;
	std::cout << prog << "   [ OPTIONS ]" << std::endl;
	std::cout << "-i   client id" << std::endl;
	std::cout << "-c   peer count" << std::endl;
	std::cout << "-f   peer address file" << std::endl;
	std::cout << "-a   service address" << std::endl;
	std::cout << "-p   service port" << std::endl;
	std::cout << "-x   log file" << std::endl;
	std::cout << "-d   log location" << std::endl;
	std::cout << "-s   max log files" << std::endl;
	std::cout << "-z   max log size" << std::endl;
	std::cout << "-l   log level [fatal=0,alert=100,critical=200,error=300,warning=400,notice=500(default),info=600,debug=700]" << std::endl;
}

void init_log(const log_t & log)
{
	static const char the_layout[] = "%d{%y-%m-%d %H:%M:%S.%l}| %-6p | %-15c | %m%n";

	std::string log_file = log.file;
	log_file.insert(0, "/");
	log_file.insert(0, log.directory);

    log4cpp::Layout * log_layout = NULL;
    log4cpp::Appender * appender = new log4cpp::RollingFileAppender("lpm.appender", log_file.c_str(), log.max_size, log.max_files);

    bool pattern_layout = false;
    try
    {
        log_layout = new log4cpp::PatternLayout();
        ((log4cpp::PatternLayout *)log_layout)->setConversionPattern(the_layout);
        appender->setLayout(log_layout);
        pattern_layout = true;
    }
    catch(...)
    {
        pattern_layout = false;
    }

    if(!pattern_layout)
    {
        log_layout = new log4cpp::BasicLayout();
        appender->setLayout(log_layout);
    }

    log4cpp::Category::getInstance("drmn").addAppender(appender);
    log4cpp::Category::getInstance("drmn").setPriority((log4cpp::Priority::PriorityLevel)log.level);
    log4cpp::Category::getInstance("drmn").notice("dreamon log start");
}
