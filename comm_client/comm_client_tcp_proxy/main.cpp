
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <iostream>
#include <string>
#include <vector>

#include <event2/event.h>

#include "comm_client_cb_api.h"
#include "cct_proxy_service.h"

void get_options(int argc, char *argv[], cct_proxy_service::client_t & clnt, cct_proxy_service::service_t & svc);
void show_usage(const char * prog);

int main(int argc, char *argv[])
{
	cct_proxy_service::client_t clnt;
	cct_proxy_service::service_t svc;
	get_options(argc, argv, clnt, svc);

	cct_proxy_service proxy;
	proxy.serve(svc, clnt);

	return 0;
}


void get_options(int argc, char *argv[], cct_proxy_service::client_t & clnt, cct_proxy_service::service_t & svc)
{
	if(argc == 1)
	{
		show_usage(argv[0]);
		exit(0);
	}
	int opt;
	while ((opt = getopt(argc, argv, "hi:c:f:a:p:")) != -1)
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
			svc.ip = optarg;
			break;
		case 'p':
			svc.port = (u_int16_t)strtol(optarg, NULL, 10);
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
}
