
#pragma once

#include <semaphore.h>

class comm_client_cb_api;

class comm_client
{
protected:
	char m_syslog_name[32];
	virtual void set_syslog_name() = 0;

	void start_log();
	void stop_log();

	unsigned int m_id, m_peer_count;
	std::string m_comm_conf_file;
	comm_client_cb_api * m_sink;
	pthread_t m_runner;
	sem_t m_run_flag;

	virtual void run() = 0;
	int launch();

	bool get_run_flag();
	void set_run_flag(bool);

public:
	comm_client();
	virtual ~comm_client();

	virtual int start(const unsigned int id, const unsigned int peer_count, const char * comm_conf_file, comm_client_cb_api * sink);
	virtual void stop();

	virtual int send(const unsigned int dst_id, const unsigned char * msg, const size_t size) = 0;

	friend void * comm_client_proc(void * arg);
};
