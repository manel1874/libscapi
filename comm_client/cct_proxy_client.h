
#pragma once

class cct_proxy_client : public comm_client
{
	std::string m_proxy_addr;
	u_int16_t m_proxy_port;
	int out_pipe[2];
	u_int8_t * m_peer_mask;
	size_t m_mask_size;
	struct event_base * m_base;
	struct event * m_read, * m_write;

	void run();

	static void connect_cb(evutil_socket_t fd, short what, void * arg);

	void on_connect();

public:
	cct_proxy_client(const char * proxy_addr, const u_int16_t proxy_port);
	virtual ~cct_proxy_client();

	int start(const unsigned int id, const unsigned int peer_count, const char * comm_conf_file, comm_client_cb_api * sink);
	void stop();

	int send(const unsigned int dst_id, const unsigned char * msg, const size_t size);
};
