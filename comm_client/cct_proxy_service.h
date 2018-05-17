
#pragma once

class comm_client;

class cct_proxy_service : public comm_client_cb_api
{
	char m_syslog_name[32];
public:
	cct_proxy_service();
	virtual ~cct_proxy_service();

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
		std::string ip;
		u_int16_t port;

		__service()
		: port((u_int16_t)-1)
		{}
	}service_t;

	//comm_client_cb_api
	virtual void on_comm_up_with_party(const unsigned int party_id);
	virtual void on_comm_down_with_party(const unsigned int party_id);
	virtual void on_comm_message(const unsigned int src_id, const unsigned char * msg, const size_t size);

	int serve(const service_t & a_svc, const client_t & a_clnt);

	static void sigint_cb(evutil_socket_t fd, short what, void * arg);
	static void accept_cb(evutil_socket_t fd, short what, void * arg);
	static void connwr1_cb(evutil_socket_t fd, short what, void * arg);
	static void connwr2_cb(evutil_socket_t fd, short what, void * arg);
	static void connrd_cb(evutil_socket_t fd, short what, void * arg);

private:
	service_t m_svc;
	client_t m_clnt;
	struct event_base * m_base;
	struct event * m_tcp;
	int m_svc_sock;
	int m_conn_sock;
	int m_conn_pipe[2];
	std::vector<u_int8_t> m_conn_data;
	struct event * m_conn_rd, * m_conn_wr;
	comm_client * m_cc;

	int start_tcp_svc();
	void update_peer_comm(const unsigned int party_id, const unsigned int connected);
	void process_conn_msgs();

	void on_sigint();
	void on_accept();
	void on_accept_timeout();
	void on_connwr1();
	void on_connwr2();
	void on_connrd();
};
