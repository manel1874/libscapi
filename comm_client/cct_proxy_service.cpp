
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <semaphore.h>

#include <string>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <log4cpp/Category.hh>
#include <event2/event.h>

#include "comm_client_cb_api.h"
#include "cct_proxy_service.h"
#include "cc_proxy_protocol.h"
#include "comm_client.h"
#include "comm_client_tcp_mesh.h"

#define PPRDFD	0
#define PPWRFD	1

static const struct timeval minute = {60,0};

cct_proxy_service::cct_proxy_service(const char * logcat)
: m_base(NULL), m_tcp(NULL), m_svc_sock(-1), m_conn_sock(-1), m_cat(logcat), m_cc(NULL), m_conn_rd(NULL), m_conn_wr(NULL)
{
	m_cat += ".prx";
	m_conn_pipe[PPRDFD] = -1;
	m_conn_pipe[PPWRFD] = -1;
}

cct_proxy_service::~cct_proxy_service()
{
}

int cct_proxy_service::serve(const service_t & a_svc, const client_t & a_clnt)
{
	log4cpp::Category::getInstance(m_cat).notice("%s: proxy service started.", __FUNCTION__);

	m_svc = a_svc;
	m_clnt = a_clnt;

	m_base = event_base_new();
	if(NULL != m_base)
	{
		struct event * sigint_event = evsignal_new(m_base, 2/*=SIGINT*/, sigint_cb, this);
		if(NULL != sigint_event)
		{
			if(0 == event_add(sigint_event, NULL))
			{
				if(0 == start_tcp_svc())
				{
					//allocate the TCP accept handler
					m_tcp = event_new(m_base, m_svc_sock, EV_READ|EV_TIMEOUT|EV_PERSIST, cct_proxy_service::accept_cb, this);
					if(NULL != m_tcp)
					{
						if(0 == event_add(m_tcp, &minute))
						{
							log4cpp::Category::getInstance(m_cat).info("%s: Running event loop.", __FUNCTION__);
							event_base_dispatch(m_base);

							event_del(m_tcp);
						}
						else
							log4cpp::Category::getInstance(m_cat).error("%s: proxy service tcp event addition failed.", __FUNCTION__);

						event_free(m_tcp);
						m_tcp = NULL;
					}
					else
						log4cpp::Category::getInstance(m_cat).error("%s: proxy service tcp event allocation failed.", __FUNCTION__);

					close(m_svc_sock);
					m_svc_sock = -1;
				}
				else
					log4cpp::Category::getInstance(m_cat).error("%s: proxy service tcp service start failed.", __FUNCTION__);
				event_del(sigint_event);
			}
			else
				log4cpp::Category::getInstance(m_cat).error("%s: proxy service sigint event addition failed.", __FUNCTION__);
			event_free(sigint_event);
			sigint_event = NULL;
		}
		else
			log4cpp::Category::getInstance(m_cat).error("%s: proxy service sigint event allocation failed.", __FUNCTION__);

		event_base_free(m_base);
		m_base = NULL;
	}
	else
		log4cpp::Category::getInstance(m_cat).error("%s: proxy service event base allocation failed.", __FUNCTION__);

	log4cpp::Category::getInstance(m_cat).notice("%s: proxy service stopped.", __FUNCTION__);
}

int cct_proxy_service::start_tcp_svc()
{
	if (0 > (m_svc_sock = socket(AF_INET, SOCK_STREAM, 0)))
    {
        int errcode = errno;
        char errmsg[256];
        log4cpp::Category::getInstance(m_cat).error("%s: socket() failed with error %d : [%s].",
        		__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
        return -1;
    }
	else
		 log4cpp::Category::getInstance(m_cat).debug("%s: socket fd %d created.", __FUNCTION__, m_svc_sock);

	struct sockaddr_in service_address;
	if (inet_aton(m_svc.ip.c_str(), &service_address.sin_addr) == 0)
    {
		log4cpp::Category::getInstance(m_cat).error("%s: invalid service address [%s].", __FUNCTION__, m_svc.ip.c_str());
		close(m_svc_sock); m_svc_sock = -1;
        return -1;
    }
	service_address.sin_port = htons(m_svc.port);
	service_address.sin_family = AF_INET;

	if (0 != bind(m_svc_sock, (const sockaddr *)&service_address, (socklen_t)sizeof(struct sockaddr_in)))
	{
        int errcode = errno;
        char errmsg[256];
        log4cpp::Category::getInstance(m_cat).error("%s: bind() to [%s:%hu] failed with error %d : [%s].",
        		__FUNCTION__, m_svc.ip.c_str(), m_svc.port, errcode, strerror_r(errcode, errmsg, 256));
		close(m_svc_sock); m_svc_sock = -1;
        return -1;
	}
	else
		 log4cpp::Category::getInstance(m_cat).debug("%s: socket fd %d bound to [%s:%hu].", __FUNCTION__, m_svc_sock, m_svc.ip.c_str(), m_svc.port);

	if (0 != listen(m_svc_sock, 1))
	{
        int errcode = errno;
        char errmsg[256];
        log4cpp::Category::getInstance(m_cat).error("%s: listen() on [%s:%hu] failed with error %d : [%s].",
        		__FUNCTION__, m_svc.ip.c_str(), m_svc.port, errcode, strerror_r(errcode, errmsg, 256));
		close(m_svc_sock); m_svc_sock = -1;
        return -1;
	}
	else
		 log4cpp::Category::getInstance(m_cat).debug("%s: listening with socket fd %d on [%s:%hu].", __FUNCTION__, m_svc_sock, m_svc.ip.c_str(), m_svc.port);

	return 0;
}

void cct_proxy_service::on_sigint()
{
	log4cpp::Category::getInstance(m_cat).info("%s: Breaking event loop.", __FUNCTION__);
	event_base_loopbreak(m_base);
}

void cct_proxy_service::on_accept()
{
    struct sockaddr_in conn_addr;
    socklen_t conn_addr_size = sizeof(struct sockaddr_in);
    m_conn_sock = accept(m_svc_sock, (struct sockaddr *)&conn_addr, &conn_addr_size);
    if(0 <= m_conn_sock)
    {
    	char address[64];
    	log4cpp::Category::getInstance(m_cat).notice("%s: accepted a new connection: FD=%d from [%s:%hu].",
    			__FUNCTION__, m_conn_sock, inet_ntop(AF_INET, &conn_addr.sin_addr, address, 64), ntohs(conn_addr.sin_port));

    	if(0 == pipe(m_conn_pipe))
    	{
    		log4cpp::Category::getInstance(m_cat).debug("%s: proxy client conn pipe is open.", __FUNCTION__);
    		m_conn_data.clear();
    		m_conn_wr = event_new(m_base, m_conn_pipe[PPRDFD], EV_READ, connwr1_cb, this);
			if(NULL != m_conn_wr)
    		{
				if(0 == event_add(m_conn_wr, NULL))
				{
		    		log4cpp::Category::getInstance(m_cat).debug("%s: proxy client conn write event added.", __FUNCTION__);
					m_conn_rd = event_new(m_base, m_conn_sock, EV_READ|EV_PERSIST, connrd_cb, this);
					if(NULL != m_conn_rd)
					{
						if(0 == event_add(m_conn_rd, NULL))
						{
				    		log4cpp::Category::getInstance(m_cat).debug("%s: proxy client conn read event added.", __FUNCTION__);
							client_details_msg_t cdm;
							cdm.proxy_id = m_clnt.id;
							cdm.peer_count = m_clnt.count;
							cdm.hton();
							ssize_t nwrit = write(m_conn_pipe[PPWRFD], &cdm, sizeof(client_details_msg_t));
							if((ssize_t)sizeof(client_details_msg_t) == nwrit)
							{
					    		log4cpp::Category::getInstance(m_cat).debug("%s: proxy client details written to conn.", __FUNCTION__);
								m_cc = new comm_client_tcp_mesh;
								if(0 == m_cc->start(m_clnt.id, m_clnt.count, m_clnt.conf_file.c_str(), this))
								{
									event_del(m_tcp);
									log4cpp::Category::getInstance(m_cat).notice("%s: proxy client is connected and running.", __FUNCTION__);
								}
								else
									log4cpp::Category::getInstance(m_cat).error("%s: comm client start failed.", __FUNCTION__);
								delete m_cc;
							}
							else
								log4cpp::Category::getInstance(m_cat).error("%s: client details write failed.", __FUNCTION__);
							event_del(m_conn_rd);
						}
						else
							log4cpp::Category::getInstance(m_cat).error("%s: conn-read event addition failed.", __FUNCTION__);
						event_free(m_conn_rd);
						m_conn_rd = NULL;
					}
					else
						log4cpp::Category::getInstance(m_cat).error("%s: conn-read event allocation failed.", __FUNCTION__);
					event_del(m_conn_wr);
				}
				else
					log4cpp::Category::getInstance(m_cat).error("%s: conn-write event addition failed.", __FUNCTION__);
				event_free(m_conn_wr);
				m_conn_wr = NULL;
    		}
			else
				log4cpp::Category::getInstance(m_cat).error("%s: conn-write event allocation failed.", __FUNCTION__);
    		close(m_conn_pipe[PPRDFD]);
    		m_conn_pipe[PPRDFD] = -1;
    		close(m_conn_pipe[PPWRFD]);
    		m_conn_pipe[PPWRFD] = -1;
    	}
    	else
    	{
            int errcode = errno;
            char errmsg[256];
            log4cpp::Category::getInstance(m_cat).error("%s: pipe() failed with error %d : [%s].",
            		__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
    	}
    	close(m_conn_sock);
    	m_conn_sock = -1;
    }
    else
    {
        int errcode = errno;
        char errmsg[256];
        log4cpp::Category::getInstance(m_cat).error("%s: accept() failed with error %d : [%s].",
        		__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
    }
    //accept event still pending
}

void cct_proxy_service::on_accept_timeout()
{
	log4cpp::Category::getInstance(m_cat).info("%s: accept timed out waiting for an incoming connection.", __FUNCTION__);
}

void cct_proxy_service::on_connwr1()
{
	event_free(m_conn_wr);
	m_conn_wr = event_new(m_base, m_conn_sock, EV_WRITE, connwr2_cb, this);
	if(0 != event_add(m_conn_wr, NULL))
	{
        log4cpp::Category::getInstance(m_cat).fatal("%s: conn write 2 event add failed.", __FUNCTION__);
        exit(-__LINE__);
	}
}

void cct_proxy_service::on_connwr2()
{
	event_free(m_conn_wr);
	int result = splice(m_conn_pipe[PPRDFD], NULL, m_conn_sock, NULL, 4096, 0);
	if(0 > result)
	{
		int errcode = errno;
		char errmsg[512];
        log4cpp::Category::getInstance(m_cat).fatal("%s: splice() failed with error %d : [%s].",
        		__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
        exit(-__LINE__);
	}
	else
		log4cpp::Category::getInstance(m_cat).debug("%s: %d bytes spliced out to conn.", __FUNCTION__, result);

	m_conn_wr = event_new(m_base, m_conn_pipe[PPRDFD], EV_READ, connwr1_cb, this);
	if(0 != event_add(m_conn_wr, NULL))
	{
        log4cpp::Category::getInstance(m_cat).fatal("%s: conn write 1 event add failed.", __FUNCTION__);
        exit(-__LINE__);
	}
}

void cct_proxy_service::on_connrd()
{
	u_int8_t buffer[4096];
	ssize_t nread = read(m_conn_sock, buffer, 4096);
	if(0 < nread)
	{
		m_conn_data.insert(m_conn_data.end(), buffer, buffer + nread);
		process_conn_msgs();
		return;
	}
	else if(0 == nread)
		log4cpp::Category::getInstance(m_cat).notice("%s: read 0 bytes; disconnection.", __FUNCTION__);
	else
	{
		int errcode = errno;
		char errmsg[512];
        log4cpp::Category::getInstance(m_cat).error("%s: read() failed with error %d : [%s].",
        		__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
	}
	//disconnect conn
	m_cc->stop();
	delete m_cc;
	m_cc = NULL;

	event_del(m_conn_rd);
	event_free(m_conn_rd);
	m_conn_rd = NULL;

	event_del(m_conn_wr);
	event_free(m_conn_wr);
	m_conn_wr = NULL;

	close(m_conn_pipe[PPRDFD]);
	m_conn_pipe[PPRDFD] = -1;
	close(m_conn_pipe[PPWRFD]);
	m_conn_pipe[PPWRFD] = -1;

	close(m_conn_sock);
	m_conn_sock = -1;

	m_conn_data.clear();

	if(0 != event_add(m_tcp, &minute))
	{
        log4cpp::Category::getInstance(m_cat).fatal("%s: accept event add failed.", __FUNCTION__);
        exit(-__LINE__);
	}
}

void cct_proxy_service::on_comm_up_with_party(const unsigned int party_id)
{
	update_peer_comm(party_id, 1);
}

void cct_proxy_service::on_comm_down_with_party(const unsigned int party_id)
{
	update_peer_comm(party_id, 0);
}

void cct_proxy_service::on_comm_message(const unsigned int src_id, const unsigned char * msg, const size_t size)
{
	peer_msg_t msghdr;
	msghdr.peer_id = src_id;
	msghdr.size = size;
	msghdr.hton();

	struct iovec iov[2];
	iov[0].iov_base = &msghdr;
	iov[0].iov_len = sizeof(peer_msg_t);
	iov[1].iov_base = (void *)msg;
	iov[1].iov_len = size;

	ssize_t nwrit = writev(m_conn_pipe[PPWRFD], iov, 2);
	if((ssize_t)(sizeof(peer_msg_t) + size) != nwrit)
	{
		if(0 > nwrit)
		{
			int errcode = errno;
			char errmsg[512];
	        log4cpp::Category::getInstance(m_cat).fatal("%s: writev() failed with error %d : [%s].",
	        		__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
	        exit(-__LINE__);
		}
		else
		{
	        log4cpp::Category::getInstance(m_cat).fatal("%s: writev() partial write of %lu out of %lu.", __FUNCTION__, (size_t)nwrit, (sizeof(peer_msg_t) + size));
	        exit(-__LINE__);
		}
	}
	else
		log4cpp::Category::getInstance(m_cat).debug("%s: %d bytes written to conn pipe.", __FUNCTION__, (size_t)nwrit);
}

void cct_proxy_service::update_peer_comm(const unsigned int party_id, const unsigned int connected)
{
	peer_comm_update_t pcu;
	pcu.peer_id = party_id;
	pcu.connected = connected;
	pcu.hton();
	ssize_t nwrit = write(m_conn_pipe[PPWRFD], &pcu, sizeof(peer_comm_update_t));
	if((ssize_t)sizeof(peer_comm_update_t) != nwrit)
	{
		if(0 > nwrit)
		{
	        int errcode = errno;
	        char errmsg[256];
	        log4cpp::Category::getInstance(m_cat).error("%s: write() failed with error %d : [%s].",
	        		__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
		}
		else
			log4cpp::Category::getInstance(m_cat).error("%s: peer comm update written %lu out of %lu bytes.", __FUNCTION__, (size_t)nwrit, sizeof(peer_comm_update_t));
	}
}

void cct_proxy_service::process_conn_msgs()
{
	while(!m_conn_data.empty())
	{
		size_t data_size = m_conn_data.size();
		if(sizeof(peer_msg_t) > data_size)
			break;

		peer_msg_t hdr = *((peer_msg_t *)m_conn_data.data());
		hdr.ntoh();
		if((sizeof(peer_msg_t) + hdr.size) > data_size)
			break;

		if(0 != m_cc->send(hdr.peer_id, m_conn_data.data() + sizeof(peer_msg_t), hdr.size))
		{
	        log4cpp::Category::getInstance(m_cat).fatal("%s: comm client send() failed.", __FUNCTION__);
	        exit(-__LINE__);
		}
		m_conn_data.erase(m_conn_data.begin(), m_conn_data.begin() + (sizeof(peer_msg_t) + hdr.size));
	}
}

void cct_proxy_service::sigint_cb(evutil_socket_t fd, short what, void * arg)
{
	((cct_proxy_service *)arg)->on_sigint();
}

void cct_proxy_service::accept_cb(evutil_socket_t fd, short what, void * arg)
{
	if(0 != (EV_READ & what))
		((cct_proxy_service *)arg)->on_accept();
	else
		((cct_proxy_service *)arg)->on_accept_timeout();
}

void cct_proxy_service::connwr1_cb(evutil_socket_t fd, short what, void * arg)
{
	((cct_proxy_service *)arg)->on_connwr1();
}

void cct_proxy_service::connwr2_cb(evutil_socket_t fd, short what, void * arg)
{
	((cct_proxy_service *)arg)->on_connwr2();
}

void cct_proxy_service::connrd_cb(evutil_socket_t fd, short what, void * arg)
{
	((cct_proxy_service *)arg)->on_connrd();
}
