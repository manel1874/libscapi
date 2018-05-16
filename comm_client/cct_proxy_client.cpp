
#include <stdlib.h>
#include <semaphore.h>
#include <memory.h>
#include <syslog.h>

#include <string>

#include <event2/event.h>

#include "comm_client.h"
#include "cct_proxy_client.h"

cct_proxy_client::cct_proxy_client(const char * proxy_addr, const u_int16_t proxy_port)
: m_proxy_addr(proxy_addr), m_proxy_port(proxy_port), m_peer_mask(NULL), m_mask_size(0)
, m_base(NULL), m_read(NULL), m_write(NULL)
{
}

cct_proxy_client::~cct_proxy_client()
{
}

int cct_proxy_client::start(const unsigned int id, const unsigned int peer_count, const char * comm_conf_file, comm_client_cb_api * sink)
{
	m_mask_size = (peer_count + 7) / 8;
	m_peer_mask = new u_int8_t[m_mask_size];
	memset(m_peer_mask, 0, m_mask_size);

	return comm_client::start(id, peer_count, comm_conf_file, sink);
}

void cct_proxy_client::stop()
{
	comm_client::stop();

	delete m_peer_mask;
	m_peer_mask = NULL;
	m_mask_size = 0;
}

void cct_proxy_client::run()
{
	m_base = event_base_new();
	if(NULL != m_base)
	{
		m_read = event_new(m_base, -1, EV_TIMEOUT, connect_cb, this);
		if(NULL != m_read)
		{
			//add connect event

				//prep pipe

					//prep write event

						//prep timer exit event

							//run loop

						//release timer exit event

					//release write event

				//close pipe

			//del connect event

			event_free(m_read);
		}
		else
			syslog(LOG_ERR, "%s: connect event allocation failed.", __FUNCTION__);
		event_base_free(m_base);
		m_base = NULL;
	}
	else
		syslog(LOG_ERR, "%s: event base allocation failed.", __FUNCTION__);
}
