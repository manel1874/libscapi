
#pragma once

class cct_proxy_service : public comm_client_cb_api
{
public:
	cct_proxy_service();
	virtual ~cct_proxy_service();

	virtual void on_comm_up_with_party(const unsigned int party_id);
	virtual void on_comm_down_with_party(const unsigned int party_id);
	virtual void on_message(const unsigned int src_id, const unsigned char * msg, const size_t size);
};
