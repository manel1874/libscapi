
#pragma once

class comm_client_cb_api
{
public:
	virtual void on_comm_up_with_party(const unsigned int party_id) = 0;
	virtual void on_comm_down_with_party(const unsigned int party_id) = 0;
	virtual void on_comm_message(const unsigned int src_id, const unsigned char * msg, const size_t size) = 0;
};
