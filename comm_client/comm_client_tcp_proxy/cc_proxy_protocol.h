
#pragma once

#pragma pack(push,4)

typedef struct
{
	u_int32_t proxy_id;
	u_int32_t peer_count;

	void ntoh()
	{
		proxy_id = (u_int32_t)ntohl(proxy_id);
		peer_count = (u_int32_t)ntohl(peer_count);
	}
	void hton()
	{
		proxy_id = (u_int32_t)htonl(proxy_id);
		peer_count = (u_int32_t)htonl(peer_count);
	}
}client_details_msg_t;

typedef struct
{
	u_int32_t peer_id;
	u_int32_t connected;

	void ntoh()
	{
		peer_id = (u_int32_t)ntohl(peer_id);
		connected = (u_int32_t)ntohl(connected);
	}
	void hton()
	{
		peer_id = (u_int32_t)htonl(peer_id);
		connected = (u_int32_t)htonl(connected);
	}
}peer_comm_update_t;

typedef struct
{
	u_int32_t peer_id;
	u_int32_t size;

	void ntoh()
	{
		peer_id = (u_int32_t)ntohl(peer_id);
		size = (u_int32_t)ntohl(size);
	}
	void hton()
	{
		peer_id = (u_int32_t)htonl(peer_id);
		size = (u_int32_t)htonl(size);
	}
}peer_msg_t;

#pragma pack(pop)
