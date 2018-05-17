
#pragma once

#pragma pack(push,4)

#define MSG_TYPE_CDM	1
#define MSG_TYPE_PCU	2
#define MSG_TYPE_PMS	3

typedef struct
{
	u_int32_t type;
	u_int32_t id;
	u_int32_t param;

	void ntoh()
	{
		type = (u_int32_t)ntohl(type);
		id = (u_int32_t)ntohl(id);
		param = (u_int32_t)ntohl(param);
	}
	void hton()
	{
		type = (u_int32_t)htonl(type);
		id = (u_int32_t)htonl(id);
		param = (u_int32_t)htonl(param);
	}
}proxy_msg_t;

#pragma pack(pop)
