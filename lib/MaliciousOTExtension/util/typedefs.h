#pragma once
#ifndef __TYPEDEFS_H__
#define __TYPEDEFS_H__

#include <time.h>
#include <assert.h>
namespace maliciousot {

#define MAXGATES 32000000

#define TWO_POW(e) (((uint64_t) 1) << (e))
	static int CEIL_LOG2(int bits)
	{
		if (bits == 1) return 1;
		int targetlevel = 0, bitstemp = bits;
		while (bitstemp >>= 1) ++targetlevel;
		return targetlevel + ((1 << targetlevel) < bits);
	}

	static int FLOOR_LOG2(int bits)
	{
		if (bits == 1) return 1;
		int targetlevel = 0;
		while (bits >>= 1) ++targetlevel;
		return targetlevel;
	}

	enum ROLE { SERVER, CLIENT, ALL };


	typedef int				BOOL;
	typedef long			LONG;

	typedef unsigned char	BYTE;
	typedef unsigned short USHORT;
	typedef unsigned int	UINT;
	typedef unsigned long ULONG;
	typedef BYTE 					UINT8_T;
	typedef USHORT 					UINT16_T;
	typedef UINT 					UINT32_T;
	typedef unsigned long long 	UINT64_T;
	typedef long long SINT64_T;


	typedef ULONG	DWORD;
	typedef UINT64_T UGATE_T;
	typedef UINT64_T REGISTER_SIZE;

#define GATE_T_BITS (sizeof(UGATE_T) * 8)

	typedef REGISTER_SIZE REGSIZE;
#define LOG2_REGISTER_SIZE		CEIL_LOG2(sizeof(REGISTER_SIZE) << 3)

#define FILL_BYTES				AES_BYTES
#define FILL_BITS				AES_BITS

#define OT_WINDOW_SIZE		(AES_BITS*4)
#define OT_WINDOW_SIZE_BYTES	(AES_BYTES*4)

#define MAX_REPLY_BITS			65536 //at most 2^16 bits may be sent in one go

#define RETRY_CONNECT		1000
#define CONNECT_TIMEO_MILISEC	10000


#define SNDVALS 2

#define OTEXT_BLOCK_SIZE_BITS	AES_BITS
#define OTEXT_BLOCK_SIZE_BYTES	AES_BYTES

#define VECTOR_INTERNAL_SIZE 8


#define			SERVER_ID	0
#define			CLIENT_ID	1



#define MAX_INT (~0)
#if (MAX_INT == 0xFFFFFFFF)
#define MACHINE_SIZE_32
#elif (MAX_INT == 0xFFFFFFFFFFFFFFFF)
#define MACHINE_SIZE_64
#else
#define MACHINE_SIZE_16
#endif

	template<class T>
	T rem(T a, T b) { return ((a) > 0) ? (a) % (b) : (a) % (b)+((b) > 0 ? (b) : (b)*-1); }
	template<class T>
	T sub(T a, T b, T m) { return ((b) > (a)) ? (a)+(m)-(b) : (a)-(b); }
#ifndef FALSE
#define FALSE			0
#endif
#ifndef TRUE
#define TRUE			1
#endif
#define ZERO_BYTE		0
#define MAX_BYTE		0xFF
#define MAX_UINT		0xFFFFFFFF

#define CEIL_DIVIDE(x, y)			(( ((x) + (y)-1)/(y)))

#define PadToRegisterSize(x) 		(PadToMultiple(x, OTEXT_BLOCK_SIZE_BITS))
#ifndef PadToMultiple
#define PadToMultiple(x, y) 		( CEIL_DIVIDE(x, y) * (y))
#endif
}

#ifdef WIN32
#include <WinSock2.h>
#include <windows.h>

	typedef unsigned short	USHORT;
	typedef int socklen_t;
#pragma comment(lib, "wsock32.lib")

#define SleepMiliSec(x)			Sleep(x)

#else //WIN32



#include <sys/types.h>       
#include <sys/socket.h>      
#include <netdb.h>           
#include <arpa/inet.h>       
#include <unistd.h>          
#include <netinet/in.h>   
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>


	typedef int SOCKET;
#define INVALID_SOCKET -1

#define SleepMiliSec(x)			usleep((x)<<10)
#endif// WIN32

#include <cstring>
#include <string>  
#include <vector> 
#include <iostream>


using namespace std;


#endif //__TYPEDEFS_H__




