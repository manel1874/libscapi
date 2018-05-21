
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <semaphore.h>

#include "protocol_barrier.h"

protocol_barrier::protocol_barrier()
{
	if(0 != sem_init(&m_barrier, 0, 0))
	{
        int errcode = errno;
        char errmsg[256];
        syslog(LOG_ERR, "%s: sem_init() failed with error %d : [%s].",
        		__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
        exit(__LINE__);
	}
}

protocol_barrier::~protocol_barrier()
{
	if(0 != sem_destroy(&m_barrier))
	{
        int errcode = errno;
        char errmsg[256];
        syslog(LOG_ERR, "%s: sem_init() failed with error %d : [%s].",
        		__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
        exit(__LINE__);
	}
}

int protocol_barrier::run(const size_t parties, const size_t rounds, const struct timeval * round_timeouts)
{
	for(size_t i = 0; i < rounds; ++i)
	{
		if(0 != pre_round(i))
		{
			syslog(LOG_ERR, "%s: error running pre-round %lu.", __FUNCTION__, i);
			return -1;
		}

		if(0 != on_round(i))
		{
			syslog(LOG_ERR, "%s: error running on-round %lu.", __FUNCTION__, i);
			return -1;
		}

		bool set_round_timeout = (NULL != round_timeouts && (0 != round_timeouts[i].tv_sec || 0 != round_timeouts[i].tv_usec));
		if(set_round_timeout)
		{
			struct timespec round_timeout;
			clock_gettime(CLOCK_REALTIME, &round_timeout);
			round_timeout.tv_nsec += (round_timeouts[i].tv_usec * 1000);
			round_timeout.tv_sec += ( (round_timeout.tv_nsec/1000000000) + round_timeouts[i].tv_sec);
			round_timeout.tv_nsec = round_timeout.tv_nsec%1000000000;

			for(size_t j = 0; j < parties; ++j)
			{
				if(0 != sem_timedwait(&m_barrier, &round_timeout))
				{
			        int errcode = errno;
			        char errmsg[256];
			        syslog(LOG_ERR, "%s: sem_timedwait() failed with error %d : [%s].",
			        		__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
			        return -1;
				}
			}
		}
		else
		{
			for(size_t j = 0; j < parties; ++j)
			{
				if(0 != sem_wait(&m_barrier))
				{
			        int errcode = errno;
			        char errmsg[256];
			        syslog(LOG_ERR, "%s: sem_wait() failed with error %d : [%s].",
			        		__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
			        return -1;
				}
			}
		}

		if(0 != post_round(i))
		{
			syslog(LOG_ERR, "%s: error running post-round %lu.", __FUNCTION__, i);
			return -1;
		}
	}
	return 0;
}

void protocol_barrier::on_party_round_done(const size_t party_id)
{
	if(0 != sem_post(&m_barrier))
	{
        int errcode = errno;
        char errmsg[256];
        syslog(LOG_ERR, "%s: sem_post() failed with error %d : [%s].",
        		__FUNCTION__, errcode, strerror_r(errcode, errmsg, 256));
        exit(__LINE__);
	}
}
