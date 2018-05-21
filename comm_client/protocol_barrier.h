
#pragma once

class comm_client;

class protocol_barrier
{
	sem_t m_barrier;

protected:
	void on_party_round_done(const size_t party_id);

	virtual int run(const size_t parties, const size_t rounds, const struct timeval * round_timeouts = NULL);

	virtual int pre_round(const size_t round) = 0;
	virtual int on_round(const size_t round) = 0;
	virtual int post_round(const size_t round) = 0;
public:
	protocol_barrier();
	virtual ~protocol_barrier();
};
