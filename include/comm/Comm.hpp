#pragma once

#include "../infra/Common.hpp"


class TimeoutException : public logic_error
{
public:
	TimeoutException(const string & msg) : logic_error(msg) {};
	virtual char const * what() const throw() { return "Timeout Occured"; }
};

class DuplicatePartyException : public logic_error
{
public:
	DuplicatePartyException(const string & msg) : logic_error(msg) {};
	virtual char const * what() const throw() { return "Duplicate Party"; }
};

/**
* Represents a connection between two parties. Once a channel is open and the connection is established it can be used to send and receive messages over it.
* There are different types of channels and we use the Decorator Design Pattern to implement some of them.
*/
class Channel{
public:
	enum State {
		NOT_INIT,
		CONNECTING,
		SECURING,
		READY
	};

private:
	State state;

public:
	Channel() { state = State::NOT_INIT; };
	State getState() { return state; };
	void setState(State state) { this->state = state; };
	virtual bool connect() =0;
	virtual bool isConnected()=0;
	virtual void send(Message & message)=0;
	virtual Message receive() = 0;
	virtual void close() = 0;
	virtual bool isClosed() = 0;
};


