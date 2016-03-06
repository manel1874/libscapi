#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>

class Message
{
public:
	enum { header_length = 8 };
	enum { max_body_length = 3000000};

	Message()
		: body_length_(0), data_(header_length + max_body_length)
	{}

	const char* data() const
	{
		return &(data_[0]);
	}

	char* data()
	{
		return &(data_[0]);
	}

	size_t length() const
	{
		return header_length + body_length_;
	}

	const char* body() const
	{
		return &data_[0] + header_length;
	}

	char* body()
	{
		return &data_[header_length];
	}

	size_t body_length() const
	{
		return body_length_;
	}

	void body_length(size_t length)
	{
		body_length_ = length;
		if (body_length_ > max_body_length)
			body_length_ = max_body_length;
	}

	bool decode_header()
	{
		using namespace std; // For strncat and atoi.
		char header[header_length + 1] = "";
		strncat(header, &data_[0], header_length);
		body_length_ = atoi(header);
		if (body_length_ > max_body_length)
		{
			body_length_ = 0;
			return false;
		}
		return true;
	}

	void encode_header()
	{
		using namespace std; // For sprintf and memcpy.
		char header[header_length + 1] = "";
		sprintf(header, "%4d", (int) body_length_);
		memcpy(&data_[0], header, header_length);
	}

private:
	int vector_size = header_length + max_body_length;
	std::vector<char> data_;
	//char data_[header_length + max_body_length];
	size_t body_length_;
};