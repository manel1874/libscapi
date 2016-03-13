#include <boost/multiprecision/miller_rabin.hpp>
#include "../../include/infra/Common.hpp"
#include <chrono>
#include <boost/multiprecision/cpp_dec_float.hpp>

/******************************/
/* Helper Methods *************/
/******************************/

int find_log2_floor(biginteger bi) {
	if (bi < 0)
		throw runtime_error("log for negative number is not supported");
	int r = 0;
	while (bi >>= 1) // unroll for more speed...
		r++;
	return r;
}

int NumberOfBits(const biginteger bi) {
	auto bis = (bi>0) ? bi : -bi;
	return find_log2_floor(bis)+ 1;
}

void gen_random_bytes_vector(vector<byte> &v, const int len, mt19937 random) {
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) 
		v.push_back(alphanum[random() % (sizeof(alphanum) - 1)]);
}

/**
* Copies all byte from source vector to dest starting from some index in dest.
* Assuming dest is already initialized.
*/
void copy_byte_vector_to_byte_array(const vector<byte> &source_vector, byte * dest, int beginIndex) {
	for (auto it = source_vector.begin(); it != source_vector.end(); ++it) {
		int index = std::distance(source_vector.begin(), it) + beginIndex;
		dest[index] = *it;
	}
}

void copy_byte_array_to_byte_vector(const byte* src, int src_len, vector<byte>& target_vector, int beginIndex)
{
	target_vector.insert(target_vector.end(), &src[beginIndex], &src[src_len]);
}

/*
* Length of biginteger in bytes
*/
size_t bytesCount(biginteger value)
{
	if (value.is_zero())
		return 1;
	if (value.sign() < 0)
		value = ~value;
	size_t length = 0;
	byte lastByte;
	do {
		lastByte = value.convert_to<byte>();
		value >>= 8;
		length++;
	} while (!value.is_zero());
	if (lastByte >= 0x80)
		length++;
	return length;
}

void encodeBigInteger(biginteger value, byte* output, size_t length)
{
	if (value.is_zero())
		*output = 0;
	else if (value.sign() > 0)
		while (length-- > 0) {
			*(output++) = value.convert_to<byte>();
			value >>= 8;
		}
	else {
		value = ~value;
		while (length-- > 0) {
			*(output++) = ~value.convert_to<byte>();
			value >>= 8;
		}
	}
}

biginteger decodeBigInteger(byte* input, size_t length)
{
	biginteger result(0);
	int bits = -8;
	while (length-- > 1)
		result |= (biginteger) *(input++) << (bits += 8);
	byte a = *(input++);
	result |= (biginteger) a << (bits += 8);
	if (a >= 0x80)
		result |= (biginteger) - 1 << (bits + 8);
	return result;
}

biginteger convert_hex_to_biginteger(const string & input) {
	string s = "0x" + input;
	return boost::lexical_cast<biginteger>(s);
}

string hexStr(vector<byte> const & data)
{
	string res;
	boost::algorithm::hex(data.begin(), data.end(), back_inserter(res));
	boost::algorithm::to_lower(res);
	return res;
}

mt19937 get_seeded_random() {
	mt19937 mt;
	auto seed = chrono::high_resolution_clock::now().time_since_epoch().count();
	mt.seed(seed);
	return mt;
}

mt19937_64 get_seeded_random64() {
	mt19937_64 mt;
	auto seed = chrono::high_resolution_clock::now().time_since_epoch().count();
	mt.seed(seed);
	return mt;
}

void print_elapsed_ms(std::chrono::time_point<std::chrono::system_clock> start, string message) {
	auto end = std::chrono::system_clock::now();
	int elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	cout << message << " took: " << elapsed_ms << " ms" << endl;
}

void print_elapsed_micros(std::chrono::time_point<std::chrono::system_clock> start, string message) {
	auto end = std::chrono::system_clock::now();
	int elapsed_ms = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	cout << message << " took: " << elapsed_ms << " microsseconds" << endl;
}

std::chrono::time_point<std::chrono::system_clock> scapi_now() {
	return chrono::system_clock::now();
}

biginteger getRandomInRange(biginteger min, biginteger max, std::mt19937 random)
{
	boost::random::uniform_int_distribution<biginteger> ui(min, max);
	biginteger res = ui(random);
	return res;
}

void print_byte_array(byte * arr, int len, string message)
{
	cout << message << endl;
	for (int i = 0; i < len; i++)
		cout << (int)arr[i] << ",";
	cout << endl;
}

bool isPrime(biginteger bi) {
	auto prg = get_seeded_random();
	return (miller_rabin_test(bi, 40, prg));
}