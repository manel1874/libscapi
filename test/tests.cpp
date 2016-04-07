#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file

#include "../include/infra/Common.hpp"
#include "../include/infra/ConfigFile.hpp"
#include "catch.hpp"
#include "../include/primitives/Dlog.hpp"
#include "../include/primitives/DlogOpenSSL.hpp"
#include "../include/primitives/HashOpenSSL.hpp"
#include "../include/primitives/PrfOpenSSL.hpp"
#include "../include/primitives/TrapdoorPermutationOpenSSL.hpp"
#include "../include/primitives/Prg.hpp"
#include "../include/primitives/Kdf.hpp"
#include "../include/primitives/RandomOracle.hpp"
#include "../include/comm/Comm.hpp"
#include "../include/circuits/BooleanCircuits.hpp"
#include "../include//interactive_mid_protocols/CommitmentSchemePedersen.hpp"
#include "../include//interactive_mid_protocols/SigmaProtocol.hpp"
#include "../include//interactive_mid_protocols/SigmaProtocolDlog.hpp"
#include "../include//interactive_mid_protocols/SigmaProtocolDH.hpp"
#include "../include//interactive_mid_protocols/SigmaProtocolDHExtended.hpp"
#include <ctype.h>

biginteger endcode_decode(biginteger bi) {
	auto s = bi.str();
	s.c_str();
	return biginteger(s);
}

string rsa100 = "1522605027922533360535618378132637429718068114961380688657908494580122963258952897654000350692006139";
string xx = "12796996813601383763849798056730343283682939747202100943566894545802445831004";

TEST_CASE("Common methods", "[boost, common, math, log, bitLength, helper]") {

	SECTION("find_log2_floor") {
		REQUIRE(find_log2_floor(16) == 4);
		REQUIRE(find_log2_floor(19) == 4);
		REQUIRE(find_log2_floor(31) == 4);
		REQUIRE(find_log2_floor(32) == 5);
		REQUIRE(find_log2_floor(39) == 5);
	}

	SECTION("bitlength and byteLength")
	{
		REQUIRE(NumberOfBits(64) == 7);
		REQUIRE(bytesCount(64) == 1);
		REQUIRE(NumberOfBits(9999) == 14);
		REQUIRE(bytesCount(9999) == 2);
		REQUIRE(NumberOfBits(biginteger(rsa100))== 330);
		REQUIRE(bytesCount(biginteger(rsa100)) == 42);
		REQUIRE(NumberOfBits(-biginteger(rsa100)) == 330);
		REQUIRE(bytesCount(-biginteger(rsa100)) == 42);
	}

	SECTION("gen_random_bytes_vector")
	{
		vector<byte> v, v2;
		gen_random_bytes_vector(v, 10);
		gen_random_bytes_vector(v2, 10);
		REQUIRE(v.size() == 10);
		for (byte b : v)
			REQUIRE(isalnum(b));
		string string1(v.begin(), v.end());
		string string2(v2.begin(), v2.end());
		REQUIRE(string1 != string2);
	}

	SECTION("copy byte vector to byte array")
	{
		vector<byte> v;
		gen_random_bytes_vector(v, 20);
		byte * vb = new byte[40];
		int index;
		copy_byte_vector_to_byte_array(v, vb, 0);
		copy_byte_vector_to_byte_array(v, vb, 20);
		for (auto it = v.begin(); it != v.end(); it++)
		{
			index = it - v.begin();
			REQUIRE(*it == vb[index]);
			REQUIRE(*it == vb[index+20]);
		}
		delete vb;
	}


	SECTION("copy byte array to byte vector")
	{
		byte src[10] = { 0xb1, 0xb2, 0xb3, 0xb4,  0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xc1 };
		vector<byte> target;
		copy_byte_array_to_byte_vector(src, 10, target, 0);
		int i = 0;
		REQUIRE(target.size() == 10);
		for (byte & b : target) 
			REQUIRE(src[i++] == b);
		target.clear();
		copy_byte_array_to_byte_vector(src, 10, target, 5);
		i = 5;
		REQUIRE(target.size() == 5);
		for (byte & b : target)
			REQUIRE(src[i++] == b);
	}

	SECTION("encode and decode bigintegers")
	{
		biginteger bi_res = endcode_decode(3322);
		REQUIRE(bi_res == 3322);
		biginteger birsa100 = biginteger(rsa100);
		bi_res = endcode_decode(birsa100);
		REQUIRE(bi_res == birsa100);
		bi_res = endcode_decode(-birsa100);
		REQUIRE(bi_res == -birsa100);
		bi_res = endcode_decode(197);
		REQUIRE(bi_res == 197);
		bi_res = endcode_decode(biginteger(xx));
		REQUIRE(bi_res == biginteger(xx));

	}

	SECTION("convert hex to string") {
		string hex = "64";
		REQUIRE(convert_hex_to_biginteger(hex)==biginteger(100));
	}

	SECTION("Config file") {
		// clean and create the config file
		remove("config_for_test.txt");
		std::ofstream outfile("config_for_test.txt");
		string textforfoo = "text_for_foo";
		string textforwater = "text_for_water";
		string nosecarg = "text_for_no_section_arg";
		outfile << "no_section_arg=" << nosecarg << "\n[section_1]\nfoo=" 
			<< textforfoo << "\n[section_2]\nwater=" << textforwater << std::endl;
		outfile.close();
	
		// read the file as config file
		ConfigFile cf("config_for_test.txt");
		std::string nosec = cf.Value("", "no_section_arg");
		std::string foo = cf.Value("section_1", "foo");
		std::string water = cf.Value("section_2", "water");
		REQUIRE(foo == textforfoo);
		REQUIRE(water == textforwater);
	}
}

//TEST_CASE("perfromance") {
//	int exp;
//	cin >> exp;
//	auto start0 = scapi_now();
//	biginteger bignumber = mp::pow(biginteger(2), exp);
//	print_elapsed_micros(start0, "compute pow");
//	auto start = scapi_now();
//	bool res_80 = isPrime(bignumber);
//	print_elapsed_micros(start, "miller_rabin");
//}

TEST_CASE("boosts multiprecision", "[boost, multiprecision]") {

	mt19937 gen(get_seeded_random());

	SECTION("testing pow")
	{
		biginteger res = mp::pow(biginteger(2), 10);
		REQUIRE(res == 1024);
	}

	SECTION("miller rabin test for prime numbers")
	{
		bool res_80 = isPrime(80);
		bool res_71 = isPrime(71);
		REQUIRE(!res_80);
		REQUIRE(res_71);
	}

	SECTION("generating random from range")
	{
		for (int i = 0; i < 100; ++i) {
			biginteger randNum = getRandomInRange(0, 100, gen);
			REQUIRE((randNum >= 0 && randNum <= 100));
		}
	}
	
	SECTION("bit test")
	{
		// 16 is 1000 - bit index is starting to count right to left so:
		bool bit_4 = mp::bit_test(biginteger(16), 4);
		bool bit_0 = mp::bit_test(biginteger(16), 0);
		REQUIRE(bit_4);
		REQUIRE(!bit_0);
	}

	SECTION("string conversion for biginteger")
	{
		string s = "12345678910123456789123456789123456789123456789123456789123456789123456789123456789";
		biginteger bi(s);
		REQUIRE((string)bi == s);
		REQUIRE(bi.str()  == s);
		biginteger b2 = bi - 3;
		auto st_res = s.substr(0, s.size() - 1)+"6";
		REQUIRE(b2.str() == st_res);
	}

	SECTION("boost powm - pow modolu m")
	{
		REQUIRE(mp::powm(biginteger(2), 3, 3) == 2);
		REQUIRE(mp::powm(biginteger(3), 4, 17) == 13);
	}
}

TEST_CASE("MathAlgorithm", "[crt, sqrt_mod_3_4, math]")
{
	SECTION("conversion between CryptoPP::Integer and boost's biginteger")
	{
		// sqrt(16) mod 7 == (4,-4)
		MathAlgorithms::SquareRootResults roots = MathAlgorithms::sqrtModP_3_4(16, 7);
		REQUIRE((roots.getRoot1() == 4 || roots.getRoot2() == 4));

		// sqrt(25) mod 7 == (5,-5)
		roots = MathAlgorithms::sqrtModP_3_4(25, 7);
		REQUIRE((roots.getRoot1() == 5 || roots.getRoot2() == 5));

		// sqrt(121) mod 7 == (4,-4)
		roots = MathAlgorithms::sqrtModP_3_4(121, 7);
		REQUIRE((roots.getRoot1() == 4 || roots.getRoot2() == 4));

		// sqrt(207936) mod 7 == (1,-1)
		roots = MathAlgorithms::sqrtModP_3_4(207936, 7);
		REQUIRE((roots.getRoot1() == 1 || roots.getRoot2() == 1));

		// 13 is equal to 3 mod 4
		REQUIRE_THROWS_AS(MathAlgorithms::sqrtModP_3_4(625, 13), invalid_argument);
	}
	SECTION("mod inverse")
	{
		biginteger res = MathAlgorithms::modInverse(3, 7);
		REQUIRE(res == 5);
	}
	SECTION("Chineese reminder theorem")
	{
		vector<biginteger> congruences = { 2, 3, 2 };
		vector<biginteger> moduli = { 3, 5, 7 };
		auto bi= MathAlgorithms::chineseRemainderTheorem(congruences, moduli);
		REQUIRE(bi == 23);
	}
	SECTION("factorial")
	{
		REQUIRE(MathAlgorithms::factorial(6)==720);
		string fact35 = "10333147966386144929666651337523200000000";
		REQUIRE(MathAlgorithms::factorialBI(35).str() == fact35);
	}
}

/***************************************************/
/***********TESTING DLOG IMPLEMENTATIONS******************/
/*****************************************************/

void test_multiply_group_elements(shared_ptr<DlogGroup> dg, bool check_membership=false)
{
	auto ge = dg->createRandomElement();
	auto ige = dg->getInverse(ge.get());
	auto mul = dg->multiplyGroupElements(ge.get(), ige.get());
	auto identity = dg->getIdentity();

	vector <shared_ptr<GroupElement>> vs{ ge, ige, mul, identity };
	if (check_membership)
		for (auto tge : vs)
			REQUIRE(dg->isMember(tge.get()));

	REQUIRE(mul->isIdentity());
}

void test_exponentiate(shared_ptr<DlogGroup> dg)
{
	auto ge = dg->createRandomElement();
	auto res_exp = dg->exponentiate(ge.get(), 3);
	auto res_mul = dg->multiplyGroupElements(dg->multiplyGroupElements(ge.get(), ge.get()).get(), ge.get());
	REQUIRE(*res_exp == *res_mul); // testing the == operator overloading and override
}

void test_simultaneous_multiple_exponentiations(shared_ptr<DlogGroup> dg)
{
	auto ge1 = dg->createRandomElement();
	auto ge2 = dg->createRandomElement();

	vector<shared_ptr<GroupElement>> baseArray = { ge1, ge2 };
	vector<biginteger> exponentArray = { 3, 4 };

	auto res1 = dg->simultaneousMultipleExponentiations(baseArray, exponentArray);
	auto expected_res = dg->multiplyGroupElements(dg->exponentiate(ge1.get(), 3).get(),
		dg->exponentiate(ge2.get(), 4).get());

	REQUIRE(*res1 == *expected_res);
}

void test_exponentiate_with_pre_computed_values(shared_ptr<DlogGroup> dg)
{
	auto base = dg->createRandomElement();
	auto res = dg->exponentiateWithPreComputedValues(base, 32);
	auto expected_res = dg->exponentiate(base.get(), 32);
	dg->endExponentiateWithPreComputedValues(base);

	REQUIRE(*expected_res == *res);
}

void test_encode_decode(shared_ptr<DlogGroup> dg)
{
	int k = dg->getMaxLengthOfByteArrayForEncoding();
	REQUIRE(k > 0);

	vector<byte> v;
	v.reserve(k);
	gen_random_bytes_vector(v, k);

	auto ge = dg->encodeByteArrayToGroupElement(v);
	vector<byte> res = dg->decodeGroupElementToByteArray(ge.get());
	
	for (int i = 0; i < k; i++) {
		REQUIRE(v[i] == res[i]);
	}
}

void test_all(shared_ptr<DlogGroup> dg)
{
	test_multiply_group_elements(dg);
	test_simultaneous_multiple_exponentiations(dg);
	test_exponentiate(dg);
	test_exponentiate_with_pre_computed_values(dg);
	test_encode_decode(dg);
}

TEST_CASE("DlogGroup", "[Dlog, DlogGroup, CryptoPpDlogZpSafePrime]")
{
	SECTION("test OpenSSLZpSafePrime implementation")
	{
		// testing with the default 1024 take too much time. 64 bit is good enough to test conversion with big numbers
		auto dg = make_shared<OpenSSLDlogZpSafePrime>(64); 
		test_all(dg);
	}

	SECTION("test OpenSSLDlogECFp implementation")
	{
		auto dg = make_shared<OpenSSLDlogECFp>();
		test_all(dg);
	}
	SECTION("test OpenSSLDlogECF2m implementation")
	{
		auto dg = make_shared<OpenSSLDlogECF2m>();
		test_multiply_group_elements(dg);
		test_simultaneous_multiple_exponentiations(dg);
		test_exponentiate(dg);
		test_exponentiate_with_pre_computed_values(dg);
	}

	SECTION("test OpenSSLDlogECF2m implementation")
	{
		auto dg = make_shared<OpenSSLDlogECF2m>("B-233");
		test_multiply_group_elements(dg);
		test_simultaneous_multiple_exponentiations(dg);
		test_exponentiate(dg);
		test_exponentiate_with_pre_computed_values(dg);
	}
}

template<typename T>
void test_hash(string in, string expect)
{
	CryptographicHash * hash = new T();
	const char *cstr = in.c_str();
	int len = in.size();
	vector<byte> vec(cstr, cstr + len);
	hash->update(vec, 0, len);
	vector<byte> out;
	hash->hashFinal(out, 0);
	string actual = hexStr(out);
	CAPTURE(actual);
	CAPTURE(expect);
	CAPTURE(actual.size());
	CAPTURE(expect.size());
	CAPTURE(hash->getHashedMsgSize());
	REQUIRE(actual == expect);
	delete hash;
}

TEST_CASE("Hash", "[HASH, SHA1]")
{
	SECTION("Testing OpenSSL SHA1") {
		string input_msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		test_hash<OpenSSLSHA1>(input_msg, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
		test_hash<OpenSSLSHA224>(input_msg, "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
		test_hash<OpenSSLSHA256>(input_msg, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
		test_hash<OpenSSLSHA384>(input_msg, "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");
		test_hash<OpenSSLSHA512>(input_msg, "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
	}
}

template<typename T>
void test_prp(string key, string in, string expected_out)
{
	OpenSSLPRP * prp = new T();
	string s = boost::algorithm::unhex(key);
	char const *c = s.c_str();
	SecretKey sk = SecretKey((byte *)c, strlen(c), prp->getAlgorithmName());
	prp->setKey(sk);

	string sin = boost::algorithm::unhex(in);
	char const * cin = sin.c_str();
	vector<byte> in_vec, out_vec;
	copy_byte_array_to_byte_vector((byte*)cin, strlen(cin), in_vec, 0);
	prp->computeBlock(in_vec, 0, out_vec, 0);
	
	REQUIRE(hexStr(out_vec) == expected_out);
	delete prp;
}

TEST_CASE("PRF", "[AES, PRF]")
{
	SECTION("OpenSSL PRP")
	{
		test_prp<OpenSSLAES>("2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97");
	}
	SECTION("TRIPLE DES")
	{
		string key = "1234567890123456ABCDEFGH";
		string plain = "The quic";
		test_prp<OpenSSLTripleDES>(boost::algorithm::hex(key), boost::algorithm::hex(plain), "13d4d3549493d287");
	}
	SECTION("HMAC")
	{
		string key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
		char const * plain = "Hi There";
		string expected_out_hex = "b617318655057264e28bc0b6fb378c8ef146be00";

		// create mac and set key
		auto mac = new OpenSSLHMAC();
		string s = boost::algorithm::unhex(key);
		char const *c = s.c_str();
		SecretKey sk = SecretKey((byte *)c, strlen(c), mac->getAlgorithmName());
		mac->setKey(sk);

		// compute_block for plain 
		int in_len = strlen(plain);
		vector<byte> in_vec, out_vec;
		copy_byte_array_to_byte_vector((byte*)plain, in_len, in_vec, 0);
		mac->computeBlock(in_vec, 0, in_len, out_vec, 0);

		// clean 
		delete mac;
		
		// verify 
		REQUIRE(hexStr(out_vec) == expected_out_hex);
	}
}

void test_prg(PseudorandomGenerator * prg, string expected_name)
{
	REQUIRE(!prg->isKeySet()); // verify key is not set yet
	auto sk = prg->generateKey(32);
	prg->setKey(sk);
	REQUIRE(prg->isKeySet());

	REQUIRE(prg->getAlgorithmName() == expected_name); // verify alg name is as expected
	vector<byte> out;
	prg->getPRGBytes(out, 0, 16);
	REQUIRE(out.size() == 16);
	vector<byte> out2;
	prg->getPRGBytes(out2, 0, 16);
	string s1(out.begin(), out.end());
	string s2(out2.begin(), out2.end());
	REQUIRE(s1 != s2);
}

TEST_CASE("PRG", "[PRG]")
{
	SECTION("ScPrgFromPrf")
	{
		PseudorandomFunction * prf = new OpenSSLAES();
		ScPrgFromPrf * scprg = new ScPrgFromPrf(prf);
		test_prg(scprg, "PRG_from_AES");
	}

	SECTION("OpenSSLRC4")
	{
		test_prg(new OpenSSLRC4(), "RC4");
	}
}

TEST_CASE("KDF","")
{
	SECTION("HKDF")
	{
		HKDF hkdf(new OpenSSLHMAC());
		string s = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
		string source = boost::algorithm::unhex(s);
		vector<byte> v_source(source.begin(), source.end());
		auto sk = hkdf.deriveKey(v_source, 0, v_source.size(), 40);
		auto v = sk.getEncoded();
		string s2(v.begin(), v.end());
	}
}

void random_oracle_test(RandomOracle * ro, string algName)
{
	REQUIRE(ro->getAlgorithmName() == algName);
	string input = "123456";
	vector<byte> in_vec(input.begin(), input.end());
	vector<byte> output;
	ro->compute(in_vec, 0, 6, output, 6);
	//REQUIRE(output.size() == 6);
	string s(output.begin(), output.end());
	delete ro;
}
TEST_CASE("Random Oracle", "")
{
	SECTION("HashBasedRO") {
		random_oracle_test(new HashBasedRO(), "HashBasedRO");
	}
	SECTION("HKDFBasedRO") {
		HKDF hkdf(new OpenSSLHMAC());
		random_oracle_test(new HKDFBasedRO(&hkdf), "HKDFBasedRO");
	}
}

TEST_CASE("TrapdoorPermutation", "[OpenSSL]")
{
	SECTION("OpenSSL") {
		auto tp = OpenSSLRSAPermutation();
		REQUIRE(tp.getAlgorithmName() == "OpenSSLRSA");
		biginteger public_mod = 55;
		int public_exponent = 3;
		int private_exponent = 7;
		tp.setKey(new RSAPublicKey(public_mod, public_exponent), new RSAPrivateKey(public_mod, private_exponent));
		RSAElement * re_src = (RSAElement *) tp.generateRandomTPElement();
		auto re_enc = tp.compute(re_src);
		auto re_inv = tp.invert(re_enc);
		CAPTURE(re_enc->getElement());
		REQUIRE(re_inv->getElement() == re_src->getElement());
	}
}

TEST_CASE("Comm basics", "[Communication]") {
	SECTION("Comparing SocketPartyData") {
		auto spd1 = SocketPartyData(IpAdress::from_string("127.0.0.1"), 3000);
		auto spd2 = SocketPartyData(IpAdress::from_string("127.0.0.1"), 3001);
		REQUIRE(spd1 < spd2);
		REQUIRE(spd2 > spd1);
		REQUIRE(spd2 >= spd1);
		REQUIRE(spd1 <= spd2);
		REQUIRE(spd1 != spd2);
		REQUIRE(!(spd1 == spd2));
	}
}

TEST_CASE("Gates and Wires", "") {
	/*
	* Calculating the function f=(~X)vY.
	* 3 wires. 0-X, 1-Y, 2-f(x,y)
	* Calculating once for x=0,y=0 (expecting 1) and for x=0, y=1 (expecting 0)
	*/
	SECTION("Compute Gate") {
		vector<bool> truthT = { 1, 0, 1, 1 }; // Truth table for f=(~X)vY
		vector<int> inputWireIndices = { 0,1 };
		vector<int> outputWireIndices = { 2 };
		Gate g(3, truthT, inputWireIndices, outputWireIndices);
		map<int, Wire> computed_wires_map;
		computed_wires_map[0] = 0; // x=0
		computed_wires_map[1] = 0; // y=0
		g.compute(computed_wires_map);
		REQUIRE(computed_wires_map[0].getValue() == 0); // x still 0
		REQUIRE(computed_wires_map[1].getValue() == 0); // y still 1
		REQUIRE(computed_wires_map[2].getValue() == 1); // res = 1
		computed_wires_map[1] = 1; // y=1 now
		g.compute(computed_wires_map);
		REQUIRE(computed_wires_map[0].getValue() == 0); // x is still 0
		REQUIRE(computed_wires_map[1].getValue() == 1); // y is now 1
		REQUIRE(computed_wires_map[2].getValue() == 0); // res = 0
	}

	SECTION("Boolean Circuit") {
		/*
		* Calculating Circuit composed of 3 gates:
		*  i0 ----\
		*          > f1(X,Y)=(X or Y) -(i5 is x)\
		*  i1 ----/                              \
		*                                         --- > F3(x,y,z)= ((x or y) and z)   ----- i7 --->
		*  i2 ----\                              /   /
		*          > f2(X,Y)=(X and Y)-(i6 is y)/   /
		*  i3 ----/                                /
		*                                         /
		*  i4 --------------------------(is z)---/
		* Testing with i0=1, i1=0, i2=1, i3=0, i4=1.
		* Should get i7=1
		*/
		Gate g1(1, { 0, 1, 1, 1 }, { 0, 1 }, { 5 }); // x || y
		Gate g2(2, { 0, 0, 0, 1 }, { 2, 3 }, { 6 }); // x && y
		Gate g3(3, { 0, 0, 0, 1, 0, 1, 0, 1 }, { 5, 6, 4 }, { 7 }); // (x || y) && z
		BooleanCircuit bc({ g1, g2, g3 }, { 7 }, { {1,2,3,4} });
		map<int, Wire> presetInputWires = { { 0, Wire(1) }, { 1, Wire(0) }, { 2, Wire(1) },
											{ 3, Wire(0) }, { 4, Wire(1) } };
		bc.setInputs(presetInputWires, 1);
		auto bc_res_map = bc.compute();
		REQUIRE(bc_res_map[7].getValue() == 1);
	}
}

TEST_CASE("serialization", "[SerializedData, CmtCCommitmentMsg]")
{
	SECTION("CmtPedersenCommitmentMessage") {
		biginteger birsa100 = biginteger(rsa100);
		long id = 123123123123123;
		
		// create serialize, and verify original values untouched
		auto es = make_shared<ZpElementSendableData>(birsa100);
		CmtPedersenCommitmentMessage cmtMsg(es, id);
		auto serialized = cmtMsg.toString();
		REQUIRE(cmtMsg.getId() == id);
		REQUIRE(((ZpElementSendableData*)cmtMsg.getCommitment().get())->getX() == birsa100);

		// verify new one is created with empty values
		CmtPedersenCommitmentMessage cmtMsg2(make_shared<ZpElementSendableData>(0));
		REQUIRE(cmtMsg2.getId() == 0);
		REQUIRE(((ZpElementSendableData*)cmtMsg2.getCommitment().get())->getX() == 0);

		// deserialize and verify original values in the new object
		cmtMsg2.initFromString(serialized);
		REQUIRE(cmtMsg2.getId() == id);
		REQUIRE(((ZpElementSendableData*)cmtMsg2.getCommitment().get())->getX() == birsa100);
	}
	SECTION("SigmaBIMsg") {
		biginteger value = 123456789;
		SigmaBIMsg sMsg(value);
		auto serialized = sMsg.toString();
		REQUIRE(sMsg.getMsg() == value);

		// verify new one is created with empty values
		SigmaBIMsg sMsg2;
		REQUIRE(sMsg2.getMsg() == -100);

		// deserialize and verify original values in the new object
		sMsg2.initFromString(serialized);
		REQUIRE(sMsg2.getMsg() == value);
	}
	SECTION("CmtPedersenDecommitmentMessage") {
		biginteger rvalue(rsa100);
		biginteger xvalue(95612134554333);
		auto r = make_shared<BigIntegerRandomValue>(rvalue);
		CmtPedersenDecommitmentMessage cpdm(xvalue, r);
		auto serialized = cpdm.toString();
		auto biR = dynamic_pointer_cast<BigIntegerRandomValue>(cpdm.getR());
		REQUIRE(biR->getR() == rvalue);
		REQUIRE(cpdm.getX() == xvalue);

		// verify new one is created with empty values
		auto r2 = make_shared<BigIntegerRandomValue>(0);
		CmtPedersenDecommitmentMessage cpdm2;
		auto biR2 = dynamic_pointer_cast<BigIntegerRandomValue>(cpdm2.getR());
		REQUIRE(!biR2);
		REQUIRE(cpdm2.getX() == 0);

		// deserialize and verify original values in the new object
		cpdm2.initFromString(serialized);
		auto biR3 = dynamic_pointer_cast<BigIntegerRandomValue>(cpdm2.getR());
		REQUIRE(biR3->getR() == rvalue);
		REQUIRE(cpdm2.getX() == xvalue);
	}
	SECTION("CmtRTrapdoorCommitPhaseOutput") {
		biginteger trap(rsa100);
		long commitmentId = 123456789;
		CmtRTrapdoorCommitPhaseOutput cmtTrapOut(trap, commitmentId);
		auto serialized = cmtTrapOut.toString();
		REQUIRE(cmtTrapOut.getCommitmentId() == commitmentId);
		REQUIRE(cmtTrapOut.getTrap() == trap);

		// verify new one is created with empty values
		CmtRTrapdoorCommitPhaseOutput cmtTrapOut2;
		REQUIRE(cmtTrapOut2.getCommitmentId() == 0);
		REQUIRE(cmtTrapOut2.getTrap() == 0);

		// deserialize and verify original values in the new object
		cmtTrapOut2.initFromString(serialized);
		REQUIRE(cmtTrapOut2.getCommitmentId() == commitmentId);
		REQUIRE(cmtTrapOut2.getTrap() == trap);
	}
	SECTION("ECFp Point sendable data") {
		OpenSSLDlogECFp dlog;
		shared_ptr<GroupElement> point = dlog.createRandomElement();
		
		shared_ptr<ECElementSendableData> data = dynamic_pointer_cast<ECElementSendableData>(point->generateSendableData());
		REQUIRE(dynamic_pointer_cast<ECElement>(point)->getX() == data->getX());
		REQUIRE(dynamic_pointer_cast<ECElement>(point)->getY() == data->getY());
		
		string dataBytes = data->toString();
		ECElementSendableData point2Data(0,0);
		point2Data.initFromString(dataBytes);

		REQUIRE(point2Data.getX() == data->getX());
		REQUIRE(point2Data.getY() == data->getY());
		
		shared_ptr<GroupElement> point2 = dlog.reconstructElement(false, &point2Data);
		REQUIRE(dlog.isMember(point2.get()));
		REQUIRE(*point2.get() == *point.get());
	}

	SECTION("ECF2m Point sendable data") {
		OpenSSLDlogECF2m dlog;
		shared_ptr<GroupElement> point = dlog.createRandomElement();

		shared_ptr<ECElementSendableData> data = dynamic_pointer_cast<ECElementSendableData>(point->generateSendableData());
		REQUIRE(dynamic_pointer_cast<ECElement>(point)->getX() == data->getX());
		REQUIRE(dynamic_pointer_cast<ECElement>(point)->getY() == data->getY());

		string dataBytes = data->toString();
		ECElementSendableData point2Data(0, 0);
		point2Data.initFromString(dataBytes);

		REQUIRE(point2Data.getX() == data->getX());
		REQUIRE(point2Data.getY() == data->getY());

		shared_ptr<GroupElement> point2 = dlog.reconstructElement(false, &point2Data);
		REQUIRE(dlog.isMember(point2.get()));
		REQUIRE(*point2.get() == *point.get());
	}
}

void computeSigmaProtocol(SigmaProverComputation* prover, SigmaVerifierComputation* verifier, 
	SigmaCommonInput* commonInput, shared_ptr<SigmaProverInput> proverInput) {
	shared_ptr<SigmaProtocolMsg> firstMsg = prover->computeFirstMsg(proverInput);
	verifier->sampleChallenge();
	vector<byte> challenge = verifier->getChallenge();
	shared_ptr<SigmaProtocolMsg> secondMsg = prover->computeSecondMsg(challenge);
	bool verified = verifier->verify(commonInput, firstMsg.get(), secondMsg.get());
	
	REQUIRE(verified == true);
}

void simulate(SigmaSimulator* simulator, SigmaVerifierComputation* verifier,
	SigmaCommonInput* commonInput) {
	
	shared_ptr<SigmaSimulatorOutput> output = simulator->simulate(commonInput);
	verifier->setChallenge(output->getE());
	bool verified = verifier->verify(commonInput, output->getA().get(), output->getZ().get());

	REQUIRE(verified == true);
}

TEST_CASE("SigmaProtocols", "[SigmaProtocolDlog, SigmaProtocolDH]")
{
	SECTION("test sigma protocol dlog")
	{
		mt19937 random = get_seeded_random();
		auto dlog = make_shared<OpenSSLDlogECF2m>();
		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		
		SigmaDlogProverComputation prover(dlog, 80, get_seeded_random());
		SigmaDlogVerifierComputation verifier(dlog, 80, get_seeded_random());
		SigmaDlogSimulator simulator(dlog, 80, random);
		biginteger w = getRandomInRange(0, dlog->getOrder() - 1, random);
		
		auto h = dlog->exponentiate(dlog->getGenerator().get(), w);
		SigmaDlogCommonInput commonInput(h);
		shared_ptr<SigmaDlogProverInput> proverInput = make_shared<SigmaDlogProverInput>(h, w);
		
		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(&simulator, &verifier, &commonInput);
	}

	SECTION("test sigma protocol DH")
	{
		mt19937 random = get_seeded_random();
		auto dlog = make_shared<OpenSSLDlogECFp>();
		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		SigmaDHProverComputation prover(dlog, 80, get_seeded_random());
		SigmaDHVerifierComputation verifier(dlog, 80, get_seeded_random());
		SigmaDHSimulator simulator(dlog, 80, random);
		biginteger w = getRandomInRange(0, dlog->getOrder() - 1, random);
		
		auto u = dlog->exponentiate(dlog->getGenerator().get(), w);
		auto h = dlog->createRandomElement();
		auto v = dlog->exponentiate(h.get(), w);
		SigmaDHCommonInput commonInput(h, u, v);
		shared_ptr<SigmaDHProverInput> proverInput = make_shared<SigmaDHProverInput>(h, u, v, w);
	
		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(&simulator, &verifier, &commonInput);
	}

	SECTION("test sigma protocol DH Extended")
	{
		mt19937 random = get_seeded_random();
		auto dlog = make_shared<OpenSSLDlogECFp>();
		//auto dlog = make_shared<OpenSSLDlogZpSafePrime>();
		SigmaDHExtendedProverComputation prover(dlog, 80, get_seeded_random());
		SigmaDHExtendedVerifierComputation verifier(dlog, 80, get_seeded_random());
		SigmaDHExtendedSimulator simulator(dlog, 80, random);
		biginteger w = getRandomInRange(0, dlog->getOrder() - 1, random);

		auto g1 = dlog->getGenerator();
		auto h1 = dlog->exponentiate(g1.get(), w);
		auto g2 = dlog->createRandomElement();
		auto h2 = dlog->exponentiate(g2.get(), w);
		vector<shared_ptr<GroupElement>> g;
		g.push_back(g1);
		g.push_back(g2);
		vector<shared_ptr<GroupElement>> h;
		h.push_back(h1);
		h.push_back(h2);
		SigmaDHExtendedCommonInput commonInput(g, h);
		shared_ptr<SigmaDHExtendedProverInput> proverInput = make_shared<SigmaDHExtendedProverInput>(g, h, w);

		computeSigmaProtocol(&prover, &verifier, &commonInput, proverInput);
		simulate(&simulator, &verifier, &commonInput);
	}
	
}
