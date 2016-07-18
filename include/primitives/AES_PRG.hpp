//
// Created by liork on 30/05/16.
//
#ifndef SCAPIPRG_PRG_HPP
#define SCAPIPRG_PRG_HPP


#include <iostream>
#include <openssl/evp.h>
#include <emmintrin.h>
#include <malloc.h>
#include "Prg.hpp"
#include <bitset>


using namespace std;

typedef unsigned char byte;
typedef __m128i block;

#define DEFAULT_CACHE_SIZE 640


class AES_PRG : public PseudorandomGenerator
{
    
public:

    /*
     * Constructor of AES prg instance. The interface suplies 3 constructors:
     * 1. Constructor with initial size
     * 2. Constructor with initial key and initial size
     * 3. Constructor with initial key, initial iv and initial size
     */
    AES_PRG(int cahchedSize=DEFAULT_CACHE_SIZE);
    AES_PRG(byte *key,int cahchedSize=DEFAULT_CACHE_SIZE);
    AES_PRG(byte *key, byte *iv,int cahchedSize=DEFAULT_CACHE_SIZE);

	//move constructor
	AES_PRG(AES_PRG&& old);
	//copy constructor
	AES_PRG(AES_PRG& other);

    virtual ~AES_PRG();

	//move assignment
	AES_PRG& operator=(AES_PRG&& other);
	//copy assignment
	AES_PRG& operator=(AES_PRG& other);

    /*
     * @return byte* of the random values.
     */
    byte *getRandomBytes();

    /*
     * @return single random value from type uint32_t.
     */
    uint32_t getRandom();

    /*
     * @ param isPlanned - states if the generation of random values was planned.
     * calculate the random values and cached them in m_cachedRandoms.
     */
    void prepare(int isPlanned = 1);

    /*
    * Sets the secret key for this prg - This option Not supported for this interface.
     */
    void setKey(SecretKey secretKey) override;

    /*
    * An object trying to use an instance of prg needs to check if it has already been initialized with a key.
    * @return true if the object was initialized by calling the function setKey.
     */
    bool isKeySet() override;

    /*
     * @return the algorithm name. For example - RC4
     */
    string getAlgorithmName() override;

    /*
    * Generates a secret key to initialize this prg object - This option not supported for this interface.
    * @param keyParams algorithmParameterSpec contains the required parameters for the key generation
    * @return the generated secret key
     */
    SecretKey generateKey(AlgorithmParameterSpec keyParams) override;

    /*
    * Generates a secret key to initialize this prg object.
    * @param keySize is the required secret key size in bits
    * @return the generated secret key
     */
    SecretKey generateKey(int keySize) override;

    /*
    * Streams the prg bytes - This option not supported for this interface.
    * @param outBytes - output bytes. The result of streaming the bytes.
    * @param outOffset - output offset
    * @param outlen - the required output length
     */
	void getPRGBytes(vector<byte> & outBytes, int outOffset, int outlen);

    /*
     * @param size - the size og the output vector
     * @return vector of bits (0|1) in the given size
     */
    vector<byte> getPRGBitsBytes(int size);

    /*
     * @param size - the size og the output vector
     * @return vector of the random values
     */
    vector<byte> getRandomBytes(int size);

    /*
     * @param size - the size og the output vector
     * @return array of random values where the return type is block (__m128i*)
     */
    block* getRandomBytesBlock(int size);


private:

    unsigned char m_defualtkey[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    unsigned char m_defaultiv[16] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

    //EVP_CIPHER_CTX* m_enc;
	byte *m_iv;
	int m_cahchedSize;
	int m_cachedRandomsIdx;
	shared_ptr<EVP_CIPHER_CTX> m_enc;
	bool m_isKeySet;
	SecretKey *m_secretKey;
    byte *m_cachedRandoms;
	void updateCachedRandomsIdx(int size);
};

class EVP_CIPHER_CTX_DELETER
{
public:
	static void deleter(EVP_CIPHER_CTX* enc)
	{
		EVP_CIPHER_CTX_cleanup(enc);
	}
};

#endif //SCAPIPRG_PRG_HPP