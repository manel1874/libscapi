//
// Created by liork on 30/05/16.
//

#ifndef SCAPIPRG_PRG_HPP
#define SCAPIPRG_PRG_HPP


#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <emmintrin.h>
#include <malloc.h>
#include "Prg.hpp"


using namespace std;

typedef unsigned char byte;
typedef __m128i block;

#define DEFAULT_CACHE_SIZE 60000


/*
 * Helper class for the AES_PRG
 */
class PRG_CTR128
{
public:
    PRG_CTR128(int max_size);
    ~PRG_CTR128();
    byte *inc(int size);

private:
    void spillCounter();
    void recordCounter(int size);
    void doInc(int size);
    void AES_ctr128_inc(byte *counter);


    byte *m_buf;
    int m_max_size;
    byte m_ctr[16] = {0,0,0,0,
                      0,0,0,0,
                      0,0,0,0,
                      0,0,0,0};
    block m_CONST_ONE;

};


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
    ~AES_PRG();

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
    void getPRGBytes(vector<byte> & outBytes, int outOffset, int outLen) override;

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

    static unsigned char m_defualtkey[16];
    static unsigned char m_defaultiv[16];

    PRG_CTR128 m_ctr128;
    EVP_CIPHER_CTX m_enc;
    byte* m_key;
    int m_cahchedSize;
    byte *m_cachedRandoms;
    byte *m_iv;
    byte* m_ctr;
    int m_cachedRandomsIdx;
    int m_idx;
    uint32_t *m_pIdx;
    uint32_t m_u1;
    uint32_t m_u2;
    uint32_t m_u3;
    uint32_t m_u4;

    bool m_isKeySet;
};


#endif //SCAPIPRG_PRG_HPP