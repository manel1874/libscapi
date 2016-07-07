#include <openssl/evp.h>
#include <bitset>
#include "../../include/primitives/AES_PRG.hpp"

unsigned char AES_PRG::m_defualtkey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

unsigned char AES_PRG::m_defaultiv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                                      0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

AES_PRG::AES_PRG(int cahchedSize) : AES_PRG((byte*)m_defualtkey,(byte*)m_defaultiv,cahchedSize) { }


AES_PRG::AES_PRG(byte *key,int cahchedSize) : AES_PRG(key,(byte*)m_defaultiv,cahchedSize) { }

AES_PRG::AES_PRG(byte *key, byte *iv,int cahchedSize) : m_ctr128(cahchedSize)
{

    m_key = key;
    m_iv = iv;
    m_idx = 0;
    m_cahchedSize = cahchedSize;
    m_cachedRandomsIdx = m_cahchedSize;
    EVP_CIPHER_CTX_init(&m_enc);
    EVP_EncryptInit(&m_enc, EVP_aes_128_ecb(),m_key, m_iv);
    #ifndef _WIN32
        m_cachedRandoms = (byte*)memalign(m_cahchedSize*16, 16);
    #else
    m_cachedRandoms = (byte*)_aligned_malloc(m_cahchedSize*16, 16);
    #endif
    m_isKeySet = true;
    prepare(1);

}

AES_PRG::~AES_PRG()
{
    delete[] m_cachedRandoms;
    EVP_CIPHER_CTX_cleanup(&m_enc);
}


SecretKey AES_PRG::generateKey(int keySize)
{
    vector<byte> genBytes(m_key,m_key+16);
    SecretKey generatedKey(genBytes, "");
    return generatedKey;
}

SecretKey AES_PRG::generateKey(AlgorithmParameterSpec keyParams)
{
    throw NotImplementedException("To generate a key for this prg object use the constructor");
}


string AES_PRG::getAlgorithmName()
{
    return "AES PRG";
}

bool AES_PRG::isKeySet()
{
    return m_isKeySet;
}

void AES_PRG::setKey(SecretKey secretKey)
{
    throw NotImplementedException("To generate a key for this prg object use the constructor");
}

void AES_PRG::getPRGBytes(vector<byte> & outBytes, int outOffset, int outLen)
{
    throw NotImplementedException("To generate a key for this prg object use the constructor");
}


void PRG_CTR128::AES_ctr128_inc(byte *counter)
{

    uint64_t * p1 = (uint64_t *) counter - 8;
    uint64_t * p2 = (uint64_t *) counter + 8;
    (*p2) = (*p1) + 1;

}


byte * AES_PRG::getRandomBytes()
{
    if(m_cachedRandomsIdx==m_cahchedSize)
    {
        cout << " HIT UNEXPECTED PREPARE " << endl;
        exit(-1);
        //prepare(0);
    }
    byte *ret = m_cachedRandoms + m_cachedRandomsIdx*16;
    m_cachedRandomsIdx++;

    return ret;

}


vector<byte> AES_PRG::getPRGBitsBytes(int size)
{
    vector<byte> prg;
    prg.resize(size*8);
    byte* data = m_cachedRandoms + m_cachedRandomsIdx*size;
    m_cachedRandomsIdx += size;

    for(int i=0;i<size;i+=8)
    {
        bitset <8> bits(data[i]);

        for(int j=0;j<8;j++)
        {
            if(bits[j]==0)
                prg[i+j] = 0;
            else
                prg[i+j] = 1;
        }
    }

    return prg;
}

vector<byte> AES_PRG::getRandomBytes(int size)
{
    vector<byte> data (m_cachedRandoms,m_cachedRandoms+size);
    m_cahchedSize += size;
    return data;
}


void AES_PRG::prepare(int isPlanned)
{
    int actual;
    byte *ctr = m_ctr128.inc(m_cachedRandomsIdx);
    EVP_EncryptUpdate(&m_enc, m_cachedRandoms, &actual , ctr, 16*m_cachedRandomsIdx );
    m_cachedRandomsIdx = 0;
    m_idx = 0;
}

block* AES_PRG::getRandomBytesBlock(int size)
{
    block *data = new block[size];
    for(int i=0;i<size;i++)
    {
        uint32_t t1 = getRandom();
        uint32_t t2 = getRandom();
        uint32_t t3 = getRandom();
        uint32_t t4 = getRandom();

        data[i] = _mm_set_epi32(t4,t3,t2,t1);
    }

    return data;

}

uint32_t AES_PRG::getRandom()
{
    switch (m_idx)
    {
        case 0:
        {

            m_pIdx = (uint32_t*) getRandomBytes();
            m_u1 = *m_pIdx;
            m_pIdx++;
            m_idx++;
            return m_u1;
        }

        case 1:
        {
            m_u2 = *m_pIdx;
            m_pIdx++;
            m_idx++;
            return m_u2;
        }

        case 2:
        {
            m_u3 = *m_pIdx;
            m_pIdx++;
            m_idx++;
            return m_u3;
        }

        case 3:
        {
            m_u4 = *m_pIdx;
            m_idx = 0;
            return m_u4;
        }
    }
}




PRG_CTR128::PRG_CTR128(int max_size)
{
    m_max_size = max_size;
    #ifndef _WIN32
        m_buf = (byte*)memalign(16*max_size, 16);
        m_ctr = (byte*)memalign(16, 16);
    #else
        m_buf = (byte*)_aligned_malloc(16*max_size, 16);
        m_ctr = (byte*)_aligned_malloc(16, 16);
    #endif
    for(int i=0; i<16; i++)
        m_ctr[i] = 0x00;
    m_CONST_ONE = _mm_set_epi64x(1, 1);
}

PRG_CTR128:: ~PRG_CTR128()
{
	_aligned_free(m_buf);
	_aligned_free(m_ctr);
}

byte *PRG_CTR128::inc(int size)
{


    spillCounter();
    doInc(size);
    recordCounter(size);
    return m_buf;
}

void PRG_CTR128::spillCounter()
{
    block tempCopy;
    tempCopy = _mm_loadu_si128((block*)(m_ctr));
    _mm_stream_si128((block*)m_buf,tempCopy);

    //memcpy(m_buf, m_ctr, 16);
}

void PRG_CTR128::recordCounter(int size)
{
    block tempCopy;
    tempCopy = _mm_loadu_si128((block*)(m_buf + (size-1)*16));
    block *ctrCopy = (block*)&m_ctr;
    _mm_stream_si128(ctrCopy,tempCopy);
}

void PRG_CTR128::doInc(int size)
{
    for (int i=0; i < size; i++) {
        AES_ctr128_inc(m_buf + 16*i);
    }

}
