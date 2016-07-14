//#include "stdafx.h"
#include "../../include/primitives/AES_PRG.hpp"

/*
unsigned char AES_PRG::m_defualtkey[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

unsigned char AES_PRG::m_defaultiv[16] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
*/

AES_PRG::AES_PRG(int cahchedSize) : AES_PRG((byte*)m_defualtkey, (byte*)m_defaultiv, cahchedSize) { }


AES_PRG::AES_PRG(byte *key, int cahchedSize) : AES_PRG(key, (byte*)m_defaultiv, cahchedSize) { }

AES_PRG::AES_PRG(byte *key, byte *iv, int cahchedSize)
{
	m_key = new SecretKey(key, 16, "AES");
	m_iv = iv;
	m_cahchedSize = cahchedSize;
	m_cachedRandomsIdx = m_cahchedSize;
	EVP_CIPHER_CTX_init(&m_enc);
	EVP_EncryptInit(&m_enc, EVP_aes_128_ecb(), m_key->getEncoded().data(), m_iv);

#ifndef _WIN32
	m_cachedRandoms = (byte*)memalign(m_cahchedSize * 16, 16);
#else
	m_cachedRandoms = (byte*)_aligned_malloc(m_cahchedSize, 16);
#endif

	assert(m_cachedRandoms != NULL);
	m_isKeySet = true;
	prepare(1);

}

AES_PRG::~AES_PRG()
{
	/*
	if (m_cachedRandoms != nullptr)
	{
		_aligned_free(m_cachedRandoms);
		m_cachedRandoms = nullptr;
	}*/
	
	//EVP_CIPHER_CTX_cleanup(&m_enc);
}


SecretKey AES_PRG::generateKey(int keySize)
{
	
	vector<byte> genBytes(m_key->getEncoded().data(), m_key->getEncoded().data() + keySize);
	SecretKey generatedKey(genBytes.data(),keySize,"AES");
	return generatedKey;
	
}

SecretKey AES_PRG::generateKey(AlgorithmParameterSpec keyParams)
{
	throw NotImplementedException("To generate a key use generateKey with size parameter");
}


string AES_PRG::getAlgorithmName()
{
	return "AES";
}

bool AES_PRG::isKeySet()
{
	return m_isKeySet;
}

void AES_PRG::setKey(SecretKey secretKey)
{
	//m_key = &secretKey;
}

void AES_PRG::getPRGBytes(vector<byte> & outBytes, int outOffset, int outLen)
{
	for (int i = outOffset; i < (outOffset + outLen); i++)
	{
		outBytes[i] = m_cachedRandoms[m_cachedRandomsIdx];
		updateCachedRandomsIdx(1);
	}
}

byte * AES_PRG::getRandomBytes()
{
	byte *ret = m_cachedRandoms + m_cachedRandomsIdx;
	updateCachedRandomsIdx(1);

	return ret;

}


vector<byte> AES_PRG::getPRGBitsBytes(int size)
{
	vector<byte> prg(size);
	int byteNum = (size / 8) + 1;
	byte* data = m_cachedRandoms + m_cachedRandomsIdx;
	updateCachedRandomsIdx(byteNum);

	vector<bitset<8>> bits(byteNum);
	for (int i = 0; i < byteNum; i++)
	{
		bits[i] = data[i];
	}

	for (int i = 0; i < size; i++)
	{
		if (bits[i] == 0)
			prg[i] = 0;
		else
			prg[i] = 1;
	}

	return prg;
}

vector<byte> AES_PRG::getRandomBytes(int size)
{
	if (m_cachedRandomsIdx + size >= m_cahchedSize)
		prepare(0);
	byte* start = m_cachedRandoms + m_cachedRandomsIdx;
	updateCachedRandomsIdx(size);
	byte* end = m_cachedRandoms + m_cachedRandomsIdx;
	vector<byte> data(start, end);
	return data;
}


void AES_PRG::prepare(int isPlanned)
{
	int actual;
	//byte *ctr = m_ctr128.inc(m_cahchedSize);

	byte *ctr = (byte*)_aligned_malloc(m_cahchedSize, 16);
	EVP_EncryptUpdate(&m_enc, m_cachedRandoms, &actual, ctr, m_cahchedSize);
	m_cachedRandomsIdx = 0;

	_aligned_free(ctr);
}

block* AES_PRG::getRandomBytesBlock(int size)
{
	block *data = (block *)_aligned_malloc(sizeof(block) * size, 16);

	if (m_cachedRandomsIdx + size * 16 >= m_cahchedSize)
		prepare(0);

	auto start = m_cachedRandoms + m_cachedRandomsIdx;
	memcpy(data, start, size * 16);

	updateCachedRandomsIdx(size * 16);

	return data;

}

void AES_PRG::updateCachedRandomsIdx(int size)
{

	m_cachedRandomsIdx += size;
	if (m_cachedRandomsIdx >= m_cahchedSize)
		prepare(0);
}

uint32_t AES_PRG::getRandom()
{
	if (m_cachedRandomsIdx + 4 >= m_cahchedSize)
		prepare(0);
	auto temp = (uint32_t*)(m_cachedRandoms + m_cachedRandomsIdx) ;
	updateCachedRandomsIdx(4);

	return  *temp;
}