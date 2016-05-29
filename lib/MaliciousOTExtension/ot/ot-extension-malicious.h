#pragma once
/*
 * Methods for the OT Extension routine
 */
#ifndef __MAL_OT_EXTENSION_H_
#define __MAL_OT_EXTENSION_H_

#include "../util/typedefs.h"
#include "../util/socket.h"
#include "../util/thread.h"
#include "../util/cbitvector.h"
#include "../util/crypto.h"
#include "maskingfunction.h"

namespace maliciousot {

	//#define DEBUG
	//#define FIXED_KEY_AES_HASHING
	//#define AES_OWF
	//#define DEBUG_MALICIOUS
#define VERIFY_OT
//#define OT_HASH_DEBUG
//#define OTTiming



	const BYTE	G_OT = 0x01;
	const BYTE 	C_OT = 0x02;
	const BYTE	R_OT = 0x03;
	const BYTE	S_OT = 0x04;
	const BYTE OCRS_OT = 0x05;

	//Note: NUMOTBLOCKS = 1 does not make sense, since no new OTs are generated
#ifndef NUMOTBLOCKS
#define NUMOTBLOCKS 1024
#endif

#define CHECK_METHOD 0 //0: ALSZ style checking, 1: NNOB style checking

	typedef struct {
		int ida;
		int idb;
	} linking_t;

#if CHECK_METHOD == 0
#define RECEIVER_HASHES 4
#else
#define RECEIVER_HASHES 1
#endif


	typedef struct OTBlock_t {
		int threadid;
		int blockid;
		int processedOTs;
		BYTE* snd_buf;
#if CHECK_METHOD == 0
		BYTE* seed_hash;
		BYTE* rcv_hash;
#else
		BYTE* hash_buf;
		BYTE* permchoicebits;
#endif
		linking_t* perm;
		OTBlock_t* next;
	} OTBlock;

	typedef struct exp_seed_ctx {
		int blockid;
		int expstrbitlen;
		BYTE* T0;
		BYTE* T1;
		exp_seed_ctx* next;
	} exp_seed_t;

	typedef struct snd_check_ctx {
		linking_t* perm;
#if CHECK_METHOD == 0
		BYTE* seed_chk_buf;
		BYTE* rcv_chk_buf;
#else
		BYTE* chk_buf;
#endif
	} snd_check_t;

	typedef struct rcv_check_ctx {
		linking_t* perm;
		int nchecks;
		int otid;
		int processedOTs;
		int threadid;
		BYTE* outhashes;
#if CHECK_METHOD == 1
		BYTE* permchoicebits;
#endif
	} rcv_check_t;


	static void InitAESKey(AES_KEY_CTX* ctx, BYTE* keybytes, int numkeys)
	{
		BYTE* pBufIdx = keybytes;
		for (int i = 0; i < numkeys; i++)
		{
			MPC_AES_KEY_INIT(ctx + i);
			MPC_AES_KEY_EXPAND(ctx + i, pBufIdx);
			pBufIdx += AES_KEY_BYTES;
		}
	}
#ifdef AES_OWF
	inline void owf(AES_KEY_CTX* aesowfkey, int rowbytelen, BYTE* m, BYTE* H);
#else
	inline void owf(BYTE* hash_buf, int rowbytelen, BYTE* m, BYTE* H);
#endif
#define xor_128_buf(res, ina, inb) ((uint64_t*) (res))[0] = ((uint64_t*) (ina))[0] ^ ((uint64_t*) (inb))[0]; \
		((uint64_t*) (res))[1] = ((uint64_t*) (ina))[1] ^ ((uint64_t*) (inb))[1];

#ifdef FIXED_KEY_AES_HASHING
	static const BYTE fixedkeyseed[AES_KEY_BYTES] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
#endif

#define OWF_BYTES AES_BYTES



	class Mal_OTExtensionSender {
		/*
		 * Malicious OT sender part
		 * Input:
		 * ret: returns the resulting bit representations. Has to initialized to a byte size of: nOTs * nSndVals * state.field_size
		 *
		 * CBitVector* values: holds the values to be transferred. If C_OT is enabled, the first dimension holds the value while the delta is written into the second dimension
		 * Output: was the execution successful?
		 */
	public:
		Mal_OTExtensionSender(int nSndVals, int nOTs, int bitlength, int symsecparam, CSocket* sock, CBitVector& U, BYTE* keybytes,
			CBitVector& x0, CBitVector& x1, BYTE type, int nbaseOTs, int nchecks, int nbaseseeds, BYTE* seed) {
			Init(nSndVals, symsecparam, sock, U, keybytes, nbaseOTs, nchecks, nbaseseeds, seed);
			m_nOTs = nOTs;
			m_vValues[0] = x0;
			m_vValues[1] = x1;
			m_nBitLength = bitlength;
			m_bProtocol = type;
		};


		Mal_OTExtensionSender(int nSndVals, int symsecparam, CSocket* sock, CBitVector& U, BYTE* keybytes, int nbaseOTs, int nchecks,
			int nbaseseeds, BYTE* seed) {
			Init(nSndVals, symsecparam, sock, U, keybytes, nbaseOTs, nchecks, nbaseseeds, seed);
		};

		void Init(int nSndVals, int symsecparam, CSocket* sock, CBitVector& U, BYTE* keybytes, int nbaseOTs, int nchecks, int nbaseseeds,
			BYTE* seed) {
			m_nSndVals = nSndVals;
			m_vSockets = sock;
			m_nCounter = 0;
			m_nSymSecParam = symsecparam;

			m_nChecks = nchecks;
			m_nBaseOTs = nbaseOTs;

			int keyseeds = nbaseseeds;

			//initialize the seed for generating the random permutations
			m_vPermSeed = (BYTE*)malloc(AES_KEY_BYTES);
			memcpy(m_vPermSeed, seed, AES_KEY_BYTES);
			//m_vPermSeed = seed; //(&m_kPermSeed, seed, 1);

			m_vU.Create(keyseeds);
			m_vU.Copy(U.GetArr(), 0, CEIL_DIVIDE(keyseeds, 8));
			for (int i = keyseeds; i < PadToMultiple(keyseeds, 8); i++)
				m_vU.SetBit(i, 0);

			m_vValues = (CBitVector*)malloc(sizeof(CBitVector) * nSndVals);
			m_vKeySeeds = (AES_KEY_CTX*)malloc(sizeof(AES_KEY_CTX) * keyseeds);
			m_lSendLock = new CLock;

			InitAESKey(m_vKeySeeds, keybytes, keyseeds);

#ifdef FIXED_KEY_AES_HASHING
			m_kCRFKey = (AES_KEY_CTX*)malloc(sizeof(AES_KEY_CTX));
			MPC_AES_KEY_INIT(m_kCRFKey);
			MPC_AES_KEY_EXPAND(m_kCRFKey, fixedkeyseed);
#endif
		};

		~Mal_OTExtensionSender() { free(m_vKeySeeds); };
		BOOL send(int numOTs, int bitlength, CBitVector& s0, CBitVector& s1, BYTE type, int numThreads, MaskingFunction* maskfct);
		BOOL send(int numThreads);

		BOOL OTSenderRoutine(int id, int myNumOTs);
		void BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, int blocksize, BYTE* ctr, snd_check_t* check_vals);
		void ProcessAndEnqueue(CBitVector* snd_buf, int id, int progress, int processedOTs);
		void SendBlocks(int numThreads);
		void MaskInputs(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, int ctr, int processedOTs);
		BOOL verifyOT(int myNumOTs);

		BOOL CheckConsistentReceiveBits(BYTE* rcvhashbuf, OTBlock* tempBlock);
		void UpdateCheckBuf(BYTE* tocheckseed, BYTE* tocheckrcv, int otid, int rowbytelen, snd_check_t* check_vals);
		inline void XORandOWF(BYTE* idaptr, BYTE* idbptr, int rowbytelen, BYTE* tmpbuf, BYTE* resbuf, BYTE* hash_buf);
		inline void genRandomPermutation(linking_t* outperm, int nids, int nperms, int ctr);


	protected:
		BYTE m_bProtocol;
		int m_nSndVals;
		int m_nOTs;
		int m_nBitLength;
		int m_nCounter;
		int m_nBlocks;
		int m_nSymSecParam;
		int m_nBaseOTs;

		CSocket* m_vSockets;
		CBitVector m_vU;
		CBitVector* m_vValues;
		MaskingFunction* m_fMaskFct;
		AES_KEY_CTX* m_vKeySeeds;
		OTBlock* m_sBlockHead;
		OTBlock* m_sBlockTail;
		CLock* m_lSendLock;
		BYTE* m_vPermSeed;

		int m_nChecks;
		BYTE** m_vRcvCheckBuf;
		BYTE** m_vSeedCheckBuf;
		linking_t** m_tPermCheck;

#ifdef FIXED_KEY_AES_HASHING
		AES_KEY_CTX* m_kCRFKey;
#endif

		class OTSenderThread : public CThread {
		public:
			OTSenderThread(int id, int nOTs, Mal_OTExtensionSender* ext) { senderID = id; numOTs = nOTs; callback = ext; success = false; };
			~OTSenderThread() {};
			void ThreadMain() { success = callback->OTSenderRoutine(senderID, numOTs); };
		private:
			int senderID;
			int numOTs;
			Mal_OTExtensionSender* callback;
			BOOL success;
		};

	};



	class Mal_OTExtensionReceiver {
		/*
		 * Malicious OT receiver part
		 * Input:
		 * nSndVals: perform a 1-out-of-nSndVals OT
		 * nOTs: the number of OTs that shall be performed
		 * choices: a vector containing nBaseOTs choices in the domain 0-(SndVals-1)
		 * ret: returns the resulting bit representations, Has to initialized to a byte size of: nOTs * state.field_size
		 *
		 * Output: was the execution successful?
		 */
	public:
		Mal_OTExtensionReceiver(int nSndVals, int nOTs, int bitlength, int symsecparam, CSocket* sock,
			BYTE* keybytes, CBitVector& choices, CBitVector& ret, BYTE protocol, BYTE* seed, int nbaseOTs, int nbaseseeds) {
			Init(nSndVals, symsecparam, sock, keybytes, seed, nbaseOTs, nbaseseeds);
			m_nOTs = nOTs;
			m_nChoices = choices;
			m_nRet = ret;
			m_nBitLength = bitlength;
			m_bProtocol = protocol;
		};
		Mal_OTExtensionReceiver(int nSndVals, int symsecparam, CSocket* sock, BYTE* keybytes, BYTE* seed, int nbaseOTs, int nbaseseeds) {
			Init(nSndVals, symsecparam, sock, keybytes, seed, nbaseOTs, nbaseseeds);
		};

		void Init(int nSndVals, int symsecparam, CSocket* sock, BYTE* keybytes, BYTE* seed, int nbaseOTs, int nbaseseeds) {
			m_nSndVals = nSndVals;
			m_vSockets = sock;
			//m_nKeySeedMtx = vKeySeedMtx;
			m_nSymSecParam = symsecparam;
			m_nBaseOTs = nbaseOTs;
			int keyseeds = nbaseseeds;

			m_nSeed = seed;
			m_nCounter = 0;
			m_vKeySeedMtx = (AES_KEY_CTX*)malloc(sizeof(AES_KEY_CTX) * keyseeds * nSndVals);
			InitAESKey(m_vKeySeedMtx, keybytes, keyseeds * nSndVals);

			m_lSeedLock = new CLock;

#ifdef FIXED_KEY_AES_HASHING
			m_kCRFKey = (AES_KEY_CTX*)malloc(sizeof(AES_KEY_CTX));
			MPC_AES_KEY_INIT(m_kCRFKey);
			MPC_AES_KEY_EXPAND(m_kCRFKey, fixedkeyseed);
#endif
		}

		~Mal_OTExtensionReceiver() { free(m_vKeySeedMtx); };

		BOOL receive(int numOTs, int bitlength, CBitVector& choices, CBitVector& ret, BYTE type,
			int numThreads, MaskingFunction* maskfct);

		BOOL receive(int numThreads);
		BOOL OTReceiverRoutine(int id, int myNumOTs);
		//void ReceiveAndProcess(CBitVector& vRcv, CBitVector& seedbuf, int id, int ctr, int lim);
		void ReceiveAndProcess(int numThreads);
		void BuildMatrices(CBitVector& T,CBitVector& SndBuf, int numblocks, int ctr, BYTE* ctr_buf);
		void HashValues(CBitVector& T, CBitVector& seedbuf, int ctr, int lim);
		BOOL verifyOT(int myNumOTs);

		void ComputeOWF(rcv_check_t* chk_vals);//linking_t* permbits, int nchecks, int otid, int processedOTs, BYTE* outhashes);
		void EnqueueSeed(BYTE* T0, BYTE* T1, int ctr, int numblocks);

	protected:
		BYTE m_bProtocol;
		int m_nSndVals;
		int m_nOTs;
		int m_nBitLength;
		int m_nCounter;
		int m_nSymSecParam;
		int m_nBaseOTs;

		CSocket* m_vSockets;
		CBitVector m_nChoices;
		CBitVector m_nRet;
		CBitVector m_vTempOTMasks;
		BYTE* m_nSeed;
		MaskingFunction* m_fMaskFct;
		AES_KEY_CTX* m_vKeySeedMtx;

		//stores the T0 and T1 matrices for each thread
		exp_seed_t* m_tSeedHead;
		exp_seed_t* m_tSeedTail;
		CLock* m_lSeedLock;

#ifdef FIXED_KEY_AES_HASHING
		AES_KEY_CTX* m_kCRFKey;
#endif


		class OTReceiverThread : public CThread {
		public:
			OTReceiverThread(int id, int nOTs, Mal_OTExtensionReceiver* ext) { receiverID = id; numOTs = nOTs; callback = ext; success = false; };
			~OTReceiverThread() {};
			void ThreadMain() { success = callback->OTReceiverRoutine(receiverID, numOTs); };
		private:
			int receiverID;
			int numOTs;
			Mal_OTExtensionReceiver* callback;
			BOOL success;
		};

	};


#ifdef FIXED_KEY_AES_HASHING
	inline void FixedKeyHashing(AES_KEY_CTX* aeskey, BYTE* outbuf, BYTE* inbuf, BYTE* tmpbuf, int id, int bytessecparam) {
		memset(tmpbuf, 0, AES_BYTES);
		memcpy(tmpbuf, (BYTE*)(&id), sizeof(int));
		for (int i = 0; i < bytessecparam; i++) {
			tmpbuf[i] = tmpbuf[i] ^ inbuf[i];
		}

		MPC_AES_ENCRYPT(aeskey, outbuf, tmpbuf);

		for (int i = 0; i < bytessecparam; i++) {
			outbuf[i] = outbuf[i] ^ inbuf[i];
		}
	}
#endif
}
#endif /* __MAL_OT_EXTENSION_H_ */
