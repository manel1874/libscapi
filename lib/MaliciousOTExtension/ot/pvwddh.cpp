#include "pvwddh.h"

namespace maliciousot {

	BOOL PVWDDH::Receiver(int nSndVals, int nOTs, CBitVector& choices, CSocket& socket, BYTE* retbuf)
	{
		fieldelement g[2], h[2], pkg, pkh, u, zkcommit[2];
		//number y, alpha, r[nOTs], zkr, zkchallenge, zkproof, modnum;
		number y, alpha, zkr, zkchallenge, zkproof, modnum;
		number* r = new number[nOTs];
		BYTE *sndbuf, *sndbufptr, *rcvbuf, *rcvbufptr, *retbufptr, *tmpbuf;

		brickexp bg[2];
		brickexp bh[2];
		int i, sndbufsize, rcvbufsize;

		//First step: do initial crs exchange
		sndbufsize = m_fParams.elebytelen * 6;
		sndbuf = (BYTE*)malloc(sndbufsize);

		for (i = 0; i < 2; i++) {
			FieldElementInit(g[i]);
			FieldElementInit(h[i]);
			FieldElementInit(zkcommit[i]);
		}
		FieldElementInit(y);
		FieldElementInit(alpha);

		//use default generator and init brick
		FieldGetGenerator(g[0], m_fParams);
		BrickInit(&bg[0], g[0], m_fParams);

		//generate random y and alpha
		GetRandomNumber(y, m_fParams.secparam, m_fParams);
		GetRandomNumber(alpha, m_fParams.secparam, m_fParams);


		//compute g1 = g0 ^ y and init brick
		BrickPowerMod(&bg[0], g[1], y);
		BrickInit(&bg[1], g[1], m_fParams);

		//sample random rzk for zero-knowledge proof
		FieldElementInit(zkr);
		GetRandomNumber(zkr, m_fParams.secparam, m_fParams);

		sndbufptr = sndbuf;

		//compute h0 = g0 ^ alpha and h1 = g1 ^ alpha
		for (i = 0; i < 2; i++) {
			BrickPowerMod(&bg[i], h[i], alpha);
			BrickInit(&bh[i], h[i], m_fParams);

			//Convert field elements to bytes
			FieldElementToByte(sndbufptr, m_fParams.elebytelen, g[i]);
			sndbufptr += m_fParams.elebytelen;
			FieldElementToByte(sndbufptr, m_fParams.elebytelen, h[i]);
			sndbufptr += m_fParams.elebytelen;

			//ZK-proof data
			BrickPowerMod(&bg[i], zkcommit[i], zkr);
			FieldElementToByte(sndbufptr, m_fParams.elebytelen, zkcommit[i]);
			sndbufptr += m_fParams.elebytelen;
		}
		//send public keys together with proofs to the sender
		socket.Send(sndbuf, sndbufsize);
		free(sndbuf);

		//Second step: for each OT generate and send a public-key and receive challenge + send compute proof
		FieldElementInit(pkg);
		FieldElementInit(pkh);

		sndbufsize = m_fParams.elebytelen * 2 * nOTs + m_fParams.numbytelen;
		sndbuf = (BYTE*)malloc(sndbufsize);
		sndbufptr = sndbuf;

		for (i = 0; i < nOTs; i++) {
			FieldElementInit(r[i]);

			//generate r_i at random and compute g_i = g_sigma_i ^ r_i and h_i = h_sigma_i ^ r_i
			GetRandomNumber(r[i], m_fParams.secparam, m_fParams);
			BrickPowerMod(&bg[choices.GetBit(i)], pkg, r[i]);
			BrickPowerMod(&bh[choices.GetBit(i)], pkh, r[i]);

			//convert elements to bytes
			FieldElementToByte(sndbufptr, m_fParams.elebytelen, pkg);
			sndbufptr += m_fParams.elebytelen;
			FieldElementToByte(sndbufptr, m_fParams.elebytelen, pkh);
			sndbufptr += m_fParams.elebytelen;
		}

		//Receive challenge
		FieldElementInit(zkchallenge);
		FieldElementInit(zkproof);
		FieldElementInit(modnum);

		rcvbuf = (BYTE*)malloc(m_fParams.numbytelen);
		socket.Receive(rcvbuf, m_fParams.numbytelen);
		ByteToNumber(&zkchallenge, m_fParams.numbytelen, rcvbuf);
		free(rcvbuf);

		//Compute proof as zkproof = (zkr + zkchallenge * alpha ) mod q
		NumberModMul(zkproof, alpha, zkchallenge, m_fParams);
		NumberAdd(zkproof, zkproof, zkr);
		NumberMod(zkproof, m_fParams);
		NumberToByte(sndbufptr, m_fParams.numbytelen, zkproof);

		//send data and proof
		socket.Send(sndbuf, sndbufsize);

		//Third step: receive the seeds to the KDF from the sender and generate a random string from the chosen one
		FieldElementInit(u);

		//receive the values
		rcvbufsize = 2 * nOTs * m_fParams.elebytelen;
		rcvbuf = (BYTE*)malloc(rcvbufsize);
		socket.Receive(rcvbuf, rcvbufsize);

		//a buffer for storing the hash input
		tmpbuf = (BYTE*)malloc(m_fParams.elebytelen);

		retbufptr = retbuf;
		rcvbufptr = rcvbuf;

		for (i = 0; i < nOTs; i++, rcvbufptr += (2 * m_fParams.elebytelen), retbufptr += SHA1_BYTES) {
			//convert the received bytes to a field element, compute u_i ^ r_i, and convert u_i^r_i back to bytes
			ByteToFieldElement(&u, m_fParams.elebytelen, rcvbufptr + (choices.GetBit(i) * m_fParams.elebytelen));
			FieldElementPow(u, u, r[i], m_fParams);
			FieldElementToByte(tmpbuf, m_fParams.elebytelen, u);

			//hash u_i^r_i
			hashReturn(retbufptr, tmpbuf, m_fParams.elebytelen, i);
		}

		free(sndbuf);
		free(rcvbuf);
		free(tmpbuf);
		delete[] r;
		return true;
	}


	BOOL PVWDDH::Sender(int nSndVals, int nOTs, CSocket& socket, BYTE* retbuf)
	{
		fieldelement g[2], h[2], pkg, pkh, u, v, gs, ht, zkcommit[2], gchk, zkchk;
		number s, t, zkchallenge, zkproof;

		brickexp bg[2];
		brickexp bh[2];

		BYTE *sndbuf, *sndbufptr, *rcvbuf, *rcvbufptr, *retbufptr, *tmpbuf;

		int i, j, sndbufsize, rcvbufsize;

		//First step: receive the crs and initialize the bricks
		FieldElementInit(zkchallenge);
		GetRandomNumber(zkchallenge, m_fParams.secparam, m_fParams);

		rcvbufsize = 6 * m_fParams.elebytelen;
		rcvbuf = (BYTE*)malloc(rcvbufsize);

		socket.Receive(rcvbuf, rcvbufsize);
		//Send challenge
		sndbuf = (BYTE*)malloc(m_fParams.numbytelen);
		NumberToByte(sndbuf, m_fParams.numbytelen, zkchallenge);
		socket.Send(sndbuf, m_fParams.numbytelen);
		free(sndbuf);
		rcvbufptr = rcvbuf;
		for (i = 0; i < 2; i++) {
			FieldElementInit(g[i]);
			ByteToFieldElement(&g[i], m_fParams.elebytelen, rcvbufptr);
			rcvbufptr += m_fParams.elebytelen;
			BrickInit(&bg[i], g[i], m_fParams);

			FieldElementInit(h[i]);
			ByteToFieldElement(&h[i], m_fParams.elebytelen, rcvbufptr);
			rcvbufptr += m_fParams.elebytelen;
			BrickInit(&bh[i], h[i], m_fParams);

			//Zero-knowledge commits
			FieldElementInit(zkcommit[i]);
			ByteToFieldElement(&zkcommit[i], m_fParams.elebytelen, rcvbufptr);
			rcvbufptr += m_fParams.elebytelen;
		}

		free(rcvbuf);

		//Second step: receive a public-key for each OT
		FieldElementInit(pkg);
		FieldElementInit(pkh);
		FieldElementInit(u);
		FieldElementInit(v);
		FieldElementInit(gs);
		FieldElementInit(ht);
		FieldElementInit(s);
		FieldElementInit(t);
		rcvbufsize = 2 * nOTs * m_fParams.elebytelen + m_fParams.numbytelen;
		rcvbuf = (BYTE*)malloc(rcvbufsize);
		socket.Receive(rcvbuf, rcvbufsize);
		sndbufsize = 2 * nOTs * m_fParams.elebytelen;
		sndbuf = (BYTE*)malloc(sndbufsize);

		tmpbuf = (BYTE*)malloc(m_fParams.elebytelen);

		rcvbufptr = rcvbuf;
		sndbufptr = sndbuf;
		retbufptr = retbuf;

		for (i = 0; i < nOTs; i++) {
			//read pkg_i and pkh_i
			ByteToFieldElement(&pkg, m_fParams.elebytelen, rcvbufptr);
			rcvbufptr += m_fParams.elebytelen;
			ByteToFieldElement(&pkh, m_fParams.elebytelen, rcvbufptr);
			rcvbufptr += m_fParams.elebytelen;


			for (j = 0; j < 2; j++) {
				//choose random si and ti
				GetRandomNumber(s, m_fParams.secparam, m_fParams);
				GetRandomNumber(t, m_fParams.secparam, m_fParams);

				//u_i = g_j^s_i * h_j ^ t_i
				BrickPowerMod(&bg[j], gs, s);
				BrickPowerMod(&bh[j], ht, t);
				FieldElementMul(u, gs, ht, m_fParams);

				//v_i = pkg_i^s_i * pkh_i ^ t_i
				FieldElementDoublePowMul(v, pkg, s, pkh, t, m_fParams);

				//store u_i in the sndbuf
				FieldElementToByte(sndbufptr, m_fParams.elebytelen, u);
				sndbufptr += m_fParams.elebytelen;

				//store v_i in tmpbuf and use v_i as input into the KDF
				FieldElementToByte(tmpbuf, m_fParams.elebytelen, v);
				hashReturn(retbufptr, tmpbuf, m_fParams.elebytelen, i);
				retbufptr += SHA1_BYTES;
			}
		}

		FieldElementInit(zkproof);
		//send the u_i's
		socket.Send(sndbuf, sndbufsize);
		//Verify proof
		ByteToNumber((&zkproof), m_fParams.numbytelen, rcvbufptr);

		//Group check is omitted because both parties use the pre-generated NIST parameters
		FieldElementInit(gchk);
		FieldElementInit(zkchk);

		for (int j = 0; j < 2; j++) {
			//gj ^ zkproof
			BrickPowerMod(&bg[j], gchk, zkproof);

			//zkcommit_j * h_j^zkchallenge
			BrickPowerMod(&bh[j], zkchk, zkchallenge);
			FieldElementMul(zkchk, zkchk, zkcommit[j], m_fParams);

			if (gchk != zkchk) {
				cerr << "Zero-knowledge proof for base-OTs failed!" << endl;
				cerr << gchk << ", vs. " << zkchk << endl;
				exit(0);
			}
		}
		free(rcvbuf);
		free(sndbuf);
		free(tmpbuf);

		return true;
	}



}