#pragma once
/*
 * XORMasking.h
 *
 *  Created on: May 13, 2013
 *      Author: mzohner
 */
#ifndef XORMASKING_H_
#define XORMASKING_H_

#include "maskingfunction.h"

namespace maliciousot {

	class XORMasking : public MaskingFunction
	{
	public:
		XORMasking(int bitlength) { init(bitlength); };
		XORMasking(int bitlength, CBitVector& delta) { m_vDelta = &delta; init(bitlength); };
		~XORMasking() {};


		void init(int bitlength)
		{
			m_nBitLength = bitlength;
		}

		void Mask(int progress, int processedOTs, CBitVector* values, CBitVector* snd_buf, BYTE protocol)
		{
			if (protocol == G_OT)
			{
				snd_buf[0].XORBytes(values[0].GetArr() + CEIL_DIVIDE(progress * m_nBitLength, 8), 0, CEIL_DIVIDE(processedOTs * m_nBitLength, 8));
				snd_buf[1].XORBytes(values[1].GetArr() + CEIL_DIVIDE(progress * m_nBitLength, 8), 0, CEIL_DIVIDE(processedOTs * m_nBitLength, 8));
			}
			else if (protocol == C_OT)
			{
				values[0].SetBytes(snd_buf[0].GetArr(), CEIL_DIVIDE(progress * m_nBitLength, 8), CEIL_DIVIDE(processedOTs * m_nBitLength, 8));//.SetBits(hash_buf, i*m_nBitLength, m_nBitLength);
				int bitPos = progress * m_nBitLength;
				int length = processedOTs * m_nBitLength;
				int bytePos = CEIL_DIVIDE(bitPos, 8);

				//cerr << "Performing masking for " << bytePos << " and " << bitPos << " to " << length << "(" << m_nBitLength << ", " << processedOTs << ")"<< endl;
				values[1].SetBits(values[0].GetArr() + bytePos, bitPos, length);
				values[1].XORBits(m_vDelta->GetArr() + bytePos, bitPos, length);
				snd_buf[1].XORBits(values[1].GetArr() + bytePos, 0, length);
			}
			else if (protocol == S_OT)
			{
				int bitPos = progress * m_nBitLength;
				int length = processedOTs * m_nBitLength;
				int bytePos = CEIL_DIVIDE(bitPos, 8);

				//cerr << "Performing masking for " << bytePos << " and " << bitPos << " to " << length << "(" << m_nBitLength << ", " << processedOTs << ")"<< endl;
				values[1].SetBits(values[0].GetArr() + bytePos, bitPos, length);
				values[1].XORBits(m_vDelta->GetArr() + bytePos, bitPos, length);
				snd_buf[0].XORBits(values[1].GetArr() + bytePos, 0, length);
			}
			else if (protocol == R_OT)
			{
				values[0].SetBytes(snd_buf[0].GetArr(), CEIL_DIVIDE(progress * m_nBitLength, 8), CEIL_DIVIDE(processedOTs * m_nBitLength, 8));
				values[1].SetBytes(snd_buf[1].GetArr(), CEIL_DIVIDE(progress * m_nBitLength, 8), CEIL_DIVIDE(processedOTs * m_nBitLength, 8));
			}
			/*int bitPos = progress * m_nBitLength;
			int length = processedOTs * m_nBitLength;
			int bytePos = CEIL_DIVIDE(bitPos, 8);

			//cerr << "Performing masking for " << bytePos << " and " << bitPos << " to " << length << "(" << m_nBitLength << ", " << processedOTs << ")"<< endl;
			values[1].SetBits(values[0].GetArr() + bytePos, bitPos, length);
			values[1].XORBits(m_vDelta->GetArr() + bytePos, bitPos, length);

			snd_buf.XORBits(values[1].GetArr() + bytePos, 0, length);*/
		};

		//output already has to contain the masks
		void UnMask(int progress, int processedOTs, CBitVector& choices, CBitVector& output, CBitVector& rcv_buf, CBitVector& tmpmask, BYTE protocol)
		{
			int bytelen = CEIL_DIVIDE(m_nBitLength, 8);
			int gprogress = progress * bytelen;
			//int gprogress = progress * m_nBitLength;
			int lim = progress + processedOTs;

			if (protocol == G_OT)
			{
				for (int u, i = progress, offset = processedOTs * bytelen, l = 0; i < lim; i++, gprogress += bytelen, l += bytelen)
				{
					//TODO make this working for single bits
					u = (int)choices.GetBitNoMask(i);
					output.SetXOR(rcv_buf.GetArr() + (u * offset) + l, tmpmask.GetArr() + gprogress, gprogress, bytelen);
					//output.SetBit(gprogress, tmpmask.GetBit(l));
					//output.XORBit(gprogress, rcv_buf.GetBit(u * offset + l));
				}

			}
			else if (protocol == C_OT || protocol == S_OT)
			{
				int gprogress = progress * bytelen;
				output.Copy(tmpmask.GetArr() + gprogress, gprogress, bytelen * processedOTs);
				for (int i = progress, l = 0; i < lim; i++, l += bytelen, gprogress += bytelen)
				{
					if (choices.GetBitNoMask(i))
					{
						//TODO make this working for single bits
						output.XORBytes(rcv_buf.GetArr() + l, gprogress, bytelen);
						//output.XORBitsPosOffset(rcv_buf.GetArr(), l, progress*m_nBitLength, m_nBitLength);
					}
				}
			}
			else if (protocol == R_OT)
			{
				//The seed expansion has already been performed, so do nothing
			}
		};


		void expandMask(CBitVector& out, BYTE* sbp, int offset, int processedOTs, int bitlength)
		{

			if (bitlength <= AES_KEY_BITS)
			{
				for (int i = 0; i < processedOTs; i++, sbp += AES_KEY_BYTES)
				{
					//	cerr << "Setting bits from " << (offset + i) * bitlength << " with " << bitlength << " len " << endl;
						//cerr << "Byte: " << ((unsigned int) sbp[0]) << ", bitlenh = " << bitlength << ", pos = " << (offset + i) * bitlength << ", ";

					out.SetBits(sbp, (offset + i) * bitlength, bitlength);
					//out.PrintBinary();

				}
				//cerr << "Out = "<< endl;
				//out.PrintHex();
			}
			else
			{
				BYTE m_bBuf[AES_BYTES];
				BYTE ctr_buf[AES_BYTES] = { 0 };
				int counter;// = (int) ctr_buf[0];*((int*)ctr_buf);
				AES_KEY_CTX tkey;
				MPC_AES_KEY_INIT(&tkey);
				for (int i = 0, rem; i < processedOTs; i++, sbp += AES_KEY_BYTES)
				{
					MPC_AES_KEY_EXPAND(&tkey, sbp);
					for (counter = 0; counter < bitlength / AES_BITS; counter++)
					{
						MPC_AES_ENCRYPT(&tkey, m_bBuf, ctr_buf);
						out.SetBits(m_bBuf, (offset + i) * bitlength + (counter*AES_BITS), AES_BITS);
					}
					//the final bits
					//cerr << "bits: " << (counter*AES_BITS) << ", bitlength: " << m_nBitLength << endl;
					if ((rem = bitlength - (counter*AES_BITS)) > 0)
					{
						MPC_AES_ENCRYPT(&tkey, m_bBuf, ctr_buf);
						out.SetBits(m_bBuf, (offset + i) * bitlength + (counter*AES_BITS), rem);
					}
				}
			}
		}

	private:
		CBitVector* m_vDelta;
		int m_nBitLength;
	};

}
#endif /* XORMASKING_H_ */
