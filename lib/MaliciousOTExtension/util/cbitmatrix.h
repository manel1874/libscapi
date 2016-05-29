#pragma once
/*
 * cbitmatrix.h
 *
 *  Created on: May 6, 2013
 *      Author: mzohner
 */
#ifndef CBITMATRIX_H_
#define CBITMATRIX_H_

#include "cbitvector.h"
#include "../util/typedefs.h"


/*static const REGISTER_SIZE TRANSPOSITION_MASKS[6] =
	{0x5555555555555555, 0x3333333333333333, 0x0F0F0F0F0F0F0F0F, 0x00FF00FF00FF00FF, 0x0000FFFF0000FFFF, 0x00000000FFFFFFFF};
static const REGISTER_SIZE TRANSPOSITION_MASKS_INV[6] =
	{0xAAAAAAAAAAAAAAAA, 0xCCCCCCCCCCCCCCCC, 0xF0F0F0F0F0F0F0F0, 0xFF00FF00FF00FF00, 0xFFFF0000FFFF0000, 0xFFFFFFFF00000000};
static const int MOD_MASK[6] =
	{0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F};
*/

namespace maliciousot {

	class CBitMatrix
	{
	public:
		CBitMatrix() { m_pBits = NULL; }
		CBitMatrix(int rows, int colbits) { m_pBits = NULL; Create(rows, colbits); }
		~CBitMatrix() { if (m_pBits) delete[] m_pBits; }
		void delCBitMatrix() { for (int i = 0; i < m_nRows; i++) { m_pBits[i].delCBitVector(); } }
		void Create(int rows)
		{
			if (m_pBits) delete[] m_pBits;

			m_pBits = new CBitVector[rows];
			m_nRows = rows;
		}


		void Create(int rows, int colbits)
		{
			if (m_pBits) delete[] m_pBits;

			m_pBits = new CBitVector[rows];
			m_nRows = rows;

			for (int i = 0; i < rows; i++)
				m_pBits[i].Create(colbits);
		}


		void FillRand(int colbits, BYTE* seed, int& cnt)
		{
			for (int i = 0; i < m_nRows; i++)
				m_pBits[i].FillRand(colbits, seed, cnt);
		}

		void Create(int rows, int colbits, BYTE* seed, int& cnt)
		{
			if (m_pBits) delete[] m_pBits;

			m_pBits = new CBitVector[rows];
			m_nRows = rows;

			for (int i = 0; i < rows; i++)
				m_pBits[i].Create(colbits, seed, cnt);
		}


		//An efficient implementation of te matrix transposition of 80x128 bit matrices using Euklundhs algorithm
		//Copies the result of the transposed matrix into the CBitVectors at positions matrixpos + 0:128.
		//tMatrix has to contain values that have at least 80bit space
		void transpose80x128(BYTE* matrix, int matrixpos)
		{
			//REGISTER_SIZE temp_mat[160];
			REGISTER_SIZE* temp_mat;
			REGISTER_SIZE* rowaptr;//ptr;
			REGISTER_SIZE* rowbptr;
			REGISTER_SIZE temp_row;
			REGISTER_SIZE mask;
			REGISTER_SIZE invmask;


			int i, j, idx = 1, ctr, didx;
			int numrounds;
			temp_mat = (REGISTER_SIZE*)matrix;

			for (i = 0; i < 6; i++, idx *= 2)
			{
				numrounds = (i < 4 ? 160 : 128);
				rowaptr = temp_mat;
				rowbptr = rowaptr + 2 * idx;//ptr = temp_mat;
				mask = TRANSPOSITION_MASKS[i];
				invmask = TRANSPOSITION_MASKS_INV[i];
				didx = 2 * idx;

				for (j = 0, ctr = 0; j < numrounds;)
				{
					//Swap rows and interweave elements
					temp_row = *rowaptr;//*ptr;
					if (i > 2)  //If operating on byte level, take care of endianess.
					{
						*rowaptr = ((*rowaptr & mask) ^ ((*rowbptr & mask) << idx)); //Perform Euklundh algoritm's swapping on bit level
						*rowbptr = ((*rowbptr & invmask) ^ ((temp_row & invmask) >> idx)); //Perform Euklundh algoritm's swapping on bit level
					}
					else
					{
						*rowaptr = ((*rowaptr & invmask) ^ ((*rowbptr & invmask) >> idx)); //Perform Euklundh algoritm's swapping on bit level
						*rowbptr = ((*rowbptr & mask) ^ ((temp_row & mask) << idx)); //Perform Euklundh algoritm's swapping on bit level
					}

					//go to the next line that should be transposed (note the blockwise processing as i grows, this makes it a bit more complex)
					if ((++j) & (didx))
					{
						j += didx;
						rowaptr += didx + 1;
						rowbptr += didx + 1;
					}
					else
					{
						rowaptr++;
						rowbptr++;
					}
				}
			}

			//Copy transposed matrix into source bit vector and swap the blocks into the correct order
			for (i = 0; i < 64; i++)
			{
				memcpy(m_pBits[matrixpos + i].GetArr(), temp_mat + 2 * i, 8);
				memcpy(m_pBits[matrixpos + i].GetArr() + 8, ((BYTE*)(temp_mat + 128 + 2 * (i & 0x0F))) + ((i >> 4) * 2), 2);

				memcpy(m_pBits[64 + matrixpos + i].GetArr(), temp_mat + 2 * i + 1, 8);
				memcpy(m_pBits[64 + matrixpos + i].GetArr() + 8, ((BYTE*)(temp_mat + 128 + 2 * (i & 0x0F) + 1)) + ((i >> 4) * 2), 2);
			}
		}



		void EklundhBitTranspose(BYTE* matrix, int rows, int columns)
		{
			REGISTER_SIZE* rowaptr;//ptr;
			REGISTER_SIZE* rowbptr;
			REGISTER_SIZE temp_row;
			REGISTER_SIZE mask;
			REGISTER_SIZE invmask;

			int offset = (columns / 8) / sizeof(REGISTER_SIZE);
			int numrounds = ((columns >> 3) / sizeof(REGISTER_SIZE)) * rows;
			int numiters = CEIL_LOG2(rows);
			int srcidx = 1, destidx;

			//If swapping is performed on bit-level
			for (int i = 0, j; i < LOG2_REGISTER_SIZE; i++, srcidx *= 2)
			{
				destidx = offset*srcidx;
				rowaptr = (REGISTER_SIZE*)matrix;
				rowbptr = rowaptr + destidx;//ptr = temp_mat;

				//cerr << "numrounds = " << numrounds << " iterations: " <<endl;
				//Preset the masks that are required for bit-level swapping operations

				mask = TRANSPOSITION_MASKS[i];
				invmask = ~mask;

				for (j = 0; j < numrounds;)
				{
					//Swap rows and interweave elements
					temp_row = *rowaptr;//*ptr;
					//If swapping is performed on byte-level reverse operations due to little-endian format.
					if (i > 2)
					{
						*rowaptr = ((*rowaptr & mask) ^ ((*rowbptr & mask) << srcidx));
						*rowbptr = ((*rowbptr & invmask) ^ ((temp_row & invmask) >> srcidx));
					}
					else
					{
						*rowaptr = ((*rowaptr & invmask) ^ ((*rowbptr & invmask) >> srcidx));
						*rowbptr = ((*rowbptr & mask) ^ ((temp_row & mask) << srcidx));
					}


					//go to the next line that should be transposed (note the blockwise processing as i grows, this makes it a bit more complex)
					if ((++j) & destidx)
					{
						j += destidx;
						rowaptr += destidx + 1;
						rowbptr += destidx + 1;
					}
					else
					{
						rowaptr++;
						rowbptr++;
					}
				}
			}


			for (int i = LOG2_REGISTER_SIZE, j, swapoffset = 1, dswapoffset; i < numiters; i++, srcidx *= 2, swapoffset = swapoffset << 1)
			{
				destidx = offset*srcidx;
				dswapoffset = swapoffset << 1;

				rowaptr = (REGISTER_SIZE*)matrix;
				rowbptr = rowaptr + destidx - swapoffset;//ptr = temp_mat;


				for (j = 0; j < numrounds;)
				{

					if ((j%dswapoffset >= swapoffset))
					{
						temp_row = *rowaptr;
						*rowaptr = *rowbptr;
						*rowbptr = temp_row;
					}

					if ((++j) & (destidx))
					{
						j += destidx;
						rowaptr += destidx + 1;
						rowbptr += destidx + 1;
					}
					else
					{
						rowaptr++;
						rowbptr++;
					}
				}
			}

			//Copy transposed matrix into source bit vector and swap the blocks into the correct order
			for (int i = 0; i < AES_BITS; i++)
			{
				memcpy(m_pBits[i].GetArr(), ((REGISTER_SIZE*)matrix) + offset*i, 16);
			}
		}

		void Print()
		{
			for (int i = 0; i < m_nRows; i++)
			{
				m_pBits[i].PrintBinary();
			}
		}

		void Print(BYTE* matrix)
		{
			for (int i = 0; i < 128; i++)
			{
				for (int j = 0; j < 128; j++)
				{
					cerr << !!(matrix[(i * 128 + j) / 8] & (1 << (j % 8)));
				}
				cerr << endl;
			}
		}




		CBitVector& operator [] (int i) { return m_pBits[i]; }
	private:

		CBitVector*	 m_pBits;
		int			 m_nRows;
	};

}


#endif /* CBITMATRIX_H_ */
