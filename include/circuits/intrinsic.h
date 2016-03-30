/********************************************************************/
/* Copyright(c) 2014, Intel Corp.                                   */
/* Developers and authors: Shay Gueron (1) (2)                      */
/* (1) University of Haifa, Israel                                  */
/* (2) Intel, Israel                                                */
/* IPG, Architecture, Israel Development Center, Haifa, Israel      */
/********************************************************************/
#ifndef AES_KS4X_KS_Y_H
#define AES_KS4X_KS_Y_H

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct KEY_SCHEDULE
	{
		unsigned char KEY[16 * 15];
		unsigned int nr;
	} ROUND_KEYS;
	
	
	void intrin_sequential_ks4_enc8(const unsigned char* PT, unsigned char* CT, int test_length, unsigned char* KEYS, unsigned char* first_key, unsigned char* TEMP_BUF);
	void intrin_sequential_ks2_enc2(const unsigned char* PT, unsigned char* CT, int test_length, unsigned char* KEYS, unsigned char* first_key, unsigned char* TEMP_BUF);
	void intrin_parallel_ks1_enc1(const unsigned char* PT, unsigned char* CT, int test_length, unsigned char* KEYS, unsigned char* first_key, unsigned char* TEMP_BUF);
	void intrin_sequential_ks1_enc1(const unsigned char* PT, unsigned char* CT, int test_length, unsigned char* KEYS, unsigned char* first_key, unsigned char* TEMP_BUF);
	void intrin_sequential_ks4_enc4(const unsigned char* PT, unsigned char* CT, int test_length, unsigned char* KEYS, unsigned char* first_key, unsigned char* TEMP_BUF);



#ifdef __cplusplus
};
#endif
#endif