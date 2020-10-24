#ifndef QOT_RECEIVER_H
#define QOT_RECEIVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#define KEY_LENGTH 512
#define OUTPUT_LENGTH 128

struct qot_receiver
{
		unsigned int receiver_OTkey[KEY_LENGTH];
		unsigned int receiver_OTauxkey[KEY_LENGTH];
		unsigned int indexlist[2][KEY_LENGTH/2];
};

typedef struct qot_receiver OKDOT_RECEIVER;

void receiver_okd(OKDOT_RECEIVER *); //call OKD service and read the output key from text file
void receiver_indexlist(OKDOT_RECEIVER *); //define a pair of index lists based on the oblivious keys
void receiver_output(OKDOT_RECEIVER *, unsigned long long int * , unsigned char *); //set receiver output

#ifdef __cplusplus
}
#endif

#endif //ifndef OT_RECEIVER_H
