#include "qot_receiver.h"
#include <stdlib.h>
//#include <process.h>

void receiver_okd (OKDOT_RECEIVER * r)
{

	/*opening key files and storing the keys in the receiver structure*/

	FILE *receiverfile;
	int i = 0;

	if ((receiverfile = fopen("../quantum_oblivious_key_distribution_linux/signals/BobObliviousKeys.sgn","r")))
	{
		while (i<KEY_LENGTH)
		{
			if (fscanf(receiverfile, "%u", &r->receiver_OTkey[i]))
				i++;
			else
				printf ("QOT ERROR: failed to read oblivious keys.\n");
		}
	}	
	else
		printf ("QOT ERROR: failed to open oblivious key file: receiver's key file.\n");

	fclose (receiverfile);
	i=0;

	if ((receiverfile = fopen("../quantum_oblivious_key_distribution_linux/signals/BobControlSignal.sgn","r")))
	{
		while (i<KEY_LENGTH)
		{
			if (fscanf(receiverfile,"%u", &r->receiver_OTauxkey[i]))
				i++;
			else
				printf ("QOT ERROR: failed to read oblivious keys.\n");
		}
	}
	else
		printf ("QOT ERROR: failed to open oblivious key file: receiver's auxkey file.\n");

	fclose (receiverfile);

}





void receiver_indexlist (OKDOT_RECEIVER * r)
{
	int j = 0;
	int k = 0;


	/*generate I0 and I1 index lists from the receiver aux key*/
	for (int i = 0; i<KEY_LENGTH; i++)
	{	

		if (r->receiver_OTauxkey[i] == 0)
		{
			printf ("OT SUCCESS: valid key 0 character found.\n");
			r->indexlist[0][j] = i;
			j++;
		}
		else if (r->receiver_OTauxkey[i] == 1)
		{
			printf ("OT SUCCESS: valid key 1 character found.\n");
			r->indexlist[1][k] = i;
			k++;
		}
		else
			printf ("OT ERROR: invalid key character found.\n");
	}

}





void receiver_output (OKDOT_RECEIVER * r, unsigned long long int * vb, unsigned char * output)
{
	unsigned long int input32[KEY_LENGTH/(2*32)] = {0}; 


	/*converts the binary hash inputs into 32bit ints*/
	for (int i=0; i<32; i++)
	{
		for (int j=0; j<KEY_LENGTH/(2*32); j++)
		{	
			input32[j] <<= 1;
			input32[j] += r->receiver_OTkey[r->indexlist[0][i+j*32]] - '0';
		}
	}


	/*hashes pairs of ints from the input32 array into another 32bit value, which is stored in the output array*/
	for (int i=0; i<OUTPUT_LENGTH/32; i++)
	{
		output[i] = (unsigned long int) ((vb[0+3*i]*input32[0+2*i] + vb[1+3*i]*input32[1+2*i] + vb[2+3*i]) >> 32);
	}



}



