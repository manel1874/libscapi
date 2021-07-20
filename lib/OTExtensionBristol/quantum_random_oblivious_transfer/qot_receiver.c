#include "qot_receiver.h"
#include <stdlib.h>
//#include <process.h>
#include <string.h>

void receiver_okd (OKDOT_RECEIVER * r)
{

	/*opening key files and storing the keys in the receiver structure*/

	FILE *receiverfile;
	FILE *tempFile;
	//char * line = NULL;
	//size_t len = 0;
	//ssize_t read;

	int i = 0;

	//char cwd[1024];
    //getcwd(cwd, sizeof(cwd));
    //printf("Current working dir: %s\n", cwd);

    //char bobOKPath[1024];
    //strncpy(bobOKPath, cwd, 1024);
    //strcat(bobOKPath, "quantum_oblivious_key_distribution/signals/oblivious_keys.txt");
	//printf("Bob Oblivious Key path: %s\n", bobOKPath);


	if ((receiverfile = fopen("quantum_oblivious_key_distribution/signals/oblivious_keys.txt","r")))
	{
		for(int j = 0; j < 4; j++)
		{// skip first 4 lines
			if(fscanf(receiverfile, "%*[^\n]\n")){}
		}

		char aux_okey[KEY_LENGTH];
		if (fscanf(receiverfile, "%[^\n]", aux_okey) > 0)
		{
			while(i<KEY_LENGTH/2)
			{
				unsigned int aux_okey_uint = (unsigned int)aux_okey[2*i];
				unsigned int okey_uint = (unsigned int)aux_okey[2*i + 1];
				if(aux_okey_uint == 48) // If aux_key is zero
				{
					r->receiver_OTauxkey[2*i] = 0; // The first element is known
					r->receiver_OTauxkey[2*i + 1] = 1; // The second element is unkown

					r->receiver_OTkey[2*i] = okey_uint - 48; //Saves the value known by the receiver
					r->receiver_OTkey[2*i + 1] = 1; // Saves 1: meaning it is unkown

				}else{
					r->receiver_OTauxkey[2*i] = 1; // The first element is unknown
					r->receiver_OTauxkey[2*i + 1] = 0; // The second element is known

					r->receiver_OTkey[2*i] = 1; // Saves 1: meaning it is unkown 
					r->receiver_OTkey[2*i + 1] = okey_uint - 48; // Saves the value known by the receiver
				}
				i++;
			}
		}else
		{
			printf ("QOT ERROR: No more oblivious.\n");
		}
	}
	else
		printf ("QOT ERROR: failed to open oblivious key file: receiver's auxkey file.\n");


	// Delete one line
	tempFile = fopen("delete-line.tmp", "w");

	if(tempFile == NULL)
	{
		printf("Unnable to create temporary file.\n");
		printf("Please check you have read/write previleges.\n");
		exit(EXIT_FAILURE);
	}

	// Move src file pointer to beginning
	rewind(receiverfile);
	// Delete given line from file
	deleteLine(receiverfile, tempFile, 5);

	// Close all open files
	fclose(tempFile);
	fclose(receiverfile);

	// Delete src file and rename temp file as src
	remove("quantum_oblivious_key_distribution/signals/oblivious_keys.txt");
	rename("delete-line.tmp", "quantum_oblivious_key_distribution/signals/oblivious_keys.txt");


}





void receiver_indexlist (OKDOT_RECEIVER * r)
{
	int j = 0;
	int k = 0;


	/*generate I0 and I1 index lists from the receiver aux key*/
	for (int i = 0; i<KEY_LENGTH; i++)
	{	
		
		if (r->receiver_OTauxkey[i] == 0) // known bit
		{
			r->indexlist[0][j] = i;
			j++;
		}
		else if (r->receiver_OTauxkey[i] == 1) // unkown bit
		{
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



