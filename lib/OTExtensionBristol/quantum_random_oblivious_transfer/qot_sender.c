#include "qot_sender.h"
#include <stdlib.h>

void sender_okd (OKDOT_SENDER * s)
{

	/*opening key file and storing the key in the sender structure*/

	FILE *senderfile;
	FILE *tempFile;
	//char * line = NULL;
	//size_t len = 0;
	//ssize_t read;

	int i = 0;

	//char cwd[1024];
    //getcwd(cwd, sizeof(cwd));
    //printf("Current working dir: %s\n", cwd);

	if ((senderfile = fopen("quantum_oblivious_key_distribution/signals/oblivious_keys.txt","r")))
	{
		printf("QOT SUCCESS: oblivious key file successfully opened.");
		for(int j = 0; j < 4; j++)
		{// skip first 4 lines
			if(fscanf(senderfile, "%*[^\n]\n")){}
		}

		// Save key to sender struct
		char okey[KEY_LENGTH];
		if (fscanf(senderfile, "%[^\n]", okey) > 0)
		{
			while(i<KEY_LENGTH)
			{
				unsigned int okey_uint = (unsigned int)okey[i];
				s->sender_OTkey[i] = okey_uint - 48;
				i++;
			}
		}else
		{
			printf ("QOT ERROR: No more oblivious.\n");
		}
			
	}
	else
		printf ("QOT ERROR: failed to open oblivious key file: sender's key file DOES THIS CHANGE?? .\n");

	// Delete one line
	tempFile = fopen("delete-line.tmp", "w");

	if(tempFile == NULL)
	{
		printf("Unnable to create temporary file.\n");
		printf("Please check you have read/write previleges.\n");
		exit(EXIT_FAILURE);
	}

	// Move src file pointer to beginning
	rewind(senderfile);
	// Delete given line from file
	deleteLine(senderfile, tempFile, 5);

	// Close all open files
	fclose(tempFile);
	fclose (senderfile);

	// Delete src file and rename temp file as src
	remove("quantum_oblivious_key_distribution/signals/oblivious_keys.txt");
	rename("delete-line.tmp", "quantum_oblivious_key_distribution/signals/oblivious_keys.txt");

}



void sender_output (OKDOT_SENDER * s, unsigned long long int * v0 , unsigned long long int * v1, unsigned int * indexb, 
		unsigned int * indexb1, unsigned char (*output)[OUTPUT_LENGTH/32])
{
	unsigned long int input32b[KEY_LENGTH/(2*32)] = {0};
	unsigned long int input32b1[KEY_LENGTH/(2*32)] = {0};


	/*converts the binary hash inputs into 32bit ints*/
	for (int i = 0; i < 32; i++)
	{
		for (int j=0; j<KEY_LENGTH/(2*32); j++)
		{
			input32b[j] <<= 1;
			input32b1[j] <<= 1;

			input32b[j] += s->sender_OTkey[indexb[i+j*32]]  - '0';
			input32b1[j] += s->sender_OTkey[indexb1[i+j*32]] - '0';
		}
	}


	/*hashes pairs of ints from the input32b and intput32b1 arrays into another 32bit value, which is then stored in the output array*/
	for (int i=0; i<OUTPUT_LENGTH/32; i++)
	{
		output[0][i] = (unsigned long int)((v0[0+3*i]*input32b[0+2*i] + v0[1+3*i]*input32b[1+2*i] + v0[2+3*i]) >> 32);
		output[1][i] = (unsigned long int)((v1[0+3*i]*input32b1[0+2*i] + v1[1+3*i]*input32b1[1+2*i] + v1[2+3*i]) >> 32); 		
	}

}




void deleteLine(FILE *srcFile, FILE *tempFile, const int line)
{
	int BUFFER_SIZE = KEY_LENGTH*8;
	char buffer[BUFFER_SIZE];
	int count = 1;

	while((fgets(buffer, BUFFER_SIZE, srcFile)) != NULL)
	{
		if(line != count)
			fputs(buffer, tempFile);
		count++;
	}

}




