#include "qot_receiver.h"
#include "qot_sender.h"

int main()
{
	OKDOT_RECEIVER r;
	OKDOT_SENDER s;
	unsigned char sender_out[2][OUTPUT_LENGTH/32]; //array to store sender's output
	unsigned char receiver_out[OUTPUT_LENGTH/32]; //array to store receiver's output

	unsigned char receiver_in = 1; //receiver choice bit


	/*These 64bit values will define the universal hash functions used in the OT. 
	 * For the sake of simplicity, we define them at the beginning of this test program, 
	 * but in an actual application program they should be chosen at random by the sender during the execution of the protocol.
	 * The MASCOT implementation includes a RNG class, which will be used for this purpose */
	unsigned long long int v[2][12];
	v[0][0] = 0x65d200ce55b19ad8L;	
	v[0][1] = 0x4f2162926e40c299L;
	v[0][2] = 0x162dd799029970f8L;
	v[0][3] = 0x68b665e6872bd1f4L;
	v[0][4] = 0xb6cfcf9d79b51db2L;
	v[0][5] = 0x7a2b92ae912898c2L;
	v[0][6] = 0x65d200ce55b19ad8L;	
	v[0][7] = 0x4f2162926e40c299L;
	v[0][8] = 0x162dd799029970f8L;
	v[0][9] = 0x68b665e6872bd1f4L;
	v[0][10] = 0xb6cfcf9d79b51db2L;
	v[0][11] = 0x7a2b92ae912898c2L;


	v[1][0] = 14719996579123725625U;	
	v[1][1] = 10756103212375473669U;
	v[1][2] = 5130163678318669943U;	
	v[1][3] = 11196048602425907627U;	
	v[1][4] = 9565367076951073642U;	
	v[1][5] = 13747040114869837904U;
	v[1][6] = 15796640148607977966U;	
	v[1][7] = 2315405396079678806U;
	v[1][8] = 17633778172154324773U;
	v[1][9] = 4307822930869792043U;
	v[1][10] = 10460695327545550466U;
	v[1][11] = 11419394045892977570U;





	/*execute OKD and read receiver's key and aux key from file*/
	receiver_okd (&r);
	printf ("Receiver's key: %u\n\n", r.receiver_OTkey[0]);
	//printf ("Receiver's aux key: %s\n\n", r.receiver_OTauxkey);	

	/*execute OKD and read sender's key from file*/
	sender_okd (&s);
	printf ("Receiver's key: %u\n\n", r.receiver_OTkey[0]);
	//printf ("Sender's key: %s\n\n", s.sender_OTkey);

	/*use receiver's aux key to generate two index listes (I0 and I1)*/
	receiver_indexlist (&r);
	//printf ("list 0: %d\n", r.indexlist[0][9]);
	//printf ("list 1: %d\n", r.indexlist[1][9]);


	/*use the (supposedly random) numbers stored in array v, as well as the index listes received from the receiver, to generate the output */
	sender_output (&s, v[0], v[1], r.indexlist[receiver_in], r.indexlist[(receiver_in)^0x1], sender_out);
	
	for (int i=0; i<OUTPUT_LENGTH/32; i++)
		printf ("Sender's output 0: %x   Sender's output 1: %x  \n", sender_out[0][i], sender_out[1][i]);
	printf ("\n\n");


	
	/*use the (supposedly random) numbers stored in array v, as well as the index list I0, to generate the output*/
	receiver_output (&r, v[receiver_in], receiver_out);

	for (int i=0; i<OUTPUT_LENGTH/32; i++)
		printf ("Receiver's output: %x  \n", receiver_out[i]);
	printf ("\n\n");


	/*new execution of the protocol with a different choice bit*/

	receiver_in = 0;

	receiver_okd (&r);
	sender_okd (&s);
	receiver_indexlist (&r);
	
	sender_output (&s, v[0], v[1], r.indexlist[receiver_in], r.indexlist[(receiver_in)^0x1], sender_out);
	for (int i=0; i<OUTPUT_LENGTH/32; i++)
		printf ("Sender's output 0: %x   Sender's output 1: %x  \n", sender_out[0][i], sender_out[1][i]);
	printf ("\n\n");

	receiver_output (&r, v[receiver_in], receiver_out);
	for (int i=0; i<OUTPUT_LENGTH/32; i++)
		printf ("Receiver's output %x  \n", receiver_out[i]);
	printf ("\n\n");



	return 0;
}
