#include "COTSK.h"
#define DEBUG_PRINT

/**
* Test Program for the OT functionality with shorty keys
* This is the only file that needs to be included and used directly 
* See COTSK.h for documentation on the protocol
*
* Written by: Assi Barak, April 2018
*/
#include "args.hxx"

int main(int argc, char *argv[]) {
	
	/*
	* Parse command line - get Party Id. (0,...)
	*/
	
	args::ArgumentParser parser("This is a test program.", "This goes after the options.");
    args::HelpFlag help(parser, "help", "Display this help menu", {'h', "help"});
	args::ValueFlag<int> arg_partyId(parser, "partyId", "Id of the local party", {'p'});	
	args::ValueFlag<long> arg_numPartyOne(parser, "numPartyOne", "number of parties in P1 commitee", {"np1"}, 2);	
	args::ValueFlag<long> arg_numPartyTwo(parser, "numPartyTwo", "number of parties in P2 commitee", {"np2"}, 2);	
	args::ValueFlag<uint32_t> arg_l(parser, "L", "Short key length ", {'l'}, 16);	
	args::ValueFlag<uint32_t> arg_mBytes(parser, "mBytes", "M size (in bytes) for extend test", {'m'}, 1024*10);	
  	args::ValueFlag<long> arg_repeat(parser, "repeat", "Number of timer extend is repeated ", {'r'}, 1);	
  	args::CompletionFlag completion(parser, {"complete"});
    try
    {
        parser.ParseCLI(argc, argv);
    }
    catch (args::Completion e)
    {
        std::cout << e.what();
        return 0;
    }
    catch (args::Help)
    {
        std::cout << parser;
        return 0;
    }
    catch (args::ParseError e)
    {
        std::cerr << e.what() << std::endl;
        std::cerr << parser;
        return 1;
    }
	
	int my_num =  args::get(arg_partyId);
	uint32_t L = args::get(arg_l);
    uint32_t m_bytes = args::get(arg_mBytes);
	int REPEAT_EXTEND = args::get(arg_repeat);
	/*
	* Number of parties in each grCommitee. By default this is set to 2 and 2
	* When running the progam, the party Id should be passed as a parameter
	* parties 0, 1 will be in Commitee_P1 , and parties 2 and 3 in Commitee_P2
	*/
    int NUM_P1 = args::get(arg_numPartyOne);
	int NUM_P2 = args::get(arg_numPartyTwo);
	/*
	* Peer IPs. Default uses localhost for all parties 
	*/
	vector<string> p1ips(NUM_P1,"127.0.0.1");
    vector<string> p2ips(NUM_P2,"127.0.0.1");

	/*
	 * Parties in Committee 1. Instantiate a COTSK_pOne object 
	*/
	
 	if (my_num < NUM_P1 ) { //pOne
   	    	auto p1 = new COTSK_pOne(L, m_bytes, my_num ,"127.0.0.1" ,p2ips);
		    vector<byte> delta(L);
			for (uint32_t i=0; i < L; i++) {
				delta[i] = (i % 2 == 0) ? 0x00 : 0x01; 
			}
			auto start = scapi_now();
			p1->initialize(delta);
		    print_elapsed_ms(start, "initialize ");
		
#ifdef DEBUG_PRINT
	        cout << "** Status :: Initialize Complete" << endl;
#endif

 			vector<byte *> q_i_j(p2ips.size());
	
			start = scapi_now();
			for (int i = 0; i < REPEAT_EXTEND; i++) {
				p1->extend (q_i_j);
			
#ifdef DEBUG_PRINT
				//assert( q_i_j[0] != nullptr);
				//byte *tmp = q_i_j[0];
				//cout << "touch byte" << hex << (int)tmp[0] << endl;
#endif	
			}
		    print_elapsed_ms(start, "extend ");
				
#ifdef DEBUG_PRINT
	        cout << "** Status :: Extend Complete" << endl;
#endif
    }
	/*
     * Parties in Committee 2. Instantiate a COTSK_pTwo object 
	 */
	else if (my_num <= NUM_P1 + NUM_P2) { //pTwo
       		auto p2 = new COTSK_pTwo(L, m_bytes , my_num - NUM_P1 ,"127.0.0.1" ,p1ips);

			auto start = scapi_now();
			p2->initialize();  		
			print_elapsed_ms(start, "initialize ");


		
#ifdef DEBUG_PRINT
	        cout << "** Status :: Initialize Complete" << endl;
#endif
  		    vector<byte> x(m_bytes);
 			vector<byte *> t_j_i_out(p1ips.size());
		
			start = scapi_now();
			for (int i = 0; i < REPEAT_EXTEND; i++) {
				p2->extend(x.data(),t_j_i_out);
				
#ifdef DEBUG_PRINT
				//assert( t_j_i_out[0] != nullptr);
				//byte *tmp = t_j_i_out[0];
				//cout << "touch byte" << hex << (int)tmp[0] << endl;
#endif				
			}
		    print_elapsed_ms(start, "extend ");
		
#ifdef DEBUG_PRINT
	        cout << "** Status :: Extend Complete" << endl;
#endif
    }

}
