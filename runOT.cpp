#include "OTParties.hpp"

// ================================ //
//                                  //
//        Main Functionality        //   
//                                  //
// ================================ //

int main(int argc, char* argv[]) {
    
    int party = atoi(argv[1]);

    // ++++++++++++++++++++++++++++ //
    //      Communication Setup     //
    // ++++++++++++++++++++++++++++ //

    boost::asio::io_service io_service;
    SocketPartyData senderParty = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
    SocketPartyData receiverParty = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);

    shared_ptr<CommParty> myChannel = (party == 0) ? 
        make_shared<CommPartyTCPSynced>(io_service, senderParty, receiverParty) :
        make_shared<CommPartyTCPSynced>(io_service, receiverParty, senderParty);


    // ++++++++++++++++++++++++++++ //
    //         Group Setup          //
    // ++++++++++++++++++++++++++++ //

    shared_ptr<OpenSSLDlogECF2m> dlog = make_shared<OpenSSLDlogECF2m>("include/configFiles/NISTEC.txt", "K-233");
    biginteger p = dlog->getOrder();
    cout << "\nGroup order is: " << p << "\n";

    
    if (party == 0) { // sender

        myChannel->join(500,5000);
        int crs_setup_type = atoi(argv[2]);
        shared_ptr<SenderParty> sender = make_shared<SenderParty>(myChannel, dlog, crs_setup_type);
        
        // run sender
        sender->run(myChannel);

    } else if (party == 1) { // receiver 

        myChannel->join(500, 5000);
        int sigma = atoi(argv[2]);
        shared_ptr<ReceiverParty> receiver = make_shared<ReceiverParty>(myChannel, dlog, sigma);
        
        // run receiver
        receiver->run(myChannel);
    } else {
        std::cerr << "partyId must be 0 or 1" << std::endl;
        return 1;
    }

    return 0;

}
     
    