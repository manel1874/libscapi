#include "include/comm/Comm.hpp"
#include "include/primitives/DlogOpenSSL.hpp"


// ================================ //
//                                  //
//              Sender              //   
//                                  //
// ================================ //

class SenderParty {
private:

    shared_ptr<CommParty> channel;

    DlogGroup* dlog;

    vector<shared_ptr<GroupElement>> crs_sent;

    shared_ptr<GroupElement> m0, m1;

    vector<shared_ptr<GroupElement>> pk_received;

public:

    SenderParty(int argc, char* argv[]){

        // ++++++++++++++++++++++++++++ //
        //         Group Setup          //
        // ++++++++++++++++++++++++++++ //

        DlogGroup* dlog = new OpenSSLDlogECF2m("include/configFiles/NISTEC.txt", "K-233");
        //auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);
        biginteger p = dlog->getOrder();
        cout << "\nOrder is: " << p << "\n";


        // ++++++++++++++++++++++++++++ //
        //          OT inputs           //
        // ++++++++++++++++++++++++++++ //    

        // generate two random numbers
        m0 = dlog->createRandomElement();
        m1 = dlog->createRandomElement();

        // Print for debugging
        /*
        auto ele0 = m0.get();
        ECElement * ECele0 = (ECElement*) ele0;
        biginteger test_int0 = ECele0->getX();
        cout << "\nMy first message, m0: " << test_int0;

        auto ele1 = m1.get();
        ECElement * ECele1 = (ECElement*) ele1;
        biginteger test_int1 = ECele1->getX();
        cout << "\nMy second message, m1: " << test_int1;
        */


        // ++++++++++++++++++++++++++++ //
        //      Communication Setup     //
        // ++++++++++++++++++++++++++++ //
        
        boost::asio::io_service io_service;
        SocketPartyData senderParty, receiverParty;

        senderParty = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
        receiverParty = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);
        
        channel = make_shared<CommPartyTCPSynced>(io_service, senderParty, receiverParty);
        // connect to party one
        channel->join(500, 5000);
        cout <<"channel established"<< endl;


        // ++++++++++++++++++++++++++++ //
        //          CRS Setup           //
        // ++++++++++++++++++++++++++++ //

        if(atoi(argv[2]) == 0){ // setup Messy mode
            
            crs_sent = SenderParty::genMessySetUp(dlog, p);

            // Send vector group element to receiver
            send_vec_ecelement(channel, crs_sent);

        } else { // setup Decryption mode 
            
            crs_sent = SenderParty::genDecSetUp(dlog, p);
            
            // Send vector group element to receiver
            send_vec_ecelement(channel, crs_sent);

        }

    }

    void run() {

        
        // ++++++++++++++++++++++++++++ //
        //          Receive pk          //
        // ++++++++++++++++++++++++++++ //

        pk_received = receive_vec_ecelement(channel, dlog, 2);


        // ++++++++++++++++++++++++++++ //
        //       m0, m1 Encryption      //
        // ++++++++++++++++++++++++++++ //

        biginteger p = dlog->getOrder();

        shared_ptr<GroupElement> u0, v0_m0 = encryptMessage(p, 0, m0); // = y0
        shared_ptr<GroupElement> u1, v1_m1 = encryptMessage(p, 1, m1); // = y1

        // ++++++++++++++++++++++++++++ //
        //         Send y0, y1          //
        // ++++++++++++++++++++++++++++ //

        vector<shared_ptr<GroupElement>> Y;
        Y.push_back(u0);
        Y.push_back(v0_m0);
        Y.push_back(u1);
        Y.push_back(v1_m1);

        send_vec_ecelement(channel, Y);

    }

    // ---------------------------------- //
    // ------- Auxiliar Functions ------- //
    // ---------------------------------- //

    vector<shared_ptr<GroupElement>> genMessySetUp(DlogGroup* dlog, biginteger p){

        vector<shared_ptr<GroupElement>> crs;
        // generate two random group generators
        auto g0 = dlog->createRandomGenerator();
        auto g1 = dlog->createRandomGenerator();

        // generate two random elements in Zp
        shared_ptr<PrgFromOpenSSLAES> gen = get_seeded_prg();
        biginteger r0 = getRandomInRange(0, p-1, gen.get());
        biginteger r1 = getRandomInRange(0, p-1, gen.get());

        // define h0 and h1
        auto h0 = dlog->exponentiate(g0.get(), r0);
        auto h1 = dlog->exponentiate(g1.get(), r1);

        crs.push_back(g0);
        crs.push_back(h0);
        crs.push_back(g1);
        crs.push_back(h1);

        return crs;

    }

    vector<shared_ptr<GroupElement>> genDecSetUp(DlogGroup* dlog, biginteger p){

        vector<shared_ptr<GroupElement>> crs;
        
        auto g0 = dlog->createRandomGenerator();

        p = dlog->getOrder();

        // generate two random elements in Zp
        shared_ptr<PrgFromOpenSSLAES> gen = get_seeded_prg();
        biginteger y = getRandomInRange(0, p-1, gen.get());
        biginteger x = getRandomInRange(0, p-1, gen.get());

        // define g1, h0 and h1
        auto g1 = dlog->exponentiate(g0.get(), y);
        auto h0 = dlog->exponentiate(g0.get(), x);
        auto h1 = dlog->exponentiate(g1.get(), x);

        crs.push_back(g0);
        crs.push_back(h0);
        crs.push_back(g1);
        crs.push_back(h1);

        return crs;

    }

    shared_ptr<GroupElement> encryptMessage(biginteger p, int message_number, shared_ptr<GroupElement> mi){

        // Encrypt mi
        // Generate si and ti
        shared_ptr<PrgFromOpenSSLAES> gen_encmi = get_seeded_prg();
        biginteger si = getRandomInRange(0, p-1, gen_encmi.get());
        biginteger ti = getRandomInRange(0, p-1, gen_encmi.get());
        // Define ui (recall that crs_sent = {g0, h0, g1, h1})
        auto gi_si = dlog->exponentiate(crs_sent[2 * message_number].get(), si);
        auto hi_ti = dlog->exponentiate(crs_sent[2 * message_number + 1].get(), ti);
        auto ui = dlog->multiplyGroupElements(gi_si.get(), hi_ti.get());
        // Define vi
        auto gsig_si = dlog->exponentiate(pk_received[0].get(), si);
        auto hsig_ti = dlog->exponentiate(pk_received[1].get(), ti);
        auto vi = dlog->multiplyGroupElements(gsig_si.get(), hsig_ti.get());
        // Define vi_mi
        auto vi_mi = dlog->multiplyGroupElements(vi.get(), mi.get());

        return ui, vi_mi;

    }

    // Send vector of EC group elements to receiver
    void send_vec_ecelement(shared_ptr<CommParty> channel, vector<shared_ptr<GroupElement>> vec_ecelem){
    
        for (shared_ptr<GroupElement> ecelem : vec_ecelem){
            auto ecelem_sendable = ecelem->generateSendableData();
            auto ecelem_sendableStr = ecelem_sendable->toString();
            channel->writeWithSize(ecelem_sendableStr);
        }
        
    }

    // Receive vector of EC group elements from sender
    vector<shared_ptr<GroupElement>> receive_vec_ecelement(shared_ptr<CommParty> channel, DlogGroup* dlog, int size){

        vector<shared_ptr<GroupElement>> vec_ecelem;

        for (int i=0; i < size; i++){

            shared_ptr<GroupElement> ecelem;
            shared_ptr<GroupElementSendableData> ecelem_sendable = make_shared<ECElementSendableData>(dlog->getOrder(), dlog->getOrder());
            //shared_ptr<GroupElementSendableData> elem_receivable = make_shared<ZpElementSendableData>(dlog->getOrder());
            vector<byte> raw_ecelement;
            channel->readWithSizeIntoVector(raw_ecelement);
            ecelem_sendable->initFromByteVector(raw_ecelement);
            ecelem = dlog->reconstructElement(true, ecelem_sendable.get());

            vec_ecelem.push_back(ecelem);
        }

        return vec_ecelem;

    }

};


// ================================ //
//                                  //
//              Receiver            //   
//                                  //
// ================================ //

class ReceiverParty {
private:

    shared_ptr<CommParty> channel;

    int sigma;

    DlogGroup* dlog;

    vector<shared_ptr<GroupElement>> crs_received;
    
    biginteger r;

    shared_ptr<GroupElement> g;
    shared_ptr<GroupElement> h;

public:

    ReceiverParty(int argc, char* argv[]) {

        // ++++++++++++++++++++++++++++ //
        //          OT inputs           //
        // ++++++++++++++++++++++++++++ //    
        
        sigma = atoi(argv[2]);

        // ++++++++++++++++++++++++++++ //
        //      Communication Setup     //
        // ++++++++++++++++++++++++++++ //
        
        boost::asio::io_service io_service;
        SocketPartyData senderParty, receiverParty;

        senderParty = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8000);
        receiverParty = SocketPartyData(boost_ip::address::from_string("127.0.0.1"), 8001);
        
        channel = make_shared<CommPartyTCPSynced>(io_service, receiverParty, senderParty);
        // connect to party one
        channel->join(500, 5000);
        cout<<"channel established"<<endl;

        // ++++++++++++++++++++++++++++ //
        //         Group Setup          //
        // ++++++++++++++++++++++++++++ //

        DlogGroup* dlog = new OpenSSLDlogECF2m("include/configFiles/NISTEC.txt", "K-233");
        //auto dlog = make_shared<OpenSSLDlogZpSafePrime>(128);
        biginteger p = dlog->getOrder();
        cout << "\nOrder is: " << p << "\n";

        // ++++++++++++++++++++++++++++ //
        //          CRS Setup           //
        // ++++++++++++++++++++++++++++ //    

        crs_received = receive_vec_ecelement(channel, dlog, 4);

    }

    void run() {

        // ++++++++++++++++++++++++++++ //
        //        Key Generation        //
        // ++++++++++++++++++++++++++++ // 
        biginteger p = dlog->getOrder();

        shared_ptr<PrgFromOpenSSLAES> gen = get_seeded_prg();
        r = getRandomInRange(0, p-1, gen.get());

        auto g_sigma = crs_received[2 * sigma];
        auto h_sigma = crs_received[2 * sigma + 1];
        auto g = dlog->exponentiate(g_sigma.get(), r);
        auto h = dlog->exponentiate(h_sigma.get(), r);


        // ++++++++++++++++++++++++++++ //
        //           Send pk            //
        // ++++++++++++++++++++++++++++ //
        vector<shared_ptr<GroupElement>> pk;
        pk.push_back(g);
        pk.push_back(h);

        send_vec_ecelement(channel, pk);


        // ++++++++++++++++++++++++++++ //
        //        Receive y0, y1        //
        // ++++++++++++++++++++++++++++ //

        vector<shared_ptr<GroupElement>> Y_received = receive_vec_ecelement(channel, dlog, 4);

        auto usig = Y_received[2 * sigma];
        auto vsig_msig = Y_received[2 * sigma + 1];

        auto vsig_computed = dlog->exponentiate(usig.get(), r);
        auto vsig_comp_inverse = dlog->getInverse(vsig_computed.get());
        auto msig = dlog->multiplyGroupElements(vsig_msig.get(), vsig_comp_inverse.get());


        // ++++++++++++++++++++++++++++ //
        //         Print m_sigma        //
        // ++++++++++++++++++++++++++++ //

        auto ele = msig.get();
        ECElement * ECele = (ECElement*) ele;
        biginteger test_int = ECele->getX();
        cout << "\nMy chosen element is: " << test_int;


    }


    // Send vector of EC group elements to receiver
    void send_vec_ecelement(shared_ptr<CommParty> channel, vector<shared_ptr<GroupElement>> vec_ecelem){
    
        for (shared_ptr<GroupElement> ecelem : vec_ecelem){
            auto ecelem_sendable = ecelem->generateSendableData();
            auto ecelem_sendableStr = ecelem_sendable->toString();
            channel->writeWithSize(ecelem_sendableStr);
        }
        
    }

    // Receive vector of EC group elements from sender
    vector<shared_ptr<GroupElement>> receive_vec_ecelement(shared_ptr<CommParty> channel, DlogGroup* dlog, int size){

        vector<shared_ptr<GroupElement>> vec_ecelem;

        for (int i=0; i < size; i++){

            shared_ptr<GroupElement> ecelem;
            shared_ptr<GroupElementSendableData> ecelem_sendable = make_shared<ECElementSendableData>(dlog->getOrder(), dlog->getOrder());
            //shared_ptr<GroupElementSendableData> elem_receivable = make_shared<ZpElementSendableData>(dlog->getOrder());
            vector<byte> raw_ecelement;
            channel->readWithSizeIntoVector(raw_ecelement);
            ecelem_sendable->initFromByteVector(raw_ecelement);
            ecelem = dlog->reconstructElement(true, ecelem_sendable.get());

            vec_ecelem.push_back(ecelem);
        }

        return vec_ecelem;

    }

};


// ================================ //
//                                  //
//        Main Functionality        //   
//                                  //
// ================================ //

int main(int argc, char* argv[]) {

    cout << "Here";
    
    int partyNum = atoi(argv[1]);
    
    
    if (partyNum == 0) { // sender
        // create sender party with input elements
        SenderParty sender(argc, argv);
        // run sender
        sender.run();
    } else if (partyNum == 1) { // receiver 
        // create receiver party with input elements
        ReceiverParty receiver(argc, argv);
        // run receiver
        receiver.run();
    } else {
        std::cerr << "partyId must be 0 or 1" << std::endl;
        return 1;
    }
    

    return 0;

}
     
    