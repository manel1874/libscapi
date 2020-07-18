#include <vector>

#include "OTParties.hpp"


// ================================ //
//                                  //
//              Sender              //   
//                                  //
// ================================ //

SenderParty::SenderParty(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, int crs_setup_type){
    
    
    // ++++++++++++++++++++++++++++ //
    //         Group Setup          //
    // ++++++++++++++++++++++++++++ //

    this->dlog = dlog;


    // ++++++++++++++++++++++++++++ //
    //          OT inputs           //
    // ++++++++++++++++++++++++++++ //    

    // generate two random numbers
    m0 = dlog->createRandomElement();
    m1 = dlog->createRandomElement();

    this->m0 = m0;
    this->m1 = m1;

    // Print sender's message
    auto ele0 = m0.get();
    ECElement * ECele0 = (ECElement*) ele0;
    biginteger test_int0 = ECele0->getX();
    cout << "\nMy first message, m0: " << test_int0 << "\n";

    auto ele1 = m1.get();
    ECElement * ECele1 = (ECElement*) ele1;
    biginteger test_int1 = ECele1->getX();
    cout << "\nMy second message, m1: " << test_int1 << "\n";


    // ++++++++++++++++++++++++++++ //
    //          CRS Setup           //
    // ++++++++++++++++++++++++++++ //

    if(crs_setup_type == 0){ // setup Messy mode
        cout << "\nUsing Messy mode\n";

        // Generate crs
        vector<shared_ptr<GroupElement>> crs;
        crs = genMessySetUp();
        this->crs_sent = crs;

        // Send vector group element to receiver
        send_vec_ecelement(channel, crs_sent);

    } else { // setup Decryption mode 
        cout << "\nUsing Decryption mode\n";

        // Generate crs
        vector<shared_ptr<GroupElement>> crs;
        crs = genDecSetUp();
        this->crs_sent = crs;
        
        // Send vector group element to receiver
        send_vec_ecelement(channel, crs_sent);

    }

}


void SenderParty::run(const shared_ptr<CommParty> & channel) {

    // ++++++++++++++++++++++++++++ //
    //          Receive pk          //
    // ++++++++++++++++++++++++++++ //
    
    vector<shared_ptr<GroupElement>> pk;
    pk = receive_vec_ecelement(channel, this->dlog, 2);

    //this->g = pk_received[0];
    //this->h = pk_received[1];

    this->pk_received = pk;

    
    // ++++++++++++++++++++++++++++ //
    //       m0, m1 Encryption      //
    // ++++++++++++++++++++++++++++ //

    biginteger p = dlog->getOrder();

    
    vector<shared_ptr<GroupElement>> u0__v0_m0;
    u0__v0_m0 = encryptMessage(0, m0); // = y0 
    vector<shared_ptr<GroupElement>> u1__v1_m1; 
    u1__v1_m1 = encryptMessage(1, m1); // = y1

    // ++++++++++++++++++++++++++++ //
    //         Send y0, y1          //
    // ++++++++++++++++++++++++++++ //
    
    vector<shared_ptr<GroupElement>> Y;
    shared_ptr<GroupElement> u0 = u0__v0_m0[0];
    shared_ptr<GroupElement> v0_m0 = u0__v0_m0[1];
    shared_ptr<GroupElement> u1 = u1__v1_m1[0];
    shared_ptr<GroupElement> v1_m1 = u1__v1_m1[1];
    

    Y.push_back(u0);
    Y.push_back(v0_m0);
    Y.push_back(u1);
    Y.push_back(v1_m1);

    send_vec_ecelement(channel, Y);
    

}

// ---------------------------------- //
// ------- Auxiliar Functions ------- //
// ---------------------------------- //

vector<shared_ptr<GroupElement>> SenderParty::genMessySetUp(){

    vector<shared_ptr<GroupElement>> crs;
    // generate two random group generators
    auto g0 = dlog->createRandomGenerator();
    auto g1 = dlog->createRandomGenerator();

    biginteger p = dlog->getOrder();

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


vector<shared_ptr<GroupElement>> SenderParty::genDecSetUp(){

    vector<shared_ptr<GroupElement>> crs;
    
    auto g0 = dlog->createRandomGenerator();

    biginteger p = dlog->getOrder();

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

vector<shared_ptr<GroupElement>> SenderParty::encryptMessage(int message_number, shared_ptr<GroupElement> mi){

    biginteger p = dlog->getOrder();
    vector<shared_ptr<GroupElement>> ui__vi_mi;
    
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

    ui__vi_mi.push_back(ui);
    ui__vi_mi.push_back(vi_mi);

    return ui__vi_mi;

}


// ================================ //
//                                  //
//              Receiver            //   
//                                  //
// ================================ //

ReceiverParty::ReceiverParty(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, int sigma) {

    this->sigma = sigma;
    this->dlog = dlog;

    vector<shared_ptr<GroupElement>> crs;
    crs = receive_vec_ecelement(channel, dlog, 4);
    this->crs_received = crs;



}


void ReceiverParty::run(const shared_ptr<CommParty> & channel) {
    
    
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
    cout << "\nMy chosen element is: " << test_int << "\n";
    
    
}
