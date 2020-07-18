#include <vector>

#include "OTParties.hpp"


// ================================================================ //
//                                                                  //
//                            Protocol                              //   
//                                                                  //
// ================================================================ //

/**
 * 
 * 
 * Sender:
 *      o Input: m0, m1
 *      o Output: Nothing
 * 
 * Receiver:
 *      o Input: sigma \in {0, 1}
 *      o Output: m_sigma
 * 
 * PROTOCOL:
 * 
 * Sender:
 * S1. Queries and gets crs = (g0, h0, g1, h1)
 * 
 * Receiver:
 * R1. Queries and gets crs = (g0, h0, g1, h1)
 * R2. (pk, sk) <- keyGen(crs, sigma)
 *      R2.1 r <- Zq
 *      R2.2 g = g_sigma ^ r; h = h_sigma ^ r
 *      R2.3 pk = (g, h); sk = r
 * R3. R sends pk to S
 * 
 * Sender:
 * S2. Computes:
 *      S2.1 y0 = Enc(pk, 0, m0); y1 = Enc(pk, 1, m1)
 *      
 *      si <- Zq; ti <- Zq
 *      yi  = DDHEnc(pk_i, mi)
 *          = ( gi^si hi^ti, ( g_sigma^si h_sigma^ti )^r.mi )
 *          = (ui, vi.mi)
 * 
 *      for pk_i = (hi, hi, g_sigma^r, h_sigma^r)  and  i \in {0, 1}
 * 
 * S3. S sends Y = (y0, y1) to R
 * 
 * Receiver:
 * R4. Decrypt m_sigma: y_sigma[0]^r / y_sigma[1]
 * 
 * 
 * **/


// ================================================================ //
//                                                                  //
//                            Sender                                //   
//                                                                  //
// ================================================================ //

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
    cout << "\nMy first message, m0 = " << m0->generateSendableData()->toString() << endl;
    cout << "My second message, m1 = " << m1->generateSendableData()->toString() << endl;


    // ++++++++++++++++++++++++++++ //
    //          CRS Setup           //
    // ++++++++++++++++++++++++++++ //
    /**
     * S1. Queries and gets crs = (g0, h0, g1, h1)
     * **/

    if(crs_setup_type == 0){ // setup Messy mode
        cout << "\nUsing Messy mode\n";

        // Set messy crs
        vector<shared_ptr<GroupElement>> crs;
        crs = messySetUp(dlog);
        this->crs_sent = crs;

        send_int(channel, crs_setup_type);

    } else { // setup Decryption mode 
        cout << "\nUsing Decryption mode\n";

        // Set decryption crs
        vector<shared_ptr<GroupElement>> crs;
        crs = decSetUp(dlog);
        this->crs_sent = crs;
        
        send_int(channel, crs_setup_type);

    }

}


void SenderParty::run(const shared_ptr<CommParty> & channel) {

    // ++++++++++++++++++++++++++++ //
    //          Receive pk          //
    // ++++++++++++++++++++++++++++ //
    
    vector<shared_ptr<GroupElement>> pk;
    pk = receive_vec_ecelement(channel, this->dlog, 2);
    this->pk_received = pk;

    
    // ++++++++++++++++++++++++++++ //
    //       m0, m1 Encryption      //
    // ++++++++++++++++++++++++++++ //
    /**
    * S2. Computes:
    *      S2.1 y0 = Enc(pk, 0, m0); y1 = Enc(pk, 1, m1)
    *      
    *      si <- Zq; ti <- Zq
    *      yi  = DDHEnc(pk_i, mi)
    *          = ( gi^si hi^ti, ( g_sigma^si h_sigma^ti )^r.mi )
    *          = (ui, vi.mi)
    * 
    *      for pk_i = (hi, hi, g_sigma^r, h_sigma^r)  and  i \in {0, 1}
    * **/

    biginteger p = dlog->getOrder();
    
    vector<shared_ptr<GroupElement>> u0__v0_m0;
    u0__v0_m0 = encryptMessage(0, m0); // = y0 
    vector<shared_ptr<GroupElement>> u1__v1_m1; 
    u1__v1_m1 = encryptMessage(1, m1); // = y1


    // ++++++++++++++++++++++++++++ //
    //         Send y0, y1          //
    // ++++++++++++++++++++++++++++ //
    /**
     * S3. S sends Y = (y0, y1) to R
     * **/
    
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


// ================================================================ //
//                                                                  //
//                            Receiver                              //   
//                                                                  //
// ================================================================ //

ReceiverParty::ReceiverParty(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, int sigma) {

    this->sigma = sigma;
    this->dlog = dlog;
    
    // ++++++++++++++++++++++++++++ //
    //          CRS Setup           //
    // ++++++++++++++++++++++++++++ //
    /**
     * R1. Queries and gets crs = (g0, h0, g1, h1)
     * **/

    int crs_setup_type;
    crs_setup_type = receive_int(channel);

    if(crs_setup_type == 0){ // setup Messy mode
        cout << "\nUsing Messy mode\n";

        // Set messy crs
        vector<shared_ptr<GroupElement>> crs;
        crs = messySetUp(dlog);
        this->crs_received = crs;

    } else { // setup Decryption mode 
        cout << "\nUsing Decryption mode\n";

        // Set decryption crs
        vector<shared_ptr<GroupElement>> crs;
        crs = decSetUp(dlog);
        this->crs_received = crs;

    }

}


void ReceiverParty::run(const shared_ptr<CommParty> & channel) {
    
    
    // ++++++++++++++++++++++++++++ //
    //        Key Generation        //
    // ++++++++++++++++++++++++++++ //
    /**
     * R2. (pk, sk) <- keyGen(crs, sigma)
     *      R2.1 r <- Zq
     *      R2.2 g = g_sigma ^ r; h = h_sigma ^ r
     *      R2.3 pk = (g, h); sk = r
     * **/


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
    /**
     * R3. R sends pk to S
     * **/
    
    vector<shared_ptr<GroupElement>> pk;
    pk.push_back(g);
    pk.push_back(h);

    send_vec_ecelement(channel, pk);

    
    // ++++++++++++++++++++++++++++ //
    //        Receive y0, y1        //
    // ++++++++++++++++++++++++++++ //
    /**
     * R4. Decrypt m_sigma: y_sigma[0]^r / y_sigma[1]
     * **/

    vector<shared_ptr<GroupElement>> Y_received = receive_vec_ecelement(channel, dlog, 4);

    auto usig = Y_received[2 * sigma];
    auto vsig_msig = Y_received[2 * sigma + 1];

    auto vsig_computed = dlog->exponentiate(usig.get(), r);
    auto vsig_comp_inverse = dlog->getInverse(vsig_computed.get());
    auto msig = dlog->multiplyGroupElements(vsig_msig.get(), vsig_comp_inverse.get());


    // ++++++++++++++++++++++++++++ //
    //         Print m_sigma        //
    // ++++++++++++++++++++++++++++ //

    cout << "\nMy chosen element, m_sigma = " << msig->generateSendableData()->toString() << endl;
    
}

