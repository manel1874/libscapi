#include "Postman.hpp"


// ================================ //
//                                  //
//          Communication           //   
//                                  //
// ================================ //

// Send vector of EC group elements to receiver
void send_vec_ecelement(const shared_ptr<CommParty> & this_channel, vector<shared_ptr<GroupElement>> vec_ecelem){
 

    for (shared_ptr<GroupElement> ecelem : vec_ecelem){
        auto ecelem_sendable = ecelem->generateSendableData();
        auto ecelem_sendableStr = ecelem_sendable->toString();
        this_channel->writeWithSize(ecelem_sendableStr);
    }
    
}

// Send int to receiver
void send_int(const shared_ptr<CommParty> & this_channel, int msg){

    string msg_string = to_string(msg);
    this_channel->writeWithSize(msg_string);

}

// Receive vector of EC group elements from sender
vector<shared_ptr<GroupElement>> receive_vec_ecelement(const shared_ptr<CommParty> & channel, shared_ptr<DlogGroup> dlog, int size){

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

// Receive int from sender
int receive_int(const shared_ptr<CommParty> & channel){

    string str_msg;
    int msg;

    vector<byte> raw_msg;
    channel->readWithSizeIntoVector(raw_msg);
    const byte * uc = &(raw_msg[0]);
    str_msg = string(reinterpret_cast<char const*>(uc), raw_msg.size());

    msg = stoi(str_msg);

    return msg;

}


// ================================ //
//                                  //
//        CRS  distribution         //   
//                                  //
// ================================ //



vector<shared_ptr<GroupElement>> messySetUp(shared_ptr<DlogGroup> dlog){

    vector<shared_ptr<GroupElement>> crs;

    vector<biginteger> point(2);
    point[0] = biginteger("5095743867735907340429172157014501881298372438572335273976768533377220");
    point[1] = biginteger("11378462819536813429055783026824228466220050944925700081307530656562534");
    auto g0 = dlog->generateElement(false, point);
    point[0] = biginteger("12534834438420479756264243881504877144349892663668089730696363695806751");
    point[1] = biginteger("10306647177692537054903078702367358172560512989015743052890895551899274");
    auto h0 = dlog->generateElement(false, point);
    point[0] = biginteger("10673732820825919286379442699598555566910899968906084172592403654415728");
    point[1] = biginteger("42265058675534991901702357301769193240954974299561114187740824811215");
    auto g1 = dlog->generateElement(false, point);
    point[0] = biginteger("2636943167419398678829766130881991926656326453668596144181343217151372");
    point[1] = biginteger("10736996757665612042685013254585147616126829476562808741151758181945566");
    auto h1 = dlog->generateElement(false, point);

    crs.push_back(g0);
    crs.push_back(h0);
    crs.push_back(g1);
    crs.push_back(h1);

    return crs;
}


vector<shared_ptr<GroupElement>> decSetUp(shared_ptr<DlogGroup> dlog){

    vector<shared_ptr<GroupElement>> crs;

    vector<biginteger> point(2);
    point[0] = biginteger("12900430447750717326210806918460204495883114334523224268531204118597213");
    point[1] = biginteger("11772246473547043278035792841258266552738542597445626077626455950861764");
    auto g0 = dlog->generateElement(false, point);
    point[0] = biginteger("6871918008412558051292695948330556352815388126863228305023243377110055");
    point[1] = biginteger("8284293186998754964520691791939949719793330223581125666018016911630716");
    auto h0 = dlog->generateElement(false, point);
    point[0] = biginteger("4413734513281428897520126879044835649741936195220411943363949465394297");
    point[1] = biginteger("13555071031116696611002567805485493266776332322559355512178974659539760");
    auto g1 = dlog->generateElement(false, point);
    point[0] = biginteger("11251189308970924808384357076231832314616314200505206291130381228676698");
    point[1] = biginteger("10609899570472671085162844898801785157180838703445589608487625987593857");
    auto h1 = dlog->generateElement(false, point);

    crs.push_back(g0);
    crs.push_back(h0);
    crs.push_back(g1);
    crs.push_back(h1);

    return crs;
}


vector<shared_ptr<GroupElement>> genMessySetUp(shared_ptr<DlogGroup> dlog){

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


vector<shared_ptr<GroupElement>> genDecSetUp(shared_ptr<DlogGroup> dlog){

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

