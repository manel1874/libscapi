#pragma once

#include "Postman.hpp"
#include <boost/thread/thread.hpp>

class SenderParty {

private:

    shared_ptr<DlogGroup> dlog;

    vector<shared_ptr<GroupElement>> crs_sent; // this should be substituted by:
    shared_ptr<GroupElement> g0, g1, h0, h1;

    shared_ptr<GroupElement> m0, m1;

    vector<shared_ptr<GroupElement>> pk_received; // this should be substituted by:
    shared_ptr<GroupElement> g, h;


public:

    SenderParty(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, int crs_setup_type);

    vector<shared_ptr<GroupElement>> genMessySetUp();

    vector<shared_ptr<GroupElement>> genDecSetUp();

    void run(const shared_ptr<CommParty> & channel);

    vector<shared_ptr<GroupElement>> encryptMessage(int message_number, shared_ptr<GroupElement> mi);


};

class ReceiverParty {
private:

public:

    int sigma; // may be delete it

    //DlogGroup* dlog; // change to:
    shared_ptr<DlogGroup> dlog;

    vector<shared_ptr<GroupElement>> crs_received; //change for
    shared_ptr<GroupElement> g0, g1, h0, h1;
    
    biginteger r;

    shared_ptr<GroupElement> g, h;

    ReceiverParty(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, int sigma);

    void run(const shared_ptr<CommParty> & channel);

};