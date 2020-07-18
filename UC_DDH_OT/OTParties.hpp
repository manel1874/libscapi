#pragma once

#include "Postman.hpp"
#include <boost/thread/thread.hpp>

class SenderParty {
private:

    shared_ptr<DlogGroup> dlog;

    vector<shared_ptr<GroupElement>> crs_sent;

    shared_ptr<GroupElement> m0, m1;

    vector<shared_ptr<GroupElement>> pk_received; 

public:

    SenderParty(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, int crs_setup_type);

    void run(const shared_ptr<CommParty> & channel);

    vector<shared_ptr<GroupElement>> encryptMessage(int message_number, shared_ptr<GroupElement> mi);
};


class ReceiverParty {
private:

    int sigma; 

    shared_ptr<DlogGroup> dlog;

    vector<shared_ptr<GroupElement>> crs_received;
    
    biginteger r;

public:

    ReceiverParty(const shared_ptr<CommParty> & channel, const shared_ptr<DlogGroup> & dlog, int sigma);
    
    void run(const shared_ptr<CommParty> & channel);
};