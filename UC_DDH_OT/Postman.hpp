#pragma once

#include "include/comm/Comm.hpp"
#include "include/primitives/DlogOpenSSL.hpp"


// ================================ //
//                                  //
//          Communication           //   
//                                  //
// ================================ //

void send_vec_ecelement(const shared_ptr<CommParty> & this_channel, vector<shared_ptr<GroupElement>> vec_ecelem);

void send_int(const shared_ptr<CommParty> & this_channel, int msg);

vector<shared_ptr<GroupElement>> receive_vec_ecelement(const shared_ptr<CommParty> & channel, shared_ptr<DlogGroup> dlog, int size);

int receive_int(const shared_ptr<CommParty> & channel);


// ================================ //
//                                  //
//        CRS  distribution         //   
//                                  //
// ================================ //

vector<shared_ptr<GroupElement>> messySetUp(shared_ptr<DlogGroup> dlog);

vector<shared_ptr<GroupElement>> decSetUp(shared_ptr<DlogGroup> dlog);

vector<shared_ptr<GroupElement>> genMessySetUp(shared_ptr<DlogGroup> dlog);

vector<shared_ptr<GroupElement>> genDecSetUp(shared_ptr<DlogGroup> dlog);
