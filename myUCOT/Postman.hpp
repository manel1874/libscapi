#pragma once

#include "include/comm/Comm.hpp"
#include "include/primitives/DlogOpenSSL.hpp"



void send_vec_ecelement(const shared_ptr<CommParty> & this_channel, vector<shared_ptr<GroupElement>> vec_ecelem);

vector<shared_ptr<GroupElement>> receive_vec_ecelement(const shared_ptr<CommParty> & channel, shared_ptr<DlogGroup> dlog, int size);

