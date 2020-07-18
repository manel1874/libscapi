#include "Postman.hpp"

// Send vector of EC group elements to receiver
void send_vec_ecelement(const shared_ptr<CommParty> & this_channel, vector<shared_ptr<GroupElement>> vec_ecelem){
 

    for (shared_ptr<GroupElement> ecelem : vec_ecelem){
        auto ecelem_sendable = ecelem->generateSendableData();
        auto ecelem_sendableStr = ecelem_sendable->toString();
        this_channel->writeWithSize(ecelem_sendableStr);
    }
    
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
