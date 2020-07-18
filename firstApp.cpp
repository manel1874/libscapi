#include "../include/primitives/DlogOpenSSL.hpp"

int main(int argc, char* argv[]){
    // initiate a discrete log group
    // (in this case the OpenSSL implementation of the elliptic curve group K-233)
    DlogGroup* dlog = new OpenSSLDlogECF2m("include/configFiles/NISTEC.txt", "K-233");

    // get the group generator and order
    auto g = dlog->getGenerator();
    biginteger q = dlog->getOrder();

    shared_ptr<PrgFromOpenSSLAES> gen = get_seeded_prg();
    biginteger r = getRandomInRange(0, q-1, gen.get());

    // exponentiate g in r to receive a new group element
    auto g1 = dlog->exponentiate(g.get(), r);
    // create a random group element
    auto h = dlog->createRandomElement();
    // multiply elements
    auto gMult = dlog->multiplyGroupElements(g1.get(), h.get());

    cout << "Hello Typhon\n";

}