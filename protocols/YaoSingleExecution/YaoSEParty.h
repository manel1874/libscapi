//
// Created by moriya on 15/2/17.
//
#pragma once

//#ifndef LIBSCAPI_YAOSEPARTY_H
//#define LIBSCAPI_YAOSEPARTY_H
#include <libscapi/include/CryptoInfra/Protocol.hpp>
#include <libscapi/include/CryptoInfra/SecurityLevel.hpp>
#include <emp-m2pc/malicious/malicious.h>
#include <fstream>

CircuitFile *cf;
void compute(Bit * res, Bit * in, Bit * in2) {
    cf->compute((block*)res, (block*)in, (block*)in2);
}

class YaoSEParty : public Protocol, public Malicious {
private:
    int id;
    string inputFile;
    bool * input;
    NetIO *io;
    bool* out;
    Malicious2PC <off> * mal;

    /*
	 * Reads the input from the given file.
	 */
    void readInputs(bool * inputs, int size);



public:
    YaoSEParty(int id, string circuitFile, string ip, int port, string inputFile);
    ~YaoSEParty(){
        delete cf;
    }

    /*
     * Implement the function derived from the Protocol abstract class.
     */
    void run() override;

    int runOffline();
    int runOnline();

    bool* getOutput(){
        return out;
    }

};


//#endif //LIBSCAPI_YAOSEPARTY_H
