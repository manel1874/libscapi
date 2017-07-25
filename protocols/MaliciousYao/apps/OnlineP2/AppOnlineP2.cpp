#include <boost/thread/thread.hpp>
#include <lib/include/common/CommonMaliciousYao.hpp>
#include <lib/include/primitives/CommunicationConfig.hpp>
#include <lib/include/primitives/CryptoPrimitives.hpp>
#include <libscapi/include/circuits/GarbledCircuitFactory.hpp>
#include <lib/include/primitives/CircuitInput.hpp>
#include <lib/include/primitives/ExecutionParameters.hpp>
#include <lib/include/primitives/KProbeResistantMatrix.hpp>
#include <lib/include/OfflineOnline/primitives/BucketLimitedBundle.hpp>
#include <lib/include/OfflineOnline/primitives/BucketLimitedBundleList.hpp>
#include <lib/include/common/LogTimer.hpp>
#include <lib/include/OfflineOnline/specs/OnlineProtocolP2.hpp>
#include <lib/include/OfflineOnline/primitives/LimitedBundle.hpp>
#include <lib/include/OfflineOnline/primitives/BucketLimitedBundle.hpp>

/**
* This class runs the second party of the online protocol.
* It contain multiple
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
*
*/

const int PARTY = 2;
const string HOME_DIR = "../..";
//const string CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/AES/NigelAes.txt";
//const string CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/AES/AESPartyTwoInputs.txt";
const string COMM_CONFIG_FILENAME = HOME_DIR + string("/lib/assets/conf/PartiesConfig.txt");

//const string CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1Input.txt";
//const string BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P2/aes";
//const string BUCKETS_PREFIX_CR = HOME_DIR + "/data/P2/cr";
//const string MAIN_MATRIX = HOME_DIR + "/data/P2/aes.matrix";
//const string CR_MATRIX = HOME_DIR + "/data/P2/cr.matrix";

//file for dlog
const string NISTEC_FILE_NAME = "../../../../include/configFiles/NISTEC.txt";

int BUCKET_ID = 0;

vector<byte> getProtocolOutput(OnlineProtocolP2* protocol) {
    auto output = protocol->getOutput();
    return output.getOutput();
}

void printOutput(vector<byte> output) {
    cout << "(P2) Received Protocol output:" << endl;

    cout << "output of protocol:" << endl;
    auto outputSize = output.size();
    for (size_t i = 0; i < outputSize; i++) {
        cout << (int)output[i] << ",";
    }
    cout << endl;

    cout << "Expected output is:" << endl;
    cout << "0,1,1,0,1,0,0,1,1,1,0,0,0,1,0,0,1,1,1,0,0,0,0,0,1,1,0,1,1,0,0,0,0,1,1,0,1,0,1,0,0,1,1,1,1,0,1,1,0,0,0,0,0,1,0,0,0,0,1,1,0,0,0,0,1,1,0,1,1,0,0,0,1,1,0,0,1,1,0,1,1,0,1,1,0,1,1,1,1,0,0,0,0,0,0,0,0,1,1,1,0,0,0,0,1,0,1,1,0,1,0,0,1,1,0,0,0,1,0,1,0,1,0,1,1,0,1,0" << endl;
}


block** saveBucketGarbledTables(int size, BucketLimitedBundle * bucket){
    block** tables = new block*[size];

    for (int i=0;i<size; i++) {
        auto bundle = bucket->getLimitedBundleAt(i);
        tables[i] = (block *) _mm_malloc(bundle->getGarbledTablesSize(), SIZE_OF_BLOCK);
        memcpy((byte *) tables[i], (byte *) bundle->getGarbledTables(), bundle->getGarbledTablesSize());
    }

    return tables;

}

void restoreBucketTables(int size, BucketLimitedBundle* bucket, block** tables){
    for (int i=0;i<size; i++) {
        bucket->getLimitedBundleAt(i)->setGarbledTables(tables[i]);
    }
    delete [] tables;
}

/*************************************************************************
MAIN
**************************************************************************/
int main(int argc, char* argv[]) {

    int counter = 1;

    auto CIRCUIT_FILENAME = HOME_DIR + argv[counter++];
    auto CIRCUIT_INPUT_FILENAME = HOME_DIR + argv[counter++];
    auto CIRCUIT_CHEATING_RECOVERY = HOME_DIR + argv[counter++];
    auto BUCKETS_PREFIX_MAIN = HOME_DIR + argv[counter++];
    auto BUCKETS_PREFIX_CR = HOME_DIR + argv[counter++];
    auto MAIN_MATRIX = HOME_DIR + argv[counter++];
    auto CR_MATRIX = HOME_DIR + argv[counter++];

    int N1 = atoi(argv[counter++]);
    int B1 = atoi(argv[counter++]);
    int s1 = atoi(argv[counter++]);
    double p1 = stod(argv[counter++]);
    int N2 = atoi(argv[counter++]);
    int B2 = atoi(argv[counter++]);
    int s2 = atoi(argv[counter++]);
    double p2 = stod(argv[counter++]);

    //set crypto primitives
    CryptoPrimitives::setCryptoPrimitives(NISTEC_FILE_NAME);
    CryptoPrimitives::setNumOfThreads(8);

    /*int N1 = 32;
    int B1 = 7;
    int s1 = 40;
    double p1 = 0.62;

    int N2 = 32;
    int B2 = 20;
    int s2 = 40;
    double p2 = 0.71;*/

    /*int N1 = 128;
    int B1 = 6;
    int s1 = 40;
    double p1 = 0.77;

    int N2 = 128;
    int B2 = 14;
    int s2 = 40;
    double p2 = 0.76;*/

    /*int N1 = 1024;
    int B1 = 4;
    int s1 = 40;
    double p1 = 0.72;

    int N2 = 1024;
    int B2 = 10;
    int s2 = 40;
    double p2 = 0.85;*/

    int size = N1;

    vector<shared_ptr<BucketLimitedBundle>> mainBuckets(N1), crBuckets(N1);

    for (int i = 0; i<N1; i++) {

        mainBuckets[i] = BucketLimitedBundleList::loadBucketFromFile(BUCKETS_PREFIX_MAIN + "." + to_string(BUCKET_ID) + ".cbundle");
        crBuckets[i] = BucketLimitedBundleList::loadBucketFromFile(BUCKETS_PREFIX_CR + "." + to_string(BUCKET_ID++) + ".cbundle");

    }

    // only now we start counting the running time
    string tmp = "reset times";
    byte tmpBuf[20];

    vector<long long> times(size);
    OnlineProtocolP2* protocol = new OnlineProtocolP2(CIRCUIT_FILENAME, CIRCUIT_CHEATING_RECOVERY,
                                                      MAIN_MATRIX, CR_MATRIX, N1, s1, B1, p1, N2, s2, B2, p2);

    auto input = CircuitInput::fromFile(CIRCUIT_INPUT_FILENAME, protocol->getMainCircuit()->getNumberOfInputs(2));

    for (int j = 0; j < 10; j+=4) {


        CryptoPrimitives::setNumOfThreads(j);

        for (int i = 0; i < size; i++) {

            int readsize = protocol->getChannel()->read(tmpBuf, tmp.size());
            //cout << "read size = " << readsize << endl;
            protocol->getChannel()->write((const byte*)tmp.c_str(), tmp.size());

            auto mainBucket = mainBuckets[i];
            auto crBucket = crBuckets[i];

            auto mainTables = saveBucketGarbledTables(B1, mainBucket.get());
            auto crTables = saveBucketGarbledTables(B2, crBucket.get());

            protocol->setBuckets(mainBucket, crBucket);
            protocol->setInput(*input);

            auto start = chrono::high_resolution_clock::now();
            protocol->run();

            auto end = chrono::high_resolution_clock::now();
            auto time = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            //cout << "exe no. " << i << " took " << time << " milis." << endl;
            times[i] = time;

            restoreBucketTables(B1, mainBucket.get(), mainTables);
            restoreBucketTables(B2, crBucket.get(), crTables);
        }
        int count = 0;
        for (int i = 0; i < size; i++) {
            count += times[i];
            cout << times[i] << " ";
        }

        auto average = count / size;

        cout << endl;

        //System.out.println();
        cout << size << " executions took in average " << average << " milis." << endl;


    }

    auto output = getProtocolOutput(protocol);
    printOutput(output);

    delete protocol;

    cout << "\nP2 end communication\n";

    return 0;
}
