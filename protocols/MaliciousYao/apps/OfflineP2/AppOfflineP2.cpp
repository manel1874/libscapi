//#include <boost/thread/thread.hpp>
#include <boost/algorithm/string.hpp>
#include <libscapi/include/circuits/GarbledCircuitFactory.hpp>
#include <libscapi/include/circuits/GarbledBooleanCircuit.h>
//#include <libscapi/include/interactive_mid_protocols/OTExtensionBristol.hpp>
//#include <lib/include/primitives/CheatingRecoveryCircuitCreator.hpp>
#include <lib/include/OfflineOnline/specs/OfflineProtocolP2.hpp>

using namespace std;

//party number
const int PARTY = 2;

//home directory path for all files
const  string HOME_DIR = "../..";
const string COMM_CONFIG_FILENAME = HOME_DIR + string("/lib/assets/conf/PartiesConfig.txt");

//file for dlog
const string NISTEC_FILE_NAME = "../../../../include/configFiles/NISTEC.txt";



/*************************************************************************
MAIN
**************************************************************************/
int main(int argc, char* argv[]) {
//	//set io_service for peer to peer communication
//	boost::asio::io_service io_service;
//	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));

	//set crypto primitives
	CryptoPrimitives::setCryptoPrimitives(NISTEC_FILE_NAME);

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
    int numOfThreads = 8; //atoi(argv[counter++]);
    CryptoPrimitives::setNumOfThreads(numOfThreads);

    cout<<"N1 = " << N1<<" B1 = "<< B1 << " s1 = "<< s1 << " p1 = "<< p1 << " N2 = " << N2<< " B2 = "<< B2 <<
                       " s2 = " <<s2<< " p2 = "<< p2 << "numOfThread = " << numOfThreads<<endl;

	CryptoPrimitives::setNumOfThreads(numOfThreads);

//	//make circuit
//
//	vector<shared_ptr<GarbledBooleanCircuit>> mainCircuit;
//	vector<shared_ptr<GarbledBooleanCircuit>> crCircuit;
//
//	if (numOfThreads == 0)
//		numOfThreads = 1;
//
//	mainCircuit.resize(numOfThreads);
//	crCircuit.resize(numOfThreads);
//
//	for (int i = 0; i<numOfThreads; i++) {
//		mainCircuit[i] = shared_ptr<GarbledBooleanCircuit>(GarbledCircuitFactory::createCircuit(CIRCUIT_FILENAME,
//			GarbledCircuitFactory::CircuitType::FIXED_KEY_FREE_XOR_HALF_GATES, true));
//		crCircuit[i] = shared_ptr<GarbledBooleanCircuit>(CheatingRecoveryCircuitCreator(CIRCUIT_CHEATING_RECOVERY, mainCircuit[i]->getNumberOfGates()).create());
//	}
	
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


//	auto mainExecution = make_shared<ExecutionParameters>(nullptr, mainCircuit, N1, s1, B1, p1);
//	auto crExecution = make_shared<ExecutionParameters>(nullptr, crCircuit, N2, s2, B2, p2);

    string tmp = "reset times";
    cout << "tmp size = " << tmp.size() << endl;
    byte tmpBuf[20];

    OfflineProtocolP2* protocol = new OfflineProtocolP2(CIRCUIT_FILENAME, CIRCUIT_CHEATING_RECOVERY, N1, s1, B1, p1,  N2, s2, B2, p2, false);

    int totalTimes = 0;
    for (int j = 0; j < 10; j += 4) {
        cout << "in first loop. num threads = " << j << endl;
        CryptoPrimitives::setNumOfThreads(j);

        for (int i = 0; i < 5; i++) {

                protocol->getChannel()[0]->write((const byte *) tmp.c_str(), tmp.size());
                int readsize = protocol->getChannel()[0]->read(tmpBuf, tmp.size());

                // we start counting the running time just before estalishing communication
                auto start = chrono::high_resolution_clock::now();

                // and run the protocol
                protocol->run();

                // we measure how much time did the protocol take
                auto end = chrono::high_resolution_clock::now();
                auto runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                totalTimes += runtime;
                cout << "\nOffline protocol party 2 with " << j << "threads took " << runtime << " miliseconds.\n";

        }

        cout << " average time of running OfflineP2 with " << j << " threads = " << totalTimes / 5 << endl;
        totalTimes = 0;
    }


	cout << "\nSaving buckets to files...\n";
	auto start = chrono::high_resolution_clock::now();
	
//	auto mainBuckets = protocol->getMainBuckets();
//	auto crBuckets = protocol->getCheatingRecoveryBuckets();
//	mainBuckets->saveToFiles(BUCKETS_PREFIX_MAIN);
//	crBuckets->saveToFiles(BUCKETS_PREFIX_CR);
//	protocol->getMainProbeResistantMatrix()->saveToFile(MAIN_MATRIX);
//	protocol->getCheatingRecoveryProbeResistantMatrix()->saveToFile(CR_MATRIX);
    protocol->saveOnDisk(BUCKETS_PREFIX_MAIN, BUCKETS_PREFIX_CR, MAIN_MATRIX, CR_MATRIX);

	auto end = chrono::high_resolution_clock::now();
	auto runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	cout << "\nSaving buckets took " << runtime << " miliseconds.\n";

    delete protocol;

	cout << "\nP2 end communication\n";


	return 0;
}
