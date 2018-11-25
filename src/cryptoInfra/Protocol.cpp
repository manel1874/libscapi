//
// Created by moriya on 24/09/17.
//
#include <../../include/cryptoInfra/Protocol.hpp>

string CmdParser::getKey(string parameter)
{
    if (parameter[0] == '-')
        return parameter.substr(1);
    else
        return parameter;
}


string CmdParser::getValueByKey(vector<pair<string, string>> arguments, string key)
{
    int size = arguments.size();
    for (int i = 0; i < size; ++i)
    {
        pair<string, string> p = arguments[i];
        if (p.first == key)
            return p.second;
    }
    return "NotFound";
}

vector<pair<string, string>> CmdParser::parseArguments(string protocolName, int argc, char* argv[])
{
    string key, value;

    //Put the protocol name in the vector pairs
    vector<pair<string, string>> arguments;
    arguments.push_back(make_pair("protocolName", protocolName));

    //Put all other parameters in the map
    for(int i=1; i<argc; i+=2)
    {

        key = getKey(string(argv[i]));
        value = getKey(string(argv[i+1]));
        arguments.emplace_back(make_pair(key, value));

        cout<<"key = "<< key <<" value = "<< value <<endl;
    }

    return arguments;
}

Protocol::Protocol(string protocolName, int argc, char* argv[])
{
    arguments = parser.parseArguments(protocolName, argc, argv);
}

vector<pair<string, string>> Protocol::getArguments()
{
    return arguments;
}

CmdParser Protocol::getParser()
{
    return parser;
}

MPCProtocol::MPCProtocol(string protocolName, int argc, char* argv[]): Protocol (protocolName, argc, argv){

    vector<string> subTaskNames{"Offline", "Online"};
    timer = new Measurement(*this, subTaskNames);


    partyID = stoi(this->getParser().getValueByKey(arguments, "partyID"));
    cout<<"ID = "<<partyID<<endl;
    auto partiesNumber = this->getParser().getValueByKey(arguments, "partiesNumber");

    if (partiesNumber == "NotFound"){
        numParties = 2;
    } else {
        numParties = stoi(this->getParser().getValueByKey(arguments, "partiesNumber"));
    }
    cout<<"number of parties = "<<numParties<<endl;
    auto partiesFile = this->getParser().getValueByKey(arguments, "partiesFile");
    cout<<"partiesFile = "<<partiesFile<<endl;

    times = stoi(this->getParser().getValueByKey(arguments, "internalIterationsNumber"));
    parties = comm.setCommunication(partyID, numParties, partiesFile);
    numThreads = stoi(this->getParser().getValueByKey(arguments, "numThreads"));

    //Calculates the number of threads.
    if (numParties <= numThreads){
        this->numThreads = numParties;
        numPartiesForEachThread = 1;
    } else{
        numPartiesForEachThread = (numParties + numThreads - 1)/ numThreads;
    }

    initTimes();

}

MPCProtocol::~MPCProtocol(){
    delete timer;
}

void MPCProtocol::initTimes(){
    //cout<<"before sending any data"<<endl;
    byte tmpBytes[20];
    byte allBytes[20*numParties];
    roundFunctionSameMsg(tmpBytes, allBytes, 20);

}

void MPCProtocol::run(){
    auto start = std::chrono::system_clock::now();

    for (currentIteration = 0; currentIteration<times; currentIteration++){

        timer->startSubTask("Offline", currentIteration);
        runOffline();
        timer->endSubTask("Offline", currentIteration);

        timer->startSubTask("Online", currentIteration);
        runOnline();
        timer->endSubTask("Online", currentIteration);

    }

    auto end = std::chrono::system_clock::now();
    int elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    cout << "Running " << times <<" iterations took: " << elapsed_ms << " milliseconds" << endl
         << "Average time per iteration: " << elapsed_ms / (float)times << " milliseconds" << endl;

}

void MPCProtocol::roundFunctionSameMsg(byte* sendData, byte* receiveData, int msgSize){
    vector<thread> threads(numThreads);
    //Split the work to threads. Each thread gets some parties to work on.
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&MPCProtocol::exchangeDataSameInput, this, sendData, receiveData, t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread, msgSize);
        } else {
            threads[t] = thread(&MPCProtocol::exchangeDataSameInput, this, sendData, receiveData, t * numPartiesForEachThread, numParties, msgSize);
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
}


void MPCProtocol::roundFunctionDiffMsg(byte* sendData, byte* receiveData, int msgSize){
    vector<thread> threads(numThreads);
    //Split the work to threads. Each thread gets some parties to work on.
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&MPCProtocol::exchangeDataDiffInput, this, sendData, receiveData, t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread, msgSize);
        } else {
            threads[t] = thread(&MPCProtocol::exchangeDataDiffInput, this, sendData, receiveData, t * numPartiesForEachThread, numParties, msgSize);
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
}

void MPCProtocol::exchangeDataSameInput(byte* sendData, byte* receiveData, int first, int last, int msgSize){
    for (int j=first; j<last; j++){
        if (partyID < j) {
            //send myData to the other party
            parties[j]->write(sendData, msgSize);
            //receive the other data from the other party
            parties[j]->read(receiveData + j*msgSize, msgSize);

        } else if (partyID > j){
            //receive the other data from the other party
            parties[j]->read(receiveData + j*msgSize, msgSize);
            //send myData to the other party
            parties[j]->write(sendData, msgSize);
        } else {
            memcpy(receiveData + j*msgSize, sendData, msgSize);
        }
    }
}

void MPCProtocol::exchangeDataDiffInput(byte* sendData, byte* receiveData, int first, int last, int msgSize){
    for (int j=first; j<last; j++){
        if (partyID < j) {
            //send myData to the other party
            parties[j]->write(sendData + j*msgSize, msgSize);
            //receive the other data from the other party
            parties[j]->read(receiveData + j*msgSize, msgSize);

        } else if (partyID > j){
            //receive the other data from the other party
            parties[j]->read(receiveData + j*msgSize, msgSize);
            //send myData to the other party
            parties[j]->write(sendData + j*msgSize, msgSize);
        } else {
            memcpy(receiveData + j*msgSize, sendData + j*msgSize, msgSize);
        }
    }
}

