//
// Created by liork on 17/09/17.
//

/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
*
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
*/



#ifndef LIBSCAPI_MEASURE_HPP
#define LIBSCAPI_MEASURE_HPP

#include <string>
#include <chrono>
#include <fstream>
#include <iostream>
#include <exception>
#include <memory>
#include <unistd.h>
#include <stdio.h>
#include <tuple>
#include <../../lib/JsonCpp/include/json/json.h>

using namespace std;
using namespace std::chrono;
using namespace Json;

class Measurement {
public:
    Measurement(){}
    Measurement(string protocolName, int partyId, int numOfParties, int numOfIteration);
    Measurement(string protocolName, int partyId, int numOfParties, int numOfIteration, vector<string> names);
    ~Measurement();
    void startSubTask(int taskIdx, int currentIterationNum);
    void endSubTask(int taskIdx, int currentIterationNum);

    void setTaskNames(vector<string> & names){
        m_cpuStartTimes = vector<vector<long>>(names.size(), vector<long>(m_numberOfIterations));
        m_commSentStartTimes = vector<vector<unsigned long int>>(names.size(),
                vector<unsigned long int>(m_numberOfIterations));
        m_commReceivedStartTimes = vector<vector<unsigned long int>>(names.size(),
                vector<unsigned long int>(m_numberOfIterations));
        m_cpuEndTimes = vector<vector<long>>(names.size(), vector<long>(m_numberOfIterations));
        m_commSentEndTimes = vector<vector<unsigned long int>>(names.size(),
                vector<unsigned long int>(m_numberOfIterations));
        m_commReceivedEndTimes = vector<vector<unsigned long int>>(names.size(),
                vector<unsigned long int>(m_numberOfIterations));
        m_names = move(names);

    }
    string getcwdStr()
    {
        char* buff;//automatically cleaned when it exits scope
        return string(getcwd(buff,255));
    }


private:
    tuple<unsigned long int, unsigned long int> commData();
    void analyzeCpuData(); //create JSON file with cpu times
    void analyzeCommSentData(); // create JSON file with comm sent times
    void analyzeCommReceivedData(); // create JSON file with comm received times
    void createJsonFile(Value v, string fileName);
    vector<vector<long>> m_cpuStartTimes;
    vector<vector<unsigned long int>> m_commSentStartTimes;
    vector<vector<unsigned long int>> m_commReceivedStartTimes;
    vector<vector<long>> m_cpuEndTimes;
    vector<vector<unsigned long int>> m_commSentEndTimes;
    vector<vector<unsigned long int>> m_commReceivedEndTimes;
    vector<string> m_names;
    string m_protocolName;
    int m_partyId;
    int m_numOfParties;
    int m_numberOfIterations;
};


#endif //LIBSCAPI_MEASURE_HPP
