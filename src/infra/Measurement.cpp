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

#include "../../include/infra/Measurement.hpp"



using namespace std;

Measurement::Measurement(string protocolName, int partyId, int numOfParties, int numOfIteration)
{
    m_protocolName = protocolName;
    m_partyId = partyId;
    m_numberOfIterations = numOfIteration;
    m_numOfParties = numOfParties;
}


Measurement::Measurement(string protocolName, int partyId, int numOfParties, int numOfIteration, vector<string> names)
        :m_cpuStartTimes(names.size(), vector<long>(numOfIteration)),
         m_commSentStartTimes(names.size(), vector<unsigned long int>(numOfIteration)),
         m_commReceivedStartTimes(names.size(), vector<unsigned long int>(numOfIteration)),
         m_memoryUsage(names.size(), vector<long>(numOfIteration)),
         m_cpuEndTimes(names.size(), vector<long>(numOfIteration)),
         m_commSentEndTimes(names.size(), vector<unsigned long int>(numOfIteration)),
         m_commReceivedEndTimes(names.size(), vector<unsigned long int>(numOfIteration)),
         m_names{move(names)}
{
    m_protocolName = protocolName;
    m_partyId = partyId;
    m_numberOfIterations = numOfIteration;
    m_numOfParties = numOfParties;
}

void Measurement::setTaskNames(vector<string> & names)
{
    m_cpuStartTimes = vector<vector<long>>(names.size(), vector<long>(m_numberOfIterations));
    m_commSentStartTimes = vector<vector<unsigned long int>>(names.size(),
            vector<unsigned long int>(m_numberOfIterations));
    m_commReceivedStartTimes = vector<vector<unsigned long int>>(names.size(),
            vector<unsigned long int>(m_numberOfIterations));
    m_memoryUsage = vector<vector<long>>(names.size(), vector<long>(m_numberOfIterations));
    m_cpuEndTimes = vector<vector<long>>(names.size(), vector<long>(m_numberOfIterations));
    m_commSentEndTimes = vector<vector<unsigned long int>>(names.size(),
            vector<unsigned long int>(m_numberOfIterations));
    m_commReceivedEndTimes = vector<vector<unsigned long int>>(names.size(),
            vector<unsigned long int>(m_numberOfIterations));
    m_names = move(names);
}

void Measurement::startSubTask(int taskIdx, int currentIterationNum)
{
    //calculate cpu start time
    auto now = system_clock::now();
    //Cast the time point to ms, then get its duration, then get the duration's count.
    auto ms = time_point_cast<milliseconds>(now).time_since_epoch().count();
    m_cpuStartTimes[taskIdx][currentIterationNum] = ms;
    tuple<unsigned long int, unsigned long int> startData = commData();
    m_commSentStartTimes[taskIdx][currentIterationNum] = get<0>(startData);
    m_commReceivedStartTimes[taskIdx][currentIterationNum] = get<1>(startData);
    cout << "Tupple data : {0} = " << get<0>(startData) << " {1} = " << get<1>(startData) << endl;
}

void Measurement::endSubTask(int taskIdx, int currentIterationNum)
{
    struct rusage r_usage;
    getrusage(RUSAGE_SELF, &r_usage);
    m_memoryUsage[taskIdx][currentIterationNum] = r_usage.ru_maxrss;
    auto now = system_clock::now();
    //Cast the time point to ms, then get its duration, then get the duration's count.
    auto ms = time_point_cast<milliseconds>(now).time_since_epoch().count();

    m_cpuEndTimes[taskIdx][currentIterationNum] = ms - m_cpuStartTimes[taskIdx][currentIterationNum];

    tuple<unsigned long int, unsigned long int> endData = commData();
    m_commSentEndTimes[taskIdx][currentIterationNum] = get<0>(endData) -
            m_commSentStartTimes[taskIdx][currentIterationNum];
    m_commReceivedEndTimes[taskIdx][currentIterationNum] = get<1>(endData) -
            m_commReceivedStartTimes[taskIdx][currentIterationNum];
}

tuple<unsigned long int, unsigned long int> Measurement::commData()
{
    FILE *fp = fopen("/proc/net/dev", "r");
    char buf[200], ifname[20];
    unsigned long int r_bytes, t_bytes, r_packets, t_packets;

    // skip first two lines
    for (int i = 0; i < 1; i++) {
        fgets(buf, 200, fp);
    }

    while (fgets(buf, 200, fp)) {
        sscanf(buf, "%[^:]: %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
               ifname, &r_bytes, &r_packets, &t_bytes, &t_packets);
        break;
    }

    fclose(fp);
    cout << "data from function {0} = " << r_bytes << " {1} = " << t_bytes << endl;
    return make_tuple(t_bytes, r_bytes);
}

void Measurement::analyzeCpuData()
{
    string filePath = getcwdStr();
    string fileName = filePath + "/" + m_protocolName + "_cpu_partyId=" + to_string(m_partyId)
                      +"_numOfParties=" + to_string(m_numOfParties) + ".json";

    //party is the root of the json objects
    Value party(arrayValue);

    for (int taskNameIdx = 0; taskNameIdx < m_names.size(); taskNameIdx++)
    {
        //Write for each task name all the iteration
        Value task(objectValue);
        task["name"] = m_names[taskNameIdx];

        for (int iterationIdx = 0; iterationIdx < m_numberOfIterations; iterationIdx++)
        {
            Value taskTimes;
            task["iteration_" + to_string(iterationIdx)] = m_cpuEndTimes[taskNameIdx][iterationIdx];
        }
        party.append(task);
    }

    //send json object to create file
    createJsonFile(party, fileName);
}

void Measurement::analyzeCommSentData()
{
    string filePath = getcwdStr();
    string fileName = filePath + "/" + m_protocolName + "_commSent_partyId=" + to_string(m_partyId)
                      +"_numOfParties=" + to_string(m_numOfParties) + ".json";

    //party is the root of the json objects
    Value partySent(arrayValue);

    for (int taskNameIdx = 0; taskNameIdx < m_names.size(); taskNameIdx++)
    {
        //Write for each task name all the iteration
        Value task(objectValue);
        task["name"] = m_names[taskNameIdx];

        for (int iterationIdx = 0; iterationIdx < m_numberOfIterations; iterationIdx++)
        {
            Value taskTimes;
            task["iteration_" + to_string(iterationIdx)] = m_commSentEndTimes[taskNameIdx][iterationIdx];
        }
        partySent.append(task);
    }

    //send json object to create file
    createJsonFile(partySent, fileName);
}

void Measurement::analyzeCommReceivedData()
{
    string filePath = getcwdStr();
    string fileName = filePath + "/" + m_protocolName + "_commReceived_partyId=" + to_string(m_partyId)
                      +"_numOfParties=" + to_string(m_numOfParties) + ".json";

    //party is the root of the json objects
    Value partyReceived(arrayValue);

    for (int taskNameIdx = 0; taskNameIdx < m_names.size(); taskNameIdx++)
    {
        //Write for each task name all the iteration
        Value task(objectValue);
        task["name"] = m_names[taskNameIdx];

        for (int iterationIdx = 0; iterationIdx < m_numberOfIterations; iterationIdx++)
        {
            Value taskTimes;
            task["iteration_" + to_string(iterationIdx)] = m_commReceivedEndTimes[taskNameIdx][iterationIdx];
        }
        partyReceived.append(task);
    }

    //send json object to create file
    createJsonFile(partyReceived, fileName);
}

void Measurement::analyzeMemory()
{
    string filePath = getcwdStr();
    string fileName = filePath + "/" + m_protocolName + "_memory_partyId=" + to_string(m_partyId)
                      +"_numOfParties=" + to_string(m_numOfParties) + ".json";

    //party is the root of the json objects
    Value partyMemory(arrayValue);

    for (int taskNameIdx = 0; taskNameIdx < m_names.size(); taskNameIdx++)
    {
        //Write for each task name all the iteration
        Value task(objectValue);
        task["name"] = m_names[taskNameIdx];

        for (int iterationIdx = 0; iterationIdx < m_numberOfIterations; iterationIdx++)
        {
            Value taskTimes;
            task["iteration_" + to_string(iterationIdx)] = m_commReceivedEndTimes[taskNameIdx][iterationIdx];
        }
        partyMemory.append(task);
    }

    //send json object to create file
    createJsonFile(partyMemory, fileName);
}

void Measurement::createJsonFile(Value v, string fileName)
{
    StreamWriterBuilder builder;
    unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
    try
    {
        fstream myfile;
        myfile.open(fileName, fstream::out);
        if (myfile.is_open())
        {
            writer->write(v, &myfile);
        }
    }

    catch (exception& e)
    {
        cout << "Exception thrown : " << e.what() << endl;
    }
}


Measurement::~Measurement()
{
    analyzeCpuData();
    analyzeCommSentData();
    analyzeCommReceivedData();
    analyzeMemory();
}

