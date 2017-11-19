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
        :m_startTimes(names.size(), vector<long>(numOfIteration)),
         m_times(names.size(), vector<long>(numOfIteration)),
         m_names{move(names)}
{
    m_protocolName = protocolName;
    m_partyId = partyId;
    m_numberOfIterations = numOfIteration;
    m_numOfParties = numOfParties;

}


Measurement::~Measurement()
{
    string filePath = getcwdStr();
    string fileName = filePath + "/" + m_protocolName + "_partyId=" + to_string(m_partyId)
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
            task["iteration_" + to_string(iterationIdx)] = m_times[taskNameIdx][iterationIdx];
        }
        party.append(task);
    }


    //Convert JSON object to string
    StreamWriterBuilder builder;
    unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
    try
    {
        fstream myfile;
        myfile.open(fileName, fstream::out);
        if (myfile.is_open())
        {
            writer->write(party, &myfile);
        }
    }

    catch (exception& e)
    {
        cout << "Exception thrown : " << e.what() << endl;
    }
}

