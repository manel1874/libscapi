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

#include "../../include/CryptoInfra/Measurement.hpp"


using namespace std;

Measurement* Measurement::m_instance = NULL;


Measurement * Measurement::instance(string protocolName, int partyId, string pathToFile)
{
    if (!m_instance)
        m_instance = new Measurement(protocolName, partyId, pathToFile);

    return m_instance;
}

Measurement::Measurement(string protocolName, int partyId, string pathToFile)
{

    m_name = protocolName;
    m_partyId = partyId;
    m_path = pathToFile + "/";
}

Measurement::~Measurement()
{}

void Measurement::startLog(string taskName)
{
    m_start = chrono::high_resolution_clock::now();
    m_taskName = taskName;
}

void Measurement::endLog()
{
    m_end = chrono::high_resolution_clock::now();
    Value value_obj;
    auto duration = chrono::duration_cast<chrono::milliseconds>(m_end - m_start).count();

    string filePath = m_path + m_name + "_" + to_string(m_partyId) + ".csv";
    cout << filePath << endl;
    try
    {
        ofstream myfile;
        myfile.open(filePath, ios::out | ios::app);
        if (myfile.is_open())
        {
            myfile << m_taskName << " ";
            myfile << duration_cast<milliseconds>(m_start.time_since_epoch()).count() << " ";
            myfile << duration_cast<milliseconds>(m_end.time_since_epoch()).count() << " ";
            myfile << to_string(duration) + "\n";
        }
        myfile.close();
    }
    catch (exception& e)
    {
        cout << "Exception thrown : " << e.what() << endl;
    }
}






