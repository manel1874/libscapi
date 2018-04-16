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
