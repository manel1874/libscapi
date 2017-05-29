//
// Created by moriya on 15/2/17.
//
#include "YaoSEParty.h"

int binaryTodecimal(int n){

    int output = 0;
    int pow = 1;

    //turns the string of the truth table that was taken as a decimal number into a number between 0 and 15 which represents the truth table
    //0 means the truth table of 0000 and 8 means 1000 and so on. The functions returns the decimal representation of the thruth table.
    for(int i=0; n > 0; i++) {

        if(n % 10 == 1) {

            output += pow;
        }
        n /= 10;

        pow = pow*2;
    }
    return output;
}

void convertCircuit(string scapiCircuit, string newCircuit){

    int inFan, outFan, input0, input1, output, typeBin, numOfinputsForParty0, numOfinputsForParty1, numberOfGates, numberOfOutputs, type;

    ifstream myfile;
    ofstream otherFile;

    myfile.open(scapiCircuit);
    otherFile.open(newCircuit);

    int temp;
    if (myfile.is_open())
    {

        myfile >> numberOfGates;//get the gates
        otherFile << numberOfGates << " "; //print number of gates

        myfile >> temp;

        myfile >> temp;
        myfile >> numOfinputsForParty0;

        for(int i = 0; i<numOfinputsForParty0; i++){
            myfile >>temp;
        }

        myfile >> temp;
        myfile >> numOfinputsForParty1;

        for(int i = 0; i<numOfinputsForParty1; i++){
            myfile >>temp;
        }


        otherFile << numOfinputsForParty0 + numOfinputsForParty1 + numberOfGates << endl;//print number of wires
        //get the number of outputs
        myfile >> numberOfOutputs;

        otherFile << numOfinputsForParty0 << " " <<numOfinputsForParty1<<" "<<numberOfOutputs<<endl;
        for(int i=0;i < numberOfOutputs;i++){
            myfile >> temp;
        }




        for(int i=0; i<numberOfGates;i++) {

            //read from the file and print the exat values
            myfile >> inFan;
            otherFile << inFan << " ";

            myfile >> outFan;
            otherFile << outFan << " ";

            myfile >> input0;
            otherFile << input0 << " ";

            if (inFan != 1)//a 2 input 1 output gate - regualr gate, else we have a not gate
            {
                myfile >> input1;
                otherFile << input1 << " ";
            }


            myfile >> output;
            otherFile << output << " ";

            myfile >> typeBin;
            type = binaryTodecimal(typeBin);

            if (inFan == 1)//NOT gate
            {
                otherFile << "NOT" << endl;
            } else if (type == 6) {
                otherFile << "XOR" << endl;
            } else if (typeBin == 1) {
                otherFile << "AND" << endl;
            } else if (typeBin == 7) {
                otherFile << "OR" << endl;
            }
        }
    }
    myfile.close();
    otherFile.close();

}

int main(int argc, char* argv[]) {

    string newCircuit = "emp_format_circuit.txt";
    convertCircuit(argv[2], newCircuit);

    int id = atoi(argv[1]);
    YaoSEParty party(id, newCircuit, argv[3], atoi(argv[4]), argv[5]);

    int runs = 100;
    auto start = chrono::high_resolution_clock::now();
    for (int i=0; i<runs; i++){
        party.run();
    }
    auto end = chrono::high_resolution_clock::now();
    auto generateTotalTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    cout<<"running "<<runs<<" times took in average "<<generateTotalTime/runs << " millis"<<endl;
    if (id == 2) {
        auto out = party.getOutput();
        cout << "result: " << endl;
        for (int i = 0; i < cf->n3; i++) {
            cout << out[i] << " ";
        }
        cout << endl;
    }


    int offlineTime = 0, onlineTime = 0;

    for (int i=0; i<runs; i++){
        offlineTime += party.runOffline();

        onlineTime += party.runOnline();

    }
    cout<<"running offline "<<runs<<" times took "<<offlineTime/runs << " millis"<<endl;
    cout<<"running online "<<runs<<" times took "<<onlineTime/runs << " millis"<<endl;
    if (id == 2) {
        auto out = party.getOutput();
        cout << "result: " << endl;
        for (int i = 0; i < cf->n3; i++) {
            cout << (int)out[i] << " ";
        }
        cout << endl;
    }

}
