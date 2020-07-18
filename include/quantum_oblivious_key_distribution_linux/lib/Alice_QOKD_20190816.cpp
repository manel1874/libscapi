#include "Alice_QOKD_20190816.h"

bool AliceQOKD::runBlock(void) {
	int ready = inputSignals[0]->ready();
	int space_0 = outputSignals[0]->space();
	int space_1 = outputSignals[1]->space();
	int space_2 = outputSignals[2]->space();
	int space = std::min(std::min(space_0, space_1), space_2);
	int process = std::min(ready,space);

	if (process == 0) return false;
	
	for (auto i = 0; i < process; i++)
	{
		t_binary randomBits;
		inputSignals[0]->bufferGet(&randomBits);
		outputSignals[0]->bufferPut(randomBits);
		outputSignals[1]->bufferPut(randomBits);
		outputSignals[2]->bufferPut((t_binary)1);
	}

	std::cout << process <<" oblivious keys are generated"<< std::endl;
		return true;
}


