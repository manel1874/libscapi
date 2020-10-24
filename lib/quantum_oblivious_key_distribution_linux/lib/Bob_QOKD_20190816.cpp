#include "Bob_QOKD_20190816.h"


bool BobQOKD::runBlock(void) {

	int ready_0 = (inputSignals[0]->ready())/2;
	int ready_1 = inputSignals[1]->ready();
	int space_0 = outputSignals[0]->space();
	int space_1 = outputSignals[1]->space();
	int ready = std::min(ready_0, ready_1);
	int space = std::min(space_0,space_1);
	int process = std::min(ready, space);

	if (process == 0) return false;

	for (auto i = 0; i < process; i ++) 
	{
		inputSignals[0]->bufferGet((std::byte*)bobObliviousKeys, 2);

		t_binary bobRandomBits;
		inputSignals[1]->bufferGet(&bobRandomBits);

			if (bobRandomBits == 0)
			{
				bobObliviousKeys[0] = 0;
				bobControlSignal[0] = 1;
				bobControlSignal[1] = 0;
			}
			else
			{
				bobObliviousKeys[1] = 1;
				bobControlSignal[0] = 0;
				bobControlSignal[1] = 1;
			}

			outputSignals[0]->bufferPut((std::byte*)bobObliviousKeys, 2);
			outputSignals[1]->bufferPut((std::byte*)bobControlSignal, 2);
	}
	std::cout << 2*process << " oblivious keys are generated" << std::endl;
	return true;
}


