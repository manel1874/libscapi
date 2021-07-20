# include "sink_20190816.h"

Sink::Sink(std::initializer_list<Signal *> InputSig, std::initializer_list<Signal *> OutputSig) 
{

  setNumberOfInputSignals((int) InputSig.size());
  setNumberOfOutputSignals((int) OutputSig.size());

  inputSignals = InputSig;
}

bool Sink::runBlock(void)
{

	int ready = inputSignals[0]->ready();

	int process;
	if (numberOfSamplesToProcess >= 0) {
		process = std::min((long int)ready, numberOfSamplesToProcess);
	}
	else {
		process = ready;
	}
	 
	if ((process == 0) || (numberOfSamplesToProcess==0)) return false;

	for (int i = 0; i<process; i++) (inputSignals[0])->bufferGet();

	numberOfSamplesToProcess = numberOfSamplesToProcess - process;
	if (displayNumberOfSamples) std::cerr << numberOfSamplesToProcess << "\n";

	return true;
}
