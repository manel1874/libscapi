# ifndef SINK_H_
# define SINK_H_

# include "netxpto_linux_20190816.h"

class Sink : public Block {

public:

	/* Methods */
	Sink() {};
	Sink(std::initializer_list<Signal*> InputSig, std::initializer_list<Signal*> OutputSig);

	bool runBlock(void);

	void setNumberOfSamplesToProcess(long int nOfSamplesToProcess) { numberOfSamplesToProcess = nOfSamplesToProcess; };

	void setDisplayNumberOfSamples(bool opt) { displayNumberOfSamples = opt; };

private:

	/* State Variables */

	bool displayNumberOfSamples{ false };

	/* Input Parameters */

	long int numberOfSamplesToProcess{ -1 };

};

#endif
