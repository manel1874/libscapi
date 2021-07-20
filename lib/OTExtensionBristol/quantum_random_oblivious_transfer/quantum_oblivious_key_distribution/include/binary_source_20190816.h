# ifndef BINARY_SOURCE_H_
# define BINARY_SOURCE_H_

# include "netxpto_linux_20190816.h"

enum class BinarySourceMode { Random, PseudoRandom, DeterministicCyclic, DeterministicAppendZeros };

class BinarySource : public Block {

public:

	//##############################################################################################################

	BinarySource(std::initializer_list<Signal *> InputSig, std::initializer_list<Signal *> OutputSig) : Block(InputSig, OutputSig) {};


	void initialize(void);
	bool runBlock(void);

	//##############################################################################################################

	void setBitPeriod(double bPeriod);
	double getBitPeriod(void) const { return bitPeriod; };

	void setNumberOfBits(long int nOfBits) { numberOfBits = nOfBits; };
	long int getNumberOfBits(void) const { return numberOfBits; };

	void setMode(BinarySourceMode m) { mode = m; }
	BinarySourceMode getMode(void) const { return mode; };

	void setSeed(long int s) { seed = s; };
	long int getSeed(void) const { return seed; };

	void setProbabilityOfZero(double pZero) { probabilityOfZero = pZero; };
	double getProbabilityOfZero(void) const { return probabilityOfZero; };

	void setBitStream(std::string bStream) { bitStream = bStream; };
	std::string getBitStream(void) const { return bitStream; };

	void setPatternLength(int pLength) { patternLength = pLength; };
	int getPatternLength(void) const { return patternLength; };

	//###############################################################################################################

private:

	//# Input Parameters ############################################################################################

	double bitPeriod{ 1e-11 };
	long int numberOfBits{ -1 };
	BinarySourceMode mode{ BinarySourceMode::PseudoRandom };
	double probabilityOfZero{ 0.5 };
	int patternLength{ 7 };
	std::string bitStream{ "0100011101010101" };
	long int seed{ (long int) std::chrono::system_clock::now().time_since_epoch().count() };

	//# State Variables #############################################################################################

	std::vector<int> acumul;
	int posBitStream{ 0 };

	 //###############################################################################################################

	 void runPseudoRandom(long int process);
	 void runRandom(long int process);
	 void runDeterministicCyclic(long int process);
	 void runDeterministicAppendZeros(long int process);

	 UniformRandomRealNumbers<> uniformeRandomNumberBetweenZeroAndOne{ seed, 0, 1 };

	 //###############################################################################################################

};

# endif


