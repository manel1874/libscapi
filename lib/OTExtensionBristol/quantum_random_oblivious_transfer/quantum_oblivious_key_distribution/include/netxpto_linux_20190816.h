# ifndef PROGRAM_INCLUDE_NETXPTO_H_
# define PROGRAM_INCLUDE_NETXPTO_H_

// ##################### Compatibility Issues #########################################################
// # 
// # Requires C++17, because of the type std::byte
// #
// ####################################################################################################

// ####################################################################################################
// #
// # STL header files
// #
// ####################################################################################################
#define __STDC_WANT_LIB_EXT1__ 1
# include <time.h>


# include <algorithm>	// copy(), find(), sort(), std::min()
# include <array>		// array	
# include <bitset>
# include <chrono>      // duration, time_point
# include <cmath>       // sqrt(), pow()
# include <complex>		// complex, sqrt(), pow()		
# include <cctype>      
//# include <ctime>  
# include <fstream>		// fstream, ifstream, ofstream
# include <functional>	
# include <filesystem> 
# include <iostream>    // 
# include <iomanip>
# include <locale>
# include <map>         // map, multimap
# include <random>      // default_random_engine, normal_distribution
# include <sstream>     // istream, ostream
# include <vector>      // vector
# include <string>      // string, basic_string
# include <tuple>

// ####################################################################################################
// #
// # Global constants
// #
// ####################################################################################################

const int MAX_NAME_SIZE = 256;						// Maximum size of names (file names,..)
const int MAX_BUFFER_LENGTH = 10000;				// Maximum signal buffer length
const int DEFAULT_BUFFER_LENGTH = 512;				// Default buffer length
const int MAX_TOPOLOGY_SIZE = 100;					// Maximum number of blocks (topology) 
const int MAX_TAPS = 1000;							// Maximum taps number
const double PI = 3.1415926535897932384;			// Value of pi
const double SPEED_OF_LIGHT = 299792458;			// Speed of light in vaccum (m/s)
const double PLANCK_CONSTANT = 6.626070040e-34;		// Plack constant (NIST) (m^2 kg / s)  
const int MAX_NUMBER_OF_PATHS = 2;



//enum class signal_write_mode {Binary, Ascii};



// ####################################################################################################
// #
// # Alias for ISO C++ built-in types and NetXpto user-defined value types
// #
// ####################################################################################################

using t_raw = std::byte;
using t_char = char;
using t_unsigned_long = unsigned long int;
using t_unsigned = unsigned int;
using t_integer = int;
using t_binary = unsigned int;
using t_real = double;
using t_complex = std::complex<t_real>;
using t_complex_xy = struct { t_complex x; t_complex y; };
//using t_photon = struct { t_real probabilityAmplitude;  t_real polarization; }; // isto � para eliminar
//using t_photon_mp = struct { t_photon path[MAX_NUMBER_OF_PATHS]; };				// isto � para eliminar
using t_complex_xy_mp = struct { t_complex x; t_complex y; bool processed{ false }; };
using t_photon_mp_xy = struct { t_complex_xy_mp path[MAX_NUMBER_OF_PATHS]; };
using t_iqValues = std::complex<t_real>;

// ################################## t_message type definition ###########################################

// ########################################################################################################
// --------------------------------------------------------------------------------------------------------
// | messageType (14 bytes) | messageDataLength (6 bytes) | messageData (up to MAX_MEESAGE_SIZE-20 bytes) |
// --------------------------------------------------------------------------------------------------------
// ########################################################################################################

const size_t MESSAGE_TYPE_SIZE = 14;
const size_t MESSAGE_DATA_LENGTH_SIZE = 6;
const size_t MAX_MESSAGE_SIZE = 1000;

bool isNumber(const std::string& s);

size_t strToNumber(const std::string& s);

class t_message
{

public:

	t_message()
	{
		messageRaw.resize(MESSAGE_TYPE_SIZE + MESSAGE_DATA_LENGTH_SIZE);
	};

	void setMessageType(std::string mType)
	{
		mType.resize(MESSAGE_TYPE_SIZE);
		messageRaw.replace(0, MESSAGE_TYPE_SIZE, mType);
	};

	std::string getMessageType()
	{
		return messageRaw.substr(0, MESSAGE_TYPE_SIZE);
	}

	void setMessageDataLength(std::string mDataLength)
	{
		if (isNumber(mDataLength) && (strToNumber(mDataLength)<= MAX_MESSAGE_SIZE - MESSAGE_TYPE_SIZE - MESSAGE_DATA_LENGTH_SIZE))
		{
			std::string aux;
			aux.resize(MESSAGE_DATA_LENGTH_SIZE,'0');
			aux.replace(MESSAGE_DATA_LENGTH_SIZE - mDataLength.size(), mDataLength.size(), mDataLength);
			messageRaw.replace(MESSAGE_TYPE_SIZE, MESSAGE_DATA_LENGTH_SIZE, aux); 
		}
		else
		{
			std::cerr << "Message Data Length must be a positive integer, smaller than " << MAX_MESSAGE_SIZE - MESSAGE_TYPE_SIZE - MESSAGE_DATA_LENGTH_SIZE << "std::endl";
		}
	};

	std::string getMessageDataLength()
	{
		return messageRaw.substr(MESSAGE_TYPE_SIZE, MESSAGE_DATA_LENGTH_SIZE);
	}

	void setMessageData(std::string mData)
	{
		if (mData.size() > strToNumber(getMessageDataLength()))
			mData.resize(strToNumber(getMessageDataLength()));
		messageRaw.resize(MESSAGE_TYPE_SIZE + MESSAGE_DATA_LENGTH_SIZE);
		messageRaw.append(mData);
	};

	std::string getMessageData()
	{
		return messageRaw.substr(MESSAGE_TYPE_SIZE + MESSAGE_DATA_LENGTH_SIZE);
	}

	size_t size()
	{
		return messageRaw.size();
	}

	size_t maxSize() { return MAX_MESSAGE_SIZE; };

	char& operator[](int index) { return messageRaw[index]; }
	
	std::string messageRaw;

};

// ####################################################################################################
// #
// # Random engines
// #
// ####################################################################################################

using random_engine = std::default_random_engine;

// #######################################################################################################
// #
// # Operator << overloading, for complex<T>
// #
// #######################################################################################################

template<typename T>
std::ostream& operator<<(std::ostream& out, const std::complex<T>& cx) 
{ 
	out << cx.real() << " + i " << cx.imag();
	return out;
}

// ####################################################################################################
// #
// # NetXpto enumerate class types
// #
// ####################################################################################################

enum class signal_value_type {
	t_char,
	t_raw,
	t_binary,
	t_integer,
	t_real,
	t_complex,
	t_complex_xy,
	t_photon,
	t_photon_mp,
	t_photon_mp_xy,
	t_iqValues,
	t_message
};

enum class signal_type {
	Raw,
	Binary,
	TimeDiscreteAmplitudeContinuousReal,
	TimeDiscreteAmplitudeDiscreteReal,
	TimeContinuousAmplitudeContinuousReal,
	TimeContinuousAmplitudeDiscreteReal,
	TimeDiscreteAmplitudeContinuousComplex,
	TimeContinuousAmplitudeContinuousComplex,
	OpticalSignal,
	OpticalSignalXY,
	PhotonStreamXY,
	PhotonStreamMP,
	PhotonStreamMPXY,
	Message
};


//########################################################################################################################################################
//############################################################## SIGNALS DECLARATION #####################################################################
//########################################################################################################################################################

//########################################################## SIGNALS CLASS HIERARCHY #####################################################################
// The hierarchy of the signals are the following: the root is the class SIGNAL class, which includes all comum data and functions,
// the second level is a template where value type is defined.
// From this template a list of generic signals are defined using an alias.
// Specific signals are derived from the generic signals.
// All signals have associated a circular buffer, which is used as a temporary storage, to hold signal samples waiting for processing,
// and a file for permanente storage (the file is optional).
//#########################################################################################################################################################

// class Signal, this is an abstract class

class Signal {

public:

	// Signals constructors
	explicit Signal() {};
	explicit Signal(std::string fileName) : fileName{ fileName }, saveSignal{ true } {};
	explicit Signal(std::string fileName, t_unsigned_long bLength) : fileName{ fileName }, bufferLength{ bLength }, saveSignal{ true } {};
	explicit Signal(std::string fileName, std::string folderName) : fileName{ fileName }, folderName{ folderName }, saveSignal{ true } {};
	explicit Signal(std::string fileName, std::string folderName, t_unsigned_long bLength) : fileName{ fileName }, folderName{ folderName }, bufferLength{ bLength }, saveSignal{ true } {};
	explicit Signal(t_unsigned_long bLength) : bufferLength{ bLength } {};

	// Signal destructors
	virtual ~Signal() { if ( buffer != nullptr ) { delete(buffer); } };

	// Buffer manipulation funtions
	t_integer ready();										// Returns the number of samples in the circular buffer ready to be processed
	t_integer space() { return (bufferLength - ready()); }; // Returns the signal circular buffer space 




	template<typename T>void bufferPut(T value){
	(static_cast<T *>(buffer))[inPosition] = value;

	// THis part of the code should be deleted, 23/12/2019, ANP #########################
	if (bufferFull)
	{
		outPosition = (outPosition + 1) % bufferLength;
		std::cerr << "This silly point was reached!!!" << std::endl;
	}
	// ##################################################################################

	inPosition = (inPosition + 1) % bufferLength;

	bufferEmpty = false;
	bufferFull = inPosition == outPosition;

	if(inPosition == 0)
	{
 		if (saveSignal)
		{
			if (!headerWritten) writeHeader();

			if (firstValueToBeSaved <= bufferLength)
			{
				char *ptr = (char *)buffer;
				ptr = ptr + (firstValueToBeSaved - 1) * sizeof(T);
				std::ofstream fileHandler{ "./" + folderName + "/" + fileName, std::ios::out | std::ios::binary | std::ios::app };
				fileHandler.write(ptr, (bufferLength - (firstValueToBeSaved - 1)) * sizeof(T));
				fileHandler.close();
				firstValueToBeSaved = 1;
			}
			else
			{
				firstValueToBeSaved = firstValueToBeSaved - bufferLength;
			}
		}
	}
};		    // Puts a value in the buffer (at the end)



	void bufferPut(t_message& value);
	void bufferPut(std::byte* pValue);						// Puts a value in the buffer (at the end), the input parameter is a pointer for the first byte	
	//void bufferPut(std::byte* pValue, size_t n);			// Puts n values in the buffer (at the end), the input parameter is a pointer for the first byte



void bufferPut(std::byte* pValue, size_t n)
{
	auto vTypeSizeOf = this->valueTypeSizeOf();
	for (size_t m = 0; m < n; m++)
		this->bufferPut((std::byte*) &(pValue[m*vTypeSizeOf]));
}










	template<typename T> void bufferGet(T* valueAddr){

	// to be deleted, 24/12/2019 ####################################
	if (bufferEmpty) {
		*valueAddr = T();
		std::cerr << "Silly point: bufferGet template!" << std::endl;
	}
	// ##############################################################

	*valueAddr = static_cast<T*>(buffer)[outPosition];

	bufferFull = false;

	outPosition = (outPosition + 1) % bufferLength;

	bufferEmpty = outPosition == inPosition;

	return;
};

		// Returns a value from the buffer (from the begining)	




	void bufferGet(t_message* valueAddr);
	void bufferGet(std::byte* valueAddr, size_t n);			// Returns n values from the buffer (from the begining), works for any type	
	void bufferGet();										// Skips a value





// File manipulation
	void writeHeader();									// Opens the signal file in the default signals directory, \signals, and writes the signal header
	void writeHeader(std::string signalPath);			// Opens the signal file in the signalPath directory, and writes the signal header

	// Buffer and File manipulation
	void close();										// Close the signal, write the remaining samples in the file

	void reset() { inPosition = 0; outPosition = inPosition; bufferEmpty = true; bufferFull = false; }

	// Change signal parameters
	void setSaveSignal(bool sSignal) { saveSignal = sSignal; };
	bool getSaveSignal() const { return saveSignal; };

	void setType(signal_type sType, signal_value_type vType);// { type = sType; valueType = vType; };
	//void setType(std::string sType) { type = sType; };
	std::string getType() const { return type; };

	/* This functions are used in the sampler block, are they really needed? */
	void setInPosition(int iPosition) { inPosition = iPosition; };
	int getInPosition() const { return inPosition; };

	void setOutPosition(int oPosition) { outPosition = oPosition; };
	int getOutPosition() const { return outPosition; };

	void setBufferEmpty(bool bEmpty) { bufferEmpty = bEmpty; };
	bool getBufferEmpty() const { return bufferEmpty; };
	
	void setBufferFull(bool bFull) { bufferFull = bFull; };
	bool getBufferFull() const { return bufferFull; };


	//void setValueType(signal_value_type vType) { valueType = vType; };
	signal_value_type getValueType() const { return valueType; };

	void setFileName(std::string fName) { fileName = fName; };
	std::string getFileName() const { return fileName; };

	void setSignalFolderName(std::string fName) { folderName = fName; };
	std::string getSignalFolderName() const { return folderName; };

	//void setBufferLength(t_unsigned_long bLength) { bufferLength = bLength; };
	int getBufferLength() const { return bufferLength; };

	void setFirstValueToBeSaved(t_unsigned_long fValueToBeSaved) { firstValueToBeSaved = fValueToBeSaved; };
	t_unsigned_long getFirstValueToBeSaved() const { return firstValueToBeSaved; };

	void setNumberOfValuesToBeSaved(t_unsigned_long nOfValuesToBeSaved) { numberOfValuesToBeSaved = nOfValuesToBeSaved; };
	t_unsigned_long getNumberOfValuesToBeSaved() const { return numberOfValuesToBeSaved; };

	void setSymbolPeriod(double sPeriod) { symbolPeriod = sPeriod; samplesPerSymbol = symbolPeriod / samplingPeriod; };
	double getSymbolPeriod() const { return symbolPeriod; };

	void setSamplingPeriod(double sPeriod) { samplingPeriod = sPeriod; samplesPerSymbol = symbolPeriod / samplingPeriod; };
	double getSamplingPeriod() const { return samplingPeriod; };

	void setSamplesPerSymbol(double sPeriod) { samplesPerSymbol = sPeriod; symbolPeriod = samplesPerSymbol * samplingPeriod; samplingPeriod = symbolPeriod / samplesPerSymbol; };
	double getSamplesPerSymbol() const { return samplesPerSymbol; };

	void setOffHeaderWritten() { headerWritten=true; };

	virtual std::size_t valueTypeSizeOf()=0;
	template<typename t, signal_type sType, signal_value_type vType> friend class BaseSignal;

	void setCentralFrequency(double cFrequency) { centralFrequency = cFrequency; centralWavelength = SPEED_OF_LIGHT / centralFrequency; }
	double getCentralFrequency() const { return centralFrequency; };

	void setCentralWavelength(double cWavelength) { centralWavelength = cWavelength; centralFrequency = SPEED_OF_LIGHT / centralWavelength; }
	double getCentralWavelength() const { return centralWavelength; }

private:

	/* Circular buffer state variables */
	void* buffer{ nullptr };									// Pointer to buffer
	t_unsigned inPosition{ 0 };									// Next position for the buffer input values
	t_unsigned outPosition{ 0 };								// Next position for the buffer output values
	bool bufferEmpty{ true };									// Flag bufferEmpty
	bool bufferFull{ false };									// Flag bufferFull
	const t_unsigned bufferLength{ DEFAULT_BUFFER_LENGTH };		// Buffer length

	t_unsigned_long numberOfSavedValues{ 0 };					// Number of saved values
	t_unsigned_long count{ 0 };										// Number of values that have already entered in the buffer

	t_unsigned_long firstValueToBeSaved{ 1 };					// First value (>= 1) to be saved
	bool saveSignal{ false };

	std::string type;											// Signal type

	signal_type signalType;
	signal_value_type valueType;								// Signal samples type

	std::string fileName{ "" };									// Name of the file where data values are going to be saved
	std::string folderName{ "signals" };								// folder where signals are going to be saved by default
	bool headerWritten{ false };

	long int numberOfValuesToBeSaved{ -1 };						// Number of values to be saved, if -1 all values are going to be saved

	double symbolPeriod{ 1.0 };									// Signal symbol period (it is the inverse of the symbol rate)
	double samplingPeriod{ 1.0 };								// Signal sampling period (it is the time space between two samples)
	double samplesPerSymbol{ 1.0 };								// samplesPerSymbol = symbolPeriod / samplingPeriod;

	double centralWavelength{ 1550E-9 };
	double centralFrequency{ SPEED_OF_LIGHT / centralWavelength };

};

// This template defines a set of final classes
template<typename T, signal_type sType, signal_value_type vType>
class BaseSignal final: public Signal {

public:

	using value_type = T;

	BaseSignal() : Signal() { setBuffer(); }
	BaseSignal(std::string fileName) : Signal(fileName) { setBuffer(); }
	BaseSignal(std::string fileName, t_unsigned_long bLength) : Signal(fileName, bLength) { setBuffer(); }
	BaseSignal(std::string fileName, std::string folderName) : Signal(fileName, folderName) { setBuffer(); }
	BaseSignal(std::string fileName, std::string folderName, t_unsigned_long bLength) : Signal(fileName, folderName, bLength) { setBuffer(); }
	BaseSignal(t_unsigned_long bLength) : Signal(bLength) { setBuffer(); }

	value_type bufferGet()
		{
		if (bufferEmpty) return value_type();

		value_type value = static_cast<value_type *>(buffer)[outPosition];

		bufferFull = false;

		outPosition = (outPosition + 1) % bufferLength;

		bufferEmpty = outPosition == inPosition;

		return value;
	}

	value_type& operator[](int index) { return (static_cast<value_type*>(buffer)[(outPosition + index) % bufferLength]); }

	std::size_t valueTypeSizeOf() { return sizeof(T); }

private:

	void setBuffer() {
		setType(sType, vType);
		if (buffer == nullptr) buffer = (value_type*) (new value_type[getBufferLength()]());
	}
};



using Raw = BaseSignal< t_raw, signal_type::Raw, signal_value_type::t_raw>;
using Binary = BaseSignal< t_binary, signal_type::Binary, signal_value_type::t_binary> ;
using TimeDiscreteAmplitudeContinuousReal = BaseSignal<t_real, signal_type::TimeDiscreteAmplitudeContinuousReal, signal_value_type::t_real>;
using TimeDiscreteAmplitudeDiscreteReal = BaseSignal<t_real, signal_type::TimeDiscreteAmplitudeDiscreteReal, signal_value_type::t_real>;
using TimeContinuousAmplitudeContinuousReal = BaseSignal<t_real, signal_type::TimeContinuousAmplitudeContinuousReal, signal_value_type::t_real>;
using TimeContinuousAmplitudeDiscreteReal = BaseSignal<t_real, signal_type::TimeContinuousAmplitudeDiscreteReal, signal_value_type::t_real>;
using TimeDiscreteAmplitudeContinuousComplex = BaseSignal<t_complex, signal_type::TimeDiscreteAmplitudeContinuousComplex, signal_value_type::t_complex>;
using TimeContinuousAmplitudeContinuousComplex = BaseSignal<t_complex, signal_type::TimeContinuousAmplitudeContinuousComplex, signal_value_type::t_complex>;
using OpticalSignal = BaseSignal<t_complex, signal_type::OpticalSignal, signal_value_type::t_complex>;
using OpticalSignalXY = BaseSignal<t_complex, signal_type::OpticalSignalXY, signal_value_type::t_complex_xy>;
using PhotonStreamXY = BaseSignal<t_complex_xy, signal_type::PhotonStreamXY, signal_value_type::t_complex_xy>;
//using PhotonStreamMP = BaseSignal<t_photon_mp, signal_type::PhotonStreamMP, signal_value_type::t_photon_mp>;
using PhotonStreamMPXY = BaseSignal<t_photon_mp_xy, signal_type::PhotonStreamMPXY, signal_value_type::t_photon_mp_xy>;
using Message = BaseSignal<t_message*, signal_type::Message, signal_value_type::t_message>;



//########################################################################################################################################################
//########################################################## GENERIC BLOCK DECLARATIONS AND DEFINITIONS ##################################################
//########################################################################################################################################################

class Block {

public:

	/* Methods */
	Block(){};
	Block(std::vector<Signal*> &InputSig, std::vector<Signal*> &OutputSig);
	Block(std::initializer_list<Signal*> InputSig, std::initializer_list<Signal*> OutputSig); // since C++11


	//void initializeBlock(std::vector<Signal*> InputSig, vector<Signal*> OutputSig);
	void initializeBlock();

	virtual void initialize(void){};

	virtual bool runBlock();

	void terminateBlock();
	virtual void terminate(void){};

	void closeOutputSignals();

	void setNumberOfInputSignals(int nOfInputSignal) { numberOfInputSignals = nOfInputSignal; };
	int getNumberOfInputSignals() { return numberOfInputSignals; };

	void setNumberOfOutputSignals(int nOfOutputSignal) { numberOfOutputSignals = nOfOutputSignal; };
	int getNumberOfOutputSignals() { return numberOfOutputSignals; };

	void setLogValue(bool lValue) { logValue = lValue; }
	bool getLogValue() { return logValue; }

	void setFirstRun(bool fRun) { firstRun = fRun; }
	bool getFirstRun() { return firstRun; }

	void setFirstTime(bool fTime) { firstTime = fTime; }
	bool getFirstTime() { return firstTime; }

	std::string getSignalsFolderName();

	std::vector<Signal *> inputSignals;
	std::vector<Signal *> outputSignals;

private:

	bool logValue{ true };
	bool firstRun{ true };		// To be deleted, 2020/02/04, the name firstTime is more comum
	bool firstTime{ true };

	int numberOfInputSignals;	// passar para private, 2018/07/15
	int numberOfOutputSignals;  // passar para private, 2018/07/15


};


//########################################################################################################################################################
//########################################################## GENERIC SYSTEM DECLARATIONS AND DEFINITIONS #################################################
//########################################################################################################################################################


class System {

public:

	//######################################################################################################

	System() {};
	void setSystem(std::initializer_list<Block *> MainSystem);

	System(std::initializer_list<Block *> MainSystem);
	System(std::initializer_list<Block*> MainSystem, std::string signalsFolderName);
	System(std::initializer_list<Block *> MainSystem, std::string signalsFolderName, std::vector<std::string> list);

	bool run();
	bool run(std::string signalPath);
	void terminate();
	void terminateSuperBlock();

	//########################################################################################################

	void setLogValue(bool value);
	bool getLogValue() { return logValue; };

	void setOpenFile(bool value);
	bool getOpenFile() { return openFile; };

	void setLogFileName(std::string newName);
	std::string getLogFileName() { return logFileName; };

	void setSignalsFolderName(std::string newName);
	std::string getSignalsFolderName() { return signalsFolder; };

	void setSaveSignals(bool sSignals);
	bool const getSaveSignals(void) { return saveSignals; };

	void setLoadedInputParameters(std::vector<std::string> loadedInputParams);
	std::vector<std::string> getLoadedInputParameters() { return loadedInputParameters; };
	size_t getSystemBlocksSize() { return SystemBlocks.size(); };
	std::vector<Block *> getSystemBlocks() { return SystemBlocks; };
	
	//########################################################################################################

private:

	std::string signalsFolder{ "signals" };
	bool saveSignals{ true };

	char fileName[MAX_NAME_SIZE];  // Name of the file with system description (.sdf)
	char name[MAX_NAME_SIZE];  // System Name
	int numberOfBlocks;  // Number of system Blocks
	int(*topology)[MAX_TOPOLOGY_SIZE];  // Relationship matrix
	std::vector<Block *> SystemBlocks;  // Pointer to an array of pointers to Block objects
								   //Log File Inputs
	std::string logFileName{ "log.txt" }; // The name of the file where the debug info will be written
	bool logValue{ true }; // Will write debug info if true
	bool openFile{ true };
	std::ofstream logFile;
	std::vector<std::string> loadedInputParameters;
};

//########################################################################################################################################################
//#################################################### GENERIC SUPER BLOCK DECLARATIONS AND DEFINITIONS ##################################################
//########################################################################################################################################################


class SuperBlock : public Block {

public:


	/* Methods */
	SuperBlock(std::initializer_list<Signal *> inputSignals, std::initializer_list<Signal *> outputSignals) : Block(inputSignals, outputSignals) { superBlockSystem.setLogValue(false); };

	void initialize(void);

	virtual bool runBlock(std::string signalPath);

	void terminate(void);

	/* Set Methods */

	//void setBlocks(std::vector<Block*> blks) { blocks = blks; };
	void setSuperBlockSystem(std::initializer_list<Block*> blks) { superBlockSystem.setSystem(blks); };

	void setLogValue(bool lValue) { superBlockSystem.setLogValue(lValue);	};
	bool const getLogValue() { return superBlockSystem.getLogValue(); };

	void setOpenFile(bool value) { superBlockSystem.setOpenFile(value); };

	void setLogFileName(std::string lFileName) { superBlockSystem.setLogFileName(lFileName); };

	void setSuperBlockFolderName(std::string fName) { superBlockFolderName = fName; };
	std::string getSuperBlockFolderName() { return superBlockFolderName; };

	void setSignalsFolderName(std::string sFolderName) { superBlockSystem.setSignalsFolderName(sFolderName); };
	std::string getSignalsFolderName() { return superBlockSystem.getSignalsFolderName(); };

	void setLoadedInputParameters(std::vector<std::string> loadedInputParams) { superBlockSystem.setLoadedInputParameters(loadedInputParams); };

	void setSaveInternalSignals(bool sInternalSignals) { superBlockSystem.setSaveSignals(sInternalSignals);  };
	bool const getSaveInternalSignals(void) { return superBlockSystem.getSaveSignals(); };

	/*void setSuperBlockSystemValues();*/

private:

	/* State Variables */

	std::vector<Block*> moduleBlocks;
	std::vector<Block*> blocks;
	System superBlockSystem;
	std::ofstream logFileSP;

	/* Input Parameters */

	std::string superBlockFolderName{ "signals/SuperBlock" };
	
	/*
	bool logValue{ true };
	
	std::string signalsFolderName{ "signals" };
	bool saveInternalSignals{ true };
	*/
};

//########################################################################################################################################################
//###################################################################### LINEAR FILTERS ##################################################################
//########################################################################################################################################################


class FIR_Filter : public Block {

	/* State Variable */
	std::vector<t_real> delayLine;

	bool saveImpulseResponse{ true };
	std::string impulseResponseFilename{ "impulse_response.imp" };

	/* Input Parameters */
	bool seeBeginningOfImpulseResponse{ true };

public:

	/* State Variable */
	std::vector<t_real> impulseResponse;

	/* Input Parameters */
	int impulseResponseLength;							// filter order + 1 (filter order = number of delays)


	/* Methods */
	FIR_Filter(std::initializer_list<Signal *> InputSig, std::initializer_list<Signal *> OutputSig) :Block(InputSig, OutputSig) {};
	FIR_Filter(std::vector<Signal *> &InputSig, std::vector<Signal *> &OutputSig) :Block(InputSig, OutputSig) {};
	FIR_Filter() {};

	void initializeFIR_Filter(void);

	bool runBlock(void);

	void terminate(void){};

	void setSaveImpulseResponse(bool sImpulseResponse) { saveImpulseResponse = sImpulseResponse; };
	bool getSaveImpulseResponse(void){ return saveImpulseResponse; };

	void setImpulseResponseLength(int iResponseLength) { impulseResponseLength = iResponseLength; };
	int const getImpulseResponseLength(){ return impulseResponseLength; }

	void setImpulseResponseFilename(std::string fName) { impulseResponseFilename = fName; };
	std::string getImpulseResponseFilename() { return impulseResponseFilename; };

	void setSeeBeginningOfImpulseResponse(bool sBeginning){ seeBeginningOfImpulseResponse = sBeginning; };
	bool const getSeeBeginningOfImpulseResponse(){ return seeBeginningOfImpulseResponse; };

};


class FD_Filter : public Block {
	
	/* State Variable */
	
	std::vector<t_real> inputBufferTimeDomain;
	std::vector<t_real> outputBufferTimeDomain;

	int inputBufferPointer{ 0 };
	int outputBufferPointer{ 0 };
	
	/* Input Parameters */
	bool saveTransferFunction{ true };
	std::string transferFunctionFilename{ "transfer_function.tfn" };
	int transferFunctionLength{ 128 };

	int inputBufferTimeDomainLength{ transferFunctionLength };
	int outputBufferTimeDomainLength{ transferFunctionLength };

public:
	/* State Variable */
	std::vector<t_complex> transferFunction;

	/* Methods */
	FD_Filter() {};
	FD_Filter(std::vector<Signal *> &InputSig, std::vector<Signal *> &OutputSig) :Block(InputSig, OutputSig) {};
	FD_Filter(std::initializer_list<Signal *> InputSig, std::initializer_list<Signal *> OutputSig) :Block(InputSig, OutputSig) {};

	void initializeFD_Filter(void);

	bool runBlock(void);

	void terminate(void) {};

	void setInputBufferTimeDomainLength(int iBufferTimeDomainLength) { inputBufferTimeDomainLength = iBufferTimeDomainLength; };
	int const getInputBufferTimeDomainLength() { return inputBufferTimeDomainLength; }

	void setOutputBufferTimeDomainLength(int oBufferTimeDomainLength) { outputBufferTimeDomainLength = oBufferTimeDomainLength; };
	int const getOutputBufferTimeDomainLength() { return outputBufferTimeDomainLength; }

	void setInputBufferPointer(int iBufferPointer) { inputBufferPointer = iBufferPointer; };
	int const getInputBufferPointer() { return inputBufferPointer; }

	void setOutputBufferPointer(int oBufferPointer) { outputBufferPointer = oBufferPointer; };
	int const getOutputBufferPointer() { return outputBufferPointer; }

	void setSaveTransferFunction(bool sTransferFunction) { saveTransferFunction = sTransferFunction; };
	bool getSaveTransferFunction(void) { return saveTransferFunction; };

	void setTransferFunctionLength(int iTransferFunctionLength) { transferFunctionLength = iTransferFunctionLength; };
	int const getTransferFunctionLength() { return transferFunctionLength; };

};

/*
// Generates a complex signal knowing the real part and the complex part.
class RealToComplex : public Block {
 public:
	 RealToComplex(std::vector<Signal *> &InputSig, std::vector<Signal *> &OutputSig);
	 bool runBlock(void);
 //private:
};
*/

// Separates the complex signal into two parts: real and imaginary.
/*class ComplexToReal : public Block {
 public:
	 ComplexToReal(std::vector<Signal *> &InputSig, vector<Signal *> &OutputSig);
	 bool runBlock(void);
 //private:
};*/





//########################################################################################################################################################
//############################################################### GENERIC DSP FUNCTIONS ##################################################################
//########################################################################################################################################################


/*class OverlapMethod
{

public:

	void overlapSaveSymComplexIn(std::vector<complex <double>> &v_in, vector<complex <double>> &v_out, vector<complex <double>> Hf, int NFFT);
	void overlapSaveSyRealIn(std::vector<double> &v_in, vector<double> &v_out, vector<double> Hf, int NFFT);
	void overlapSaveAsym(std::vector<double> &real_in, vector<double> &imag_in, vector<double> &real_out, vector<double> &imag_out, vector<double> h_real, vector<double> h_imag, int M, int L, int N);
	void overlapSaveSym(std::vector<double> &real_in, vector<double> &imag_in, vector<double> &real_out, vector<double> &imag_out, vector<double> h_real, vector<double> h_imag, int NFFT);
	void checkSize(std::vector<double> &real_in, vector<double> &imag_in, int L);

};




class Fft
{

public:
	vector<complex <double>> directTransformInReal(std::vector<double> real);

	vector<double> inverseTransformInCP(std::vector<complex <double>> &In);
	
	void directTransform(std::vector<double> &real, vector<double> &imag);
	void inverseTransform(std::vector<double> &real, vector<double> &imag);
	void transformRadix2(std::vector<double> &real, vector<double> &imag);
	void transformBluestein(std::vector<double> &real, vector<double> &imag);
	void convolve(const vector<double> &x, const vector<double> &y, vector<double> &out);
	void convolve(const vector<double> &xreal, const vector<double> &ximag, const vector<double> &yreal, const vector<double> &yimag, vector<double> &outreal, vector<double> &outimag);
	
	void Radix2(std::vector<double> &real, vector<double> &imag, int m);
	void Bluestein(std::vector<double> &real, vector<double> &imag, int m);
};*/


class ComplexMult
{
public:
	void CMultVector(std::vector<double> &v1_real, std::vector<double> &v1_imag, std::vector<double> v2_real, std::vector<double> v2_imag);
	void CMultVector_Loop(std::vector<double> &v1_real, std::vector<double> &v1_imag, std::vector<double> v2_real, std::vector<double> v2_imag);
	std::vector<std::complex <double>> CMultVectorInCP(std::vector<std::complex <double>> &v1_in, std::vector<std::complex <double>> &v2_in);
	void ComplexVect2ReImVect(std::vector<std::complex <double>> &v_in, std::vector<double> &v1_real, std::vector<double> &v1_imag);
	void CMultVector_InComplex(std::vector<std::complex <double>> &v1_in, std::vector<std::complex <double>> &v2_in);
	void ReImVect2ComplexVect(std::vector<double> &v1_real, std::vector<double> &v1_imag, std::vector<std::complex <double>> &v_out);

	std::vector<std::complex<double>> ReImVect2ComplexVector(std::vector<double> &v1_real, std::vector<double> &v1_imag);
	std::vector<std::complex <double>> complexVectorMultiplication(std::vector<std::complex <double>> &v1_in, std::vector<std::complex <double>> &v2_in);
};


///////////////////// Fast Fourier Transform ////////////////////////

class FourierTransform {

public:

	std::vector<std::complex<double>> fft(std::vector<std::complex<double> > &vec, int sign);
	std::vector<std::complex<double>> fft(std::vector<std::complex<double> > &vec);
	std::vector<std::complex<double>> ifft(std::vector<std::complex<double> > &vec);
	void transformRadix2(std::vector<std::complex<double> > &vec);
	void transformBluestein(std::vector<std::complex<double> > &vec);
	void convolve(
		const std::vector<std::complex<double> > &vecx,
		const std::vector<std::complex<double> > &vecy,
		std::vector<std::complex<double> > &vecout);
};

///////////////////// System Parameters ////////////////////////

class SystemInputParameters {
private:
	std::vector<std::string> loadedInputParameters;
	std::string inputParametersFileName{ "input_parameters_0.txt" }; //name of the file from where the input parameters will be read
	std::string outputFolderName{ "signals" };
	enum ParameterType { INT, DOUBLE, BOOL, STRING }; //types of parameters
											  //A parameter can only be of 1 type
	class Parameter {
	private:
		//Type of the parameter. this type should be hidden from the user
		ParameterType type;
		union { //pointers to the parameter
			int* i;
			double* d;
			bool* b;
			std::string* s;
		};

	public:
		//Changes the value of the parameter
		void setValue(int value);
		void setValue(double value);
		void setValue(bool value);
		void setValue(std::string value);

		ParameterType getType();
		//Constructor for parameter of type int
		Parameter(int* elem);
		//Constructor for parameter of type double
		Parameter(double* elem);
		//Constructor for parameter of type bool
		Parameter(bool* elem);
		//Constructor for parameter of type string
		Parameter(std::string* elem);
	};

	int parseInt(std::string str);
	double parseDouble(std::string str);
	bool parseBool(std::string str);
	std::string parseString(std::string str);

	std::vector<std::string> split(const std::string& text, char sep);
	std::map<std::string, Parameter*> parameters = std::map<std::string, Parameter*>(); //Maps the names of the variables to the addresses of the parameters

public:
	std::string getInputParametersFileName() { return inputParametersFileName; }
	void setInputParametersFileName(std::string fname) { inputParametersFileName = fname; }
	std::string getOutputFolderName() { return outputFolderName; }
	std::vector<std::string> getLoadedInputParameters() { return loadedInputParameters; }
	void readSystemInputParameters();
	//Adds the parameter to the map
	void addInputParameter(std::string name, int* variable);
	void addInputParameter(std::string name, double* variable);
	void addInputParameter(std::string name, bool* variable);
	void addInputParameter(std::string name, std::string* variable);
	/* Default empty constructor. Initializes the map */
	SystemInputParameters() {}
	SystemInputParameters(int argc, char* argv[]);
	/* Deletes all heap memory occupied by the parameters */
	~SystemInputParameters();
};

//########################################################################################################################################################
//############################################################### RANDOM NUMBER GENERATORS ##################################################################
//########################################################################################################################################################


// Generates integer numbers uniformely distribuited in the interval [lo,hi)
template<typename T = random_engine >
class UniformRandomIntegerNumbers {
	UniformRandomIntegerNumbers(int low, int high) : r(bind(std::uniform_int_distribution<>(low, high), T())) { };
	UniformRandomIntegerNumbers(long int seed, int low, int high) : r(bind(std::uniform_int_distribution<>(low, high), T(seed))) { };
	int operator()() const { return r(); };
private:
	std::function<int()> r;
};

// Generates real numbers (double) uniformely distribuited in the interval [lo,hi)
template<typename T= random_engine >
class UniformRandomRealNumbers {
public:
	UniformRandomRealNumbers(double low, double high) :r(bind(std::uniform_real_distribution<>(low, high), T())) { };
	UniformRandomRealNumbers(long int seed, double low, double high) :r(bind(std::uniform_real_distribution<>(low, high), T(seed))) { };
	double operator()() { return r(); };
private:
	std::function<double()> r;
};

//########################################################################################################################################################
//############################################################### NUMERICAL WINDOWS ######################################################################
//########################################################################################################################################################

enum class WindowType { None, Hann, Hamming };

std::vector<double> getWindow(WindowType windowType, int windowSize);

# endif // PROGRAM_INCLUDE_netxpto_H_
