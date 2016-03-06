#pragma once

#include "CommitmentScheme.hpp"
#include "../comm/TwoPartyComm.hpp"
#include "../../include/primitives/DlogOpenSSL.hpp"
#include <map>


/**
* Concrete implementation of commitment message used by Pedersen commitment scheme.
*/
class CmtPedersenCommitmentMessage : public CmtCCommitmentMsg{
	// in Pedersen schemes the commitment object is a groupElement. 
	// in order to this class be a serializable, we get it as GroupElementSendableData.
private:
	std::shared_ptr<GroupElementSendableData> c=NULL;
	long id=0; // the id of the commitment
	int serializedSize_;
public:
	/**
	* Empty constructor - used to allow initialization from byte array
	*/
	CmtPedersenCommitmentMessage() {
		c = make_shared<ZpElementSendableData>(0);
	};

	/**
	* Constructor that sets the commitment and id.
	* @param c the actual commitment object. In Pedersen schemes the commitment object is a groupElement.
	* @param id the commitment id.
	*/
	CmtPedersenCommitmentMessage(std::shared_ptr<GroupElementSendableData> c, long id) {
		this->c = c;
		this->id = id;
	}

	shared_ptr<void> getCommitment() override { return c; };
	long getId() override { return id; };

	// SerializedNetwork implementation:

	std::shared_ptr<byte> toByteArray() override {
		auto byteGe = c->toByteArray();
		int geSize = c->getSerializedSize();
		serializedSize_ = sizeof(long) + geSize;
		byte * result = new byte[serializedSize_];
		copy(((byte*)&id), ((byte*)&id) + sizeof(long), result);
		copy(byteGe.get(), byteGe.get() + geSize, result+sizeof(long));
		std::shared_ptr<byte> result_shared(result, std::default_delete<byte[]>());
		return result_shared;
	}
	int getSerializedSize() override { return serializedSize_; };
	void initFromByteArray(byte * arr, int size) override {
		memcpy(&id, arr, sizeof(long));
		c->initFromByteArray(arr + sizeof(long), size - sizeof(long));
	};
};

/**
* Concrete implementation of decommitment message used by Pedersen commitment scheme.
*/
class CmtPedersenDecommitmentMessage : public CmtCDecommitmentMessage {
private:
	biginteger x; // committer's private input x in Zq
	int lenX, lenR, serializedSize;
	shared_ptr<BigIntegerRandomValue> r; // random value sampled during the sampleRandomValues stage;
public:
	CmtPedersenDecommitmentMessage() : CmtPedersenDecommitmentMessage(0, NULL) {};
	/**
	* Constructor that sets the given committed value and random value.
	* @param x the committed value
	* @param r the random value used for commit.
	*/
	CmtPedersenDecommitmentMessage(biginteger x, shared_ptr<BigIntegerRandomValue> r) {
		this->x = x;
		this->r = r;
		this->lenX = bytesCount(x);
		this->lenR = r? bytesCount(r->getR()) : 0;
		this->serializedSize = lenX + lenR + 2*sizeof(int);
	};
	/**
	* Returns the committed value.
	*/
	shared_ptr<byte> getSerializedX() override{
		std::shared_ptr<byte> res(new byte[lenX], std::default_delete<byte[]>());
		encodeBigInteger(x, res.get(), lenX);
		return res;
	}
	shared_ptr<RandomValue> getR() override { return r; };
	biginteger getRValue() { return r->getR(); }
	int getSerializedXSize() override { return lenX; };
	biginteger getX() { return x; };
	// network serialization implementation:
	void initFromByteArray(byte* arr, int size) override {
		memcpy(&lenX, arr, sizeof(int));
		x = decodeBigInteger(arr + sizeof(int), lenX);
		memcpy(&lenR, arr + sizeof(int) + lenX, sizeof(int));
		biginteger rVal = decodeBigInteger(arr + 2* sizeof(int) + lenX, lenR);
		r = make_shared<BigIntegerRandomValue>(rVal);
		serializedSize = lenX + lenR + 2*sizeof(int);
	}
	shared_ptr<byte> toByteArray() override {
		byte * result = new byte[serializedSize];
		copy(((byte*)&lenX), ((byte*)&lenX) + sizeof(int), result);
		encodeBigInteger(x, result+sizeof(int), lenX);
		copy(((byte*)&lenR), ((byte*)&lenR) + sizeof(int), result+lenX+sizeof(int));
		encodeBigInteger(r->getR(), result+lenX+2*sizeof(int), lenR);
		std::shared_ptr<byte> result_shared(result, std::default_delete<byte[]>());
		return result_shared;
	}
	int getSerializedSize() override { return serializedSize; };
};

/**
* This class holds the value sent by the receiver to the committer in the pre-process
* phase which is part of the initialization stage.
*/
class CmtPedersenPreprocessMessage : public NetworkSerialized{
private:
	shared_ptr<GroupElementSendableData> h;
public:
	/**
	* Constructor that sets the given groupElement.
	* @param h the value sent by the receiver to the committer in the pre-process phase
	*/
	CmtPedersenPreprocessMessage(shared_ptr<GroupElementSendableData> h) { this->h = h; };
	/**
	* This function return the h values which is calculated by the receiver in the pre-process
	* phase as follows:
	* SAMPLE a random value a in  Zq
	* COMPUTE h = g^a
	* SEND h to Committer.
	*/
	shared_ptr<GroupElementSendableData> getH() { return h; };
	
	// SerializedNetwork implementation:
	std::shared_ptr<byte> toByteArray() override { return h->toByteArray(); };
	int getSerializedSize() override { return h->getSerializedSize(); };
	void initFromByteArray(byte * arr, int size) override { h->initFromByteArray(arr, size); };
};

/**
* This class holds the values used by the Pedersen Committer during the commitment phase
* for a specific value that the committer commits about.
* This value is kept attached to a random value used to calculate the commitment,
* which is also kept together in this structure.
*/
class CmtPedersenCommitmentPhaseValues : public CmtCommitmentPhaseValues {
private:
	// The random value used in the computation of the commitment for the specific commitval.
	shared_ptr<BigIntegerRandomValue> r;
	// The value that the committer commits about. This value is not sent to the receiver in the 
	// commitment phase, it is sent in the decommitment phase.
	shared_ptr<CmtCommitValue> commitval;
	// The value that the committer sends to the receiver in order to
	// commit commitval in the commitment phase.
	shared_ptr<GroupElement> computedCommitment;

public:
	/**
	* Constructor that sets the given random value, committed value and the commitment object.
	* This constructor is package private. It should only be used by the classes in the package.
	* @param r random value used for commit.
	* @param commitVal the committed value
	* @param computedCommitment the commitment
	*/
	CmtPedersenCommitmentPhaseValues(shared_ptr<BigIntegerRandomValue> r, 
		shared_ptr<CmtCommitValue> commitVal, shared_ptr<GroupElement> computedCommitment) {
		this->r = r;
		this->commitval = commitVal;
		this->computedCommitment = computedCommitment;
	};

	/**
	* @return The random value used in the computation of the commitment.
	*/
	shared_ptr<RandomValue> getR() override { return r; };

	/**
	* Returns the value that the committer commits about. 
	* This value is not sent to the receiver in the commitment phase, 
	* it is sent in the decommitment phase.
	*/
	shared_ptr<CmtCommitValue> getX() override { return commitval; };

	/**
	* Returns the value that the committer sends to the receiver in order to commit commitval in 
	* the commitment phase.
	*/
	shared_ptr<void> getComputedCommitment() override { return computedCommitment; };
};

/*
* This abstract class performs all the core functionality of the receiver side of Pedersen commitment.
* Specific implementations can extend this class and add or override functions as necessary.
*/
class CmtPedersenReceiverCore : public CmtReceiver {
	/*
	* runs the following protocol:
	* "Commit phase
	*		SAMPLE a random value a <- Zq
	*		COMPUTE h = g^a
	*		SEND h to C
	*		WAIT for message c from C
	*		STORE values (h,c)
	*	Decommit phase
	*		WAIT for (r, x)  from C
	*		IF  c = g^r * h^x AND x <- Zq
	*	    	OUTPUT ACC and value x
	*		ELSE
	*	        OUTPUT REJ"
	*
	*/

protected:
	shared_ptr<ChannelServer> channel;
	std::shared_ptr<DlogGroup> dlog;
	std::mt19937 random;
	biginteger trapdoor; // sampled random value in Zq that will be the trpadoor.
	// h is a value calculated during the creation of this receiver and is sent to
	// the committer once in the beginning.
	std::shared_ptr<GroupElement> h;
	// The committer may commit many values one after the other without decommitting.
	// And only at a later time decommit some or all those values. In order to keep track
	// of the commitments and be able to relate them afterwards to the decommitments we keep 
	// them in the commitmentMap. The key is some unique id known to the application
	// running the committer. The exact same id has to be use later on to decommit the 
	// corresponding values, otherwise the receiver will reject the decommitment.
	map<long, std::shared_ptr<CmtPedersenCommitmentMessage>> commitmentMap;


	/**
	* This constructor only needs to get a connected channel (to the committer). 
	* All the other needed elements have default values.
	* If this constructor is used for the recevier then also the default constructor 
	* needs to be used by the committer.
	*/
	CmtPedersenReceiverCore(std::shared_ptr<ChannelServer> channel);

	/**
	* Constructor that receives a connected channel (to the committer),the DlogGroup agreed upon between them and a SecureRandom object.
	* The Committer needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	*/
	CmtPedersenReceiverCore(std::shared_ptr<ChannelServer> channel, 
		std::shared_ptr<DlogGroup> dlog, std::mt19937 random) {
		doConstruct(channel, dlog, random);
	}

private:
	biginteger qMinusOne;

	/**
	* Sets the given parameters and execute the preprocess phase of the scheme.
	* @param channel
	* @param dlog
	* @param random
	*/
	void doConstruct(shared_ptr<ChannelServer> channel, 
		shared_ptr<DlogGroup> dlog, std::mt19937 random);

	/**
	* Runs the preprocess stage of the protocol:
	* "SAMPLE a random value a <- Zq
	*	COMPUTE h = g^a
	*	SEND h to C".
	* The pre-process phase is performed once per instance.
	* If different values are required, a new instance of the receiver and the committer
	* need to be created.
	*/
	void preProcess();
public:
	/**
	* Wait for the committer to send the commitment. When the message is received and
	* after reconstructing the group element, save it in the commitmentMap using the id
	* also received in the message.<P>
	* Pseudo code:<P>
	* "WAIT for message c from C<P>
	*  STORE values (h,c)".
	*/
	shared_ptr<CmtRCommitPhaseOutput> receiveCommitment() override;

	/**
	* Wait for the decommitter to send the decommitment message.
	* If there had been a commitment for the requested id then proceed with validation,
	* otherwise reject.
	*/
	shared_ptr<CmtCommitValue> receiveDecommitment(long id) override;

	/**
	* Run the decommitment phase of the protocol:<P>
	* "IF  c = g^r * h^x AND x <- Zq<P>
	*	    OUTPUT ACC and value x<P>
	*	ELSE<P>
	*	    OUTPUT REJ".	<P>
	* @param id of the commitment
	* @param x
	* @param r
	* @return the committed value
	*/
	shared_ptr<CmtCommitValue> verifyDecommitment(shared_ptr<CmtCCommitmentMsg> commitmentMsg,
		shared_ptr<CmtCDecommitmentMessage> decommitmentMsg) override;

	void** getPreProcessedValues() override;
	int getPreProcessedValuesSize() override;

	shared_ptr<void> getCommitmentPhaseValues(long id) override;
};

/**
* This abstract class performs all the core functionality of the committer side of
* Pedersen commitment. <p>
* Specific implementations can extend this class and add or override functions as necessary.
*/
class CmtPedersenCommitterCore : public CmtCommitter {
	/*
	* runs the following protocol:
	* "Commit phase
	*		IF NOT VALID_PARAMS(G,q,g)
	*			REPORT ERROR and HALT
	*		WAIT for h from R
	*		IF NOT h in G
	*			REPORT ERROR and HALT
	* 		SAMPLE a random value r <- Zq
	* 		COMPUTE  c = g^r * h^x
	* 		SEND c
	*	Decommit phase
	*		SEND (r, x) to R
	*		OUTPUT nothing."
	*
	*/
protected:
	shared_ptr<ChannelServer> channel;
	shared_ptr<DlogGroup> dlog;
	std::mt19937 random;
	// the key to the map is an ID and the value is a structure that has the Committer's
	// private input x in Zq,the random value used to commit x and the actual commitment.
	// Each committed value is sent together with an ID so that the receiver can keep it in
	// some data structure. This is necessary in the cases that the same instances of committer
	// and receiver can be used for performing various commitments utilizing the values calculated
	// during the pre-process stage for the sake of efficiency.
	map<long, shared_ptr<CmtPedersenCommitmentPhaseValues>> commitmentMap;
	// the content of the message obtained from the receiver during the pre-process phase which occurs upon construction.
	shared_ptr<GroupElement> h;

	/**
	* Constructor that receives a connected channel (to the receiver) and chooses 
	* default dlog and random.
	* The receiver needs to be instantiated with the default constructor too.
	*/
	CmtPedersenCommitterCore(shared_ptr<ChannelServer> channel) {
		auto r = get_seeded_random();
		auto dg = make_shared<OpenSSLDlogZpSafePrime>(256);
		doConstruct(channel, dg, r);
	}

	/**
	* Constructor that receives a connected channel (to the receiver),
	* the DlogGroup agreed upon between them and a SecureRandom object.
	* The Receiver needs to be instantiated with the same DlogGroup, 
	* otherwise nothing will work properly.
	*/
	CmtPedersenCommitterCore(shared_ptr<ChannelServer> channel, 
		shared_ptr<DlogGroup> dlog, std::mt19937 random) {
		doConstruct(channel, dlog, random);
	};
private:
	biginteger qMinusOne;
	/**
	* Sets the given parameters and execute the preprocess phase of the scheme.
	* @param channel
	* @param dlog
	* @param random
	*/
	void doConstruct(shared_ptr<ChannelServer> channel, 
		shared_ptr<DlogGroup> dlog, std::mt19937 randomm);
	/**
	* Runs the preprocess phase of the commitment scheme:
	* "WAIT for h from R
	* IF NOT h in G
	*	REPORT ERROR and HALT"
	*/
	void preProcess();
	/**
	* Receives message from the receiver.
	* @return the received message
	*/
	shared_ptr<CmtPedersenPreprocessMessage> waitForMessageFromReceiver();

public:
	/**
	* Runs the following lines of the commitment scheme: <P>
	* "SAMPLE a random value r <- Zq<P>
	* 	COMPUTE  c = g^r * h^x". <p>
	*/
	shared_ptr<CmtCCommitmentMsg> generateCommitmentMsg(shared_ptr<CmtCommitValue> input, long id) override;
	
	/**
	* Runs the commit phase of the commitment scheme. <P>
	* "SAMPLE a random value r <- Zq<P>
	* 	COMPUTE  c = g^r * h^x<P>
	* 	SEND c".
	*/
	void commit(shared_ptr<CmtCommitValue> in, long id) override;
	shared_ptr<CmtCDecommitmentMessage> generateDecommitmentMsg(long id) override;
	/**
	* Runs the decommit phase of the commitment scheme.<P>
	* "SEND (r, x) to R<P>
	*	OUTPUT nothing."
	*/
	void decommit(long id) override;
	
	void** getPreProcessValues() override;
	int getPreProcessValuesSize() override;
	shared_ptr<CmtCommitmentPhaseValues> getCommitmentPhaseValues(long id) override{
		return commitmentMap[id]; 
	};
};

/**
* Concrete implementation of committer that executes the Pedersen commitment scheme 
* in the committer's point of view.<p>
* For more information see Protocol 6.5.3, page 164 of 
* <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 3.1 of pseudo codes 
* document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class CmtPedersenCommitter : public CmtPedersenCommitterCore, public PerfectlyHidingCmt, 
	public CmtOnBigInteger {
public:
	/**
	* Constructor that receives a connected channel (to the receiver) 
	* and chooses default dlog and random.
	* The receiver needs to be instantiated with the default constructor too.
	* @param channel
	*/
	CmtPedersenCommitter(shared_ptr<ChannelServer> channel) : CmtPedersenCommitterCore(channel) {};

	/**
	* Constructor that receives a connected channel (to the receiver), 
	* the DlogGroup agreed upon between them and a SecureRandom object.
	* The Receiver needs to be instantiated with the same DlogGroup, 
	* otherwise nothing will work properly.
	* @param channel
	* @param dlog
	* @param random
	*/
	CmtPedersenCommitter(shared_ptr<ChannelServer> channel, 
		shared_ptr<DlogGroup> dlog, std::mt19937 random) :
		CmtPedersenCommitterCore(channel, dlog, random) {};
	
	shared_ptr<CmtCommitValue> generateCommitValue(shared_ptr<byte> x, int len) override {
		biginteger bi = decodeBigInteger(x.get(), len);
		return make_shared<CmtBigIntegerCommitValue>(bi);
	};
	pair<shared_ptr<byte>,int> generateBytesFromCommitValue(shared_ptr<CmtCommitValue> value) override;
	shared_ptr<CmtCommitValue> sampleRandomCommitValue() override {
		auto val = getRandomInRange(0, dlog->getOrder() - 1, random);
		return make_shared<CmtBigIntegerCommitValue>(val);
	}
};

/**
* Concrete implementation of receiver that executes the Pedersen commitment
* scheme in the receiver's point of view.<p>
* For more information see Protocol 6.5.3, page 164 of
* <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 3.1 of pseudo codes 
* document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf} .<p>
*/
class CmtPedersenReceiver : public CmtPedersenReceiverCore, 
	public PerfectlyHidingCmt, public CmtOnBigInteger {
public:
	/**
	* Constructor that receives a connected channel (to the receiver) and chooses default dlog and random.
	* The committer needs to be instantiated with the default constructor too.
	* @param channel
	*/
	CmtPedersenReceiver(shared_ptr<ChannelServer> channel) : CmtPedersenReceiverCore(channel) {};

	/**
	* Constructor that receives a connected channel (to the receiver), the DlogGroup agreed upon between them and a SecureRandom object.
	* The committer needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	* @param channel
	* @param dlog
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	* @throws InvalidDlogGroupException if the given dlog is not valid.
	* @throws IOException if there was a problem in the communication
	*/
	CmtPedersenReceiver(shared_ptr<ChannelServer> channel, 
		shared_ptr<DlogGroup> dlog, std::mt19937 random) :
		CmtPedersenReceiverCore(channel, dlog, random) {};

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	pair<shared_ptr<byte>,int> generateBytesFromCommitValue(shared_ptr<CmtCommitValue> value) override;
};
