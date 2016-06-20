#pragma once
#include "CommitmentScheme.hpp"
#include "CommitmentSchemePedersen.hpp"
#include "../../include/primitives/HashOpenSSL.hpp"

/**
* Concrete implementation of decommitment message used by SimpleHash commitment scheme.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtPedersenHashDecommitmentMessage : public CmtCDecommitmentMessage {
private:
	shared_ptr<BigIntegerRandomValue> r; //Random value sampled during the commitment stage;
	shared_ptr<vector<byte>> x; //Committer's private input x 

public:
	CmtPedersenHashDecommitmentMessage() {}

	/**
	* Constructor that sets the given committed value and random value.
	* @param x the committed value
	* @param r the random value used for commit.
	*/
	CmtPedersenHashDecommitmentMessage(shared_ptr<BigIntegerRandomValue> r, shared_ptr<vector<byte>> x) {
		this->r = r;
		this->x = x;
	}

	shared_ptr<void> getX() override { return x; }
	vector<byte> getXValue() { return *x; }

	shared_ptr<RandomValue> getR() override { return r; }

	// network serialization implementation:
	void initFromString(const string & s) override;
	string toString() override;

};

/**
* Concrete implementation of committer that executes the Pedersen hash commitment
* scheme in the committer's point of view.<p>
*
* This is a perfectly-hiding commitment that can be used to commit to a value of any length. <p>
*
* For more information see Protocol 6.5.3, page 164 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
*
* The pseudo code of this protocol can be found in Protocol 3.2 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtPedersenHashCommitter : public CmtPedersenCommitterCore, public PerfectlyHidingCmt, public CmtOnByteArray {
	/*
	* runs the following protocol:
	* "Run COMMIT_PEDERSEN to commit to value H(x).
	* For decommitment, send x and the receiver verifies that the commitment was to H(x). "
	*/

private:
	shared_ptr<CryptographicHash> hash;
	
public:
	/**
	* This constructor uses a default Dlog Group and default Cryptographic Hash. They keep the condition that
	* the size in bytes of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	* An established channel has to be provided by the user of the class.
	* @param channel
	* @throws CheatAttemptException
	* @throws IOException
	* @throws ClassNotFoundException
	*/
	CmtPedersenHashCommitter(shared_ptr<CommParty> channel) : CmtPedersenCommitterCore(channel) {
		hash = make_shared<OpenSSLSHA256>(); 	//This default hash suits the default DlogGroup of the underlying Committer.
		if (hash->getHashedMsgSize() > bytesCount(dlog->getOrder())) {
			throw invalid_argument("The size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup.");
		}
	}

	/**
	* This constructor receives as arguments an instance of a Dlog Group and an instance
	* of a Cryptographic Hash such that they keep the condition that the size in bytes
	* of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	* Otherwise, it throws IllegalArgumentException.
	* An established channel has to be provided by the user of the class.
	* @param channel an established channel obtained via the Communication Layer
	* @param dlog
	* @param hash
	* @param random
	* @throws IllegalArgumentException if the size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup
	* @throws SecurityLevelException if the Dlog Group is not DDH
	* @throws InvalidDlogGroupException if the parameters of the group do not conform the type the group is supposed to be
	* @throws CheatAttemptException if the commetter suspects that the receiver is trying to cheat.
	* @throws IOException if there was a problem during the communication
	* @throws ClassNotFoundException if there was a problem with the serialization mechanism.
	*/
	CmtPedersenHashCommitter(shared_ptr<CommParty> channel, shared_ptr<DlogGroup> dlog, shared_ptr<CryptographicHash> hash);

	/*
	* Runs COMMIT_ElGamal to commit to value H(x).
	* @return the created commitment.
	*/
	shared_ptr<CmtCCommitmentMsg> generateCommitmentMsg(shared_ptr<CmtCommitValue> input, long id) override; 

	shared_ptr<CmtCDecommitmentMessage> generateDecommitmentMsg(long id) override;

	/**
	* This function samples random commit value and returns it.
	* @return the sampled commit value
	*/
	shared_ptr<CmtCommitValue> sampleRandomCommitValue() override;

	shared_ptr<CmtCommitValue> generateCommitValue(vector<byte> x) override {
		return make_shared<CmtByteArrayCommitValue>(make_shared<vector<byte>>(x));
	}

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	vector<byte> generateBytesFromCommitValue(CmtCommitValue* value) override; 

};

/**
* Concrete implementation of receiver that executes the Pedersen hash commitment
* scheme in the receiver's point of view.<p>
*
* This is a perfectly-hiding commitment that can be used to commit to a value of any length. <p>
*
* For more information see Protocol 6.5.3, page 164 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 3.2 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtPedersenHashReceiver : public CmtPedersenReceiverCore, public PerfectlyHidingCmt, public CmtOnByteArray {

	/*
	* runs the following protocol:
	* "Run COMMIT_PEDERSEN to commit to value H(x).
	* For decommitment, send x and the receiver verifies that the commitment was to H(x). "
	*/

private:
	shared_ptr<CryptographicHash> hash;

public:
	/**
	* This constructor uses a default Dlog Group and default Cryptographic Hash. They keep the condition that
	* the size in bytes of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	* An established channel has to be provided by the user of the class.
	* @param channel
	* @throws IOException if there was a problem in the communication.
	*/
	CmtPedersenHashReceiver(shared_ptr<CommParty> channel) : CmtPedersenReceiverCore(channel) {
		hash = make_shared<OpenSSLSHA256>(); 		//This default hash suits the default DlogGroup of the underlying Committer.
	}

	/**
	* This constructor receives as arguments an instance of a Dlog Group and an instance
	* of a Cryptographic Hash such that they keep the condition that the size in bytes
	* of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	* Otherwise, it throws IllegalArgumentException.
	* An established channel has to be provided by the user of the class.
	* @param channel an established channel obtained via the Communication Layer
	* @param dlog
	* @param hash
	* @param random
	* @throws IllegalArgumentException if the size in bytes of the resulting hash is bigger than the size in bytes of the order of the DlogGroup
	* @throws SecurityLevelException if the Dlog Group is not DDH
	* @throws InvalidDlogGroupException if the parameters of the group do not conform the type the group is supposed to be
	* @throws IOException if there was a problem during the communication
	*/
	CmtPedersenHashReceiver(shared_ptr<CommParty> channel, shared_ptr<DlogGroup> dlog, shared_ptr<CryptographicHash> hash);

	shared_ptr<CmtCommitValue> receiveDecommitment(long id) override;

	/**
	* Verifies that the commitment was to H(x).
	*/
	shared_ptr<CmtCommitValue> verifyDecommitment(CmtCCommitmentMsg* commitmentMsg,	CmtCDecommitmentMessage* decommitmentMsg) override; 

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	vector<byte> generateBytesFromCommitValue(CmtCommitValue* value) override; 

};