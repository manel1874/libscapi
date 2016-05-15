#include "../../include/interactive_mid_protocols/CommitmentSchemePedersen.hpp"

/*********************************/
/*   CmtPedersenReceiverCore     */
/*********************************/
CmtPedersenReceiverCore::CmtPedersenReceiverCore(shared_ptr<CommParty> channel) {
	auto r = get_seeded_random();
	auto dg = make_shared<OpenSSLDlogZpSafePrime>(256, r);
	doConstruct(channel, dg, r);
};

void CmtPedersenReceiverCore::doConstruct(shared_ptr<CommParty> channel,
	shared_ptr<DlogGroup> dlog, std::mt19937 random) {
	// the underlying dlog group must be DDH secure.
	auto ddh = std::dynamic_pointer_cast<DDH>(dlog);
	if (!ddh)
		throw SecurityLevelException("DlogGroup should have DDH security level");

	// validate the params of the group.
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("Group is not valid");

	this->channel = channel;
	this->dlog = dlog;
	this->random = random;
	qMinusOne = dlog->getOrder()-1;
	// the pre-process phase is actually performed at construction
	preProcess();
}

void CmtPedersenReceiverCore::preProcess() {
	trapdoor = getRandomInRange(0, qMinusOne, random);
	h = dlog->exponentiate(dlog->getGenerator().get(), trapdoor);
	auto sendableData = h->generateSendableData();	
	auto raw_msg = sendableData->toString();
	channel->writeWithSize(raw_msg);
}

shared_ptr<CmtRCommitPhaseOutput> CmtPedersenReceiverCore::receiveCommitment() {
	// create an empty CmtPedersenCommitmentMessage 
	auto msg = make_shared<CmtPedersenCommitmentMessage>(dlog->getGenerator()->generateSendableData());
	// read encoded CmtPedersenCommitmentMessage from channel
	vector<byte> raw_msg; // by the end of the scope - no need to hold it anymore - already decoded and copied
	channel->readWithSizeIntoVector(raw_msg);
	// init the empy CmtPedersenCommitmentMessage using the encdoed data
	msg->initFromByteVector(raw_msg);
	auto cm = msg->getCommitment();
	commitmentMap[msg->getId()] = msg;
	return make_shared<CmtRBasicCommitPhaseOutput>(msg->getId());
}

shared_ptr<CmtCommitValue> CmtPedersenReceiverCore::receiveDecommitment(long id) {
	vector<byte> raw_msg;
	channel->readWithSizeIntoVector(raw_msg);
	shared_ptr<CmtPedersenDecommitmentMessage> msg = make_shared<CmtPedersenDecommitmentMessage>();
	msg->initFromByteVector(raw_msg);
	auto receivedCommitment = commitmentMap[id];
	auto cmtCommitMsg = std::static_pointer_cast<CmtCCommitmentMsg>(receivedCommitment);
	return verifyDecommitment(cmtCommitMsg, msg);
}

shared_ptr<CmtCommitValue> CmtPedersenReceiverCore::verifyDecommitment(
	shared_ptr<CmtCCommitmentMsg> commitmentMsg,
	shared_ptr<CmtCDecommitmentMessage> decommitmentMsg) {
	auto decommitmentMsgPedersen = dynamic_pointer_cast<CmtPedersenDecommitmentMessage>(decommitmentMsg);
	auto commitmentMsgPedersen = dynamic_pointer_cast<CmtPedersenCommitmentMessage>(commitmentMsg);
	biginteger x = decommitmentMsgPedersen->getX();
	biginteger r = decommitmentMsgPedersen->getRValue();

	// if x is not in Zq return null
	if (x<0 || x>dlog->getOrder()) 
		return NULL;
	// calculate c = g^r * h^x
	auto gTor = dlog->exponentiate(dlog->getGenerator().get(), r);
	auto hTox = dlog->exponentiate(h.get(), x);

	auto cmt = commitmentMsgPedersen->getCommitment();
	auto ge = static_pointer_cast<GroupElementSendableData>(cmt);
	auto commitmentElement = dlog->reconstructElement(true, ge.get());
	if (*commitmentElement == *(dlog->multiplyGroupElements(gTor.get(), hTox.get())))
		return make_shared<CmtBigIntegerCommitValue>(x);
	// in the pseudocode it says to return X and ACCEPT if valid commitment else, REJECT.
	// for now we return null as a mode of reject. If the returned value of this function is not
	// null then it means ACCEPT
	return NULL;
}

void** CmtPedersenReceiverCore::getPreProcessedValues() {
	return NULL;
}
int CmtPedersenReceiverCore::getPreProcessedValuesSize() {
	return -1;
}

shared_ptr<void> CmtPedersenReceiverCore::getCommitmentPhaseValues(long id) {
	auto voidPtr = commitmentMap[id]->getCommitment();
	auto ge = static_pointer_cast<GroupElementSendableData>(voidPtr);
	return dlog->reconstructElement(true, ge.get());
}

/*********************************/
/*   CmtPedersenCommitterCore    */
/*********************************/
void CmtPedersenCommitterCore::doConstruct(shared_ptr<CommParty> channel,
	shared_ptr<DlogGroup> dlog, std::mt19937 randomm) {
	
	// the underlying dlog group must be DDH secure.
	auto ddh = std::dynamic_pointer_cast<DDH>(dlog);
	if (!ddh)
		throw SecurityLevelException("DlogGroup should have DDH security level");
	// validate the params of the group.
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("");

	this->channel = channel;
	this->dlog = dlog;
	this->random = random;
	qMinusOne = dlog->getOrder()-1;
	// the pre-process phase is actually performed at construction
	preProcess();
}

void CmtPedersenCommitterCore::preProcess() {
	auto msg = waitForMessageFromReceiver();
	h = dlog->reconstructElement(true, msg->getH().get());
	if (!dlog->isMember(h.get()))
		throw CheatAttemptException("h element is not a member of the current DlogGroup");
}

shared_ptr<CmtPedersenPreprocessMessage> CmtPedersenCommitterCore::waitForMessageFromReceiver() {
	vector<byte> rawMsg;
	channel->readWithSizeIntoVector(rawMsg);
	auto dummySendableData = dlog->getGenerator()->generateSendableData();
	auto msg = make_shared<CmtPedersenPreprocessMessage>(dummySendableData);
	msg->initFromByteVector(rawMsg);
	return msg;
}

shared_ptr<CmtCCommitmentMsg> CmtPedersenCommitterCore::generateCommitmentMsg(
	shared_ptr<CmtCommitValue> input, long id) {
	auto biCmt = std::dynamic_pointer_cast<CmtBigIntegerCommitValue>(input);
	if (!biCmt)
		throw invalid_argument("The input must be of type CmtBigIntegerCommitValue");

	biginteger x = *((biginteger *)biCmt->getX().get());
	// check that the input is in Zq.
	if(x < 0 || x > dlog->getOrder())
		throw invalid_argument("The input must be in Zq");

	// sample a random value r <- Zq
	biginteger r = getRandomInRange(0, qMinusOne, random);

	// compute  c = g^r * h^x
	auto gToR = dlog->exponentiate(dlog->getGenerator().get(), r);
	auto hToX = dlog->exponentiate(h.get(), x);
	auto c = dlog->multiplyGroupElements(gToR.get(), hToX.get());

	// keep the committed value in the map together with its ID.
	auto sharedR = make_shared<BigIntegerRandomValue>(r);
	auto cmtBIValue = make_shared<CmtBigIntegerCommitValue>(x);
	commitmentMap[id] = make_shared<CmtPedersenCommitmentPhaseValues>(sharedR, cmtBIValue, c);

	// send c
	auto res = make_shared<CmtPedersenCommitmentMessage>(c->generateSendableData(), id);
	return res;
}

void CmtPedersenCommitterCore::commit(shared_ptr<CmtCommitValue> in, long id) {
	auto msg = generateCommitmentMsg(in, id);
	auto msgStr = msg->toString();
	channel->writeWithSize(msgStr);
}

shared_ptr<CmtCDecommitmentMessage> CmtPedersenCommitterCore::generateDecommitmentMsg(long id) {
	auto values = commitmentMap[id];
	auto cmtValue = values->getX();
	auto biCmt = std::dynamic_pointer_cast<CmtBigIntegerCommitValue>(cmtValue);
	biginteger x = *((biginteger *)biCmt->getX().get());
	auto randomValuePtr = values->getR();
	auto biRVPtr = std::dynamic_pointer_cast<BigIntegerRandomValue>(randomValuePtr);
	return make_shared<CmtPedersenDecommitmentMessage>(x, biRVPtr);
}

void CmtPedersenCommitterCore::decommit(long id) {
	// fetch the commitment according to the requested ID
	auto msg = generateDecommitmentMsg(id);
	auto bMsg = msg->toString();
	channel->writeWithSize(bMsg);
}

void** CmtPedersenCommitterCore::getPreProcessValues() {
	return NULL;
	//GroupElement** values = new GroupElement*[1];
	//values[0] = h;
	//return values;
}

int CmtPedersenCommitterCore::getPreProcessValuesSize() {
	return NULL;
}

/**********/
/* Helper */
/**********/
pair<shared_ptr<byte>, int> fromCmtToByteArray(shared_ptr<CmtCommitValue> value) {
	biginteger x = *((biginteger *)value->getX().get());
	int size = bytesCount(x);
	auto byteRes = std::shared_ptr<byte>(new byte[size], std::default_delete<byte[]>());
	encodeBigInteger(x, byteRes.get(), size);
	return make_pair(byteRes, size);
}

/*********************************/
/*   CmtPedersenCommitter        */
/*********************************/
pair<shared_ptr<byte>, int> CmtPedersenCommitter::generateBytesFromCommitValue(
	shared_ptr<CmtCommitValue> value) {
	return fromCmtToByteArray(value);
}

/*********************************/
/*   CmtPedersenReceiver         */
/*********************************/
pair<shared_ptr<byte>, int> CmtPedersenReceiver::generateBytesFromCommitValue(
	shared_ptr<CmtCommitValue> value) {
	return fromCmtToByteArray(value);
}

