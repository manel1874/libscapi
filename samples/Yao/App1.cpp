#include "YaoExample.hpp"

struct YaoConfig {
	int number_of_iterations;
	bool print_output;
	string circuit_type;
	string circuit_file;
	string input_file_1;
	string input_file_2;
	IpAdress sender_ip;
	IpAdress receiver_ip;
	YaoConfig(int n_iterations, bool print, string c_file, string input_file_1,
		string input_file_2, string sender_ip_str, string rec_ip_str, string circuit_type) {
		number_of_iterations = n_iterations;
		print_output = print;
		circuit_file = c_file;
		this->input_file_1 = input_file_1;
		this->input_file_2 = input_file_2;
		sender_ip = IpAdress::from_string(sender_ip_str);
		receiver_ip = IpAdress::from_string(rec_ip_str);
		this->circuit_type = circuit_type;
	};
};

void connect(ChannelServer * channel_server) {
	cout << "PartyOne: Connecting to Receiver..." << endl;
	int sleep_time = 50;
	this_thread::sleep_for(chrono::milliseconds(sleep_time));
	channel_server->connect();
	while(!channel_server->is_connected())
	{
		cout << "Failed to connect. sleeping for " << sleep_time << " milliseconds" << endl;
		this_thread::sleep_for(chrono::milliseconds(sleep_time));
	}
	cout << "Sender Connected!" << endl;
}

vector<byte> * readInputAsVector(string input_file) {
	cout << "reading from file " << input_file << endl;;
	auto sc = scannerpp::Scanner(new scannerpp::File(input_file));
	int inputsNumber = sc.nextInt();
	auto inputVector = new vector<byte>(inputsNumber);
	for (int i = 0; i < inputsNumber; i++)
		(*inputVector)[i] = (byte)sc.nextInt();
	return inputVector;
}

FastGarbledBooleanCircuit * create_circuit(YaoConfig yao_config) {
	//return new ScNativeGarbledBooleanCircuitNoFixedKey(yao_config.circuit_file, true);
	return new ScNativeGarbledBooleanCircuit(yao_config.circuit_file, 
		ScNativeGarbledBooleanCircuit::CircuitType::FREE_XOR_HALF_GATES, false);
	//if (yao_config.circuit_type == "FixedKey")
	//	return new ScNativeGarbledBooleanCircuit(yao_config.circuit_file, 
	//		ScNativeGarbledBooleanCircuit::CircuitType::FREE_XOR_HALF_GATES, false);
	//else if (yao_config.circuit_type == "NoFixedKey")
		//return new ScNativeGarbledBooleanCircuitNoFixedKey(yao_config.circuit_file, true);
	//else
	//	throw invalid_argument("circuit_type should either be FixedKey or NoFixedKey");
}

void execute_party_one(YaoConfig yao_config) {
	auto start = scapi_now();
	boost::asio::io_service io_service;
	SocketPartyData me(yao_config.sender_ip, 1213);
	SocketPartyData other(yao_config.receiver_ip, 1212);
	ChannelServer * channel_server = new ChannelServer(io_service, me, other);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	print_elapsed_ms(start, "PartyOne: Init");
	
	// create the garbled circuit
	start = chrono::system_clock::now();
	FastGarbledBooleanCircuit * circuit = create_circuit(yao_config);
	print_elapsed_ms(start, "PartyOne: Creating FastGarbledBooleanCircuit");

	// create the semi honest OT extension sender
	SocketPartyData senderParty(yao_config.sender_ip, 7766);
	OTBatchSender * otSender = new OTSemiHonestExtensionSender(senderParty, 163, 1);

	// connect to party two
	connect(channel_server);
	
	// get the inputs of P1 
	vector<byte>* ungarbledInput = readInputAsVector(yao_config.input_file_1);

	PartyOne * p1;
	auto all = scapi_now();
	// create Party one with the previous created objects.
	p1 = new PartyOne(channel_server, otSender, circuit);
	for (int i = 0; i < yao_config.number_of_iterations ; i++) {
		// run Party one
		p1->run(&(ungarbledInput->at(0)));
	}
	auto end = std::chrono::system_clock::now();
	int elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
	cout << "********************* PartyOne ********\nRunning " << yao_config.number_of_iterations <<
		" iterations took: " << elapsed_ms << " milliseconds" << endl 
		<< "Average time per iteration: " << elapsed_ms / (float)yao_config.number_of_iterations << " milliseconds" << endl;
	
	// exit cleanly
	delete p1, channel_server, circuit, otSender, ungarbledInput;
	io_service.stop();
	t.join();
}

void execute_party_two(YaoConfig yao_config) {
	// init
	auto start = scapi_now();
	boost::asio::io_service io_service;
	SocketPartyData me(yao_config.receiver_ip, 1212);
	SocketPartyData other(yao_config.sender_ip, 1213);
	SocketPartyData receiverParty(yao_config.receiver_ip, 7766);
	ChannelServer * server = new ChannelServer(io_service, me, other);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	print_elapsed_ms(start, "PartyTwo: Init");

	// create the garbled circuit
	start = scapi_now();
	FastGarbledBooleanCircuit * circuit = create_circuit(yao_config);
	print_elapsed_ms(start, "PartyTwo: creating FastGarbledBooleanCircuit");

	// create the OT receiver.
	start = scapi_now();
	OTBatchReceiver * otReceiver = new OTSemiHonestExtensionReceiver(receiverParty, 163, 1);
	print_elapsed_ms(start, "PartyTwo: creating OTSemiHonestExtensionReceiver");

	// create Party two with the previous created objec ts			
	vector<byte> * ungarbledInput = readInputAsVector(yao_config.input_file_2);

	PartyTwo * p2;
	auto all = scapi_now();
	p2 = new PartyTwo(server, otReceiver, circuit);
	for (int i = 0; i < yao_config.number_of_iterations ; i++) {
		// init the P1 yao protocol and run party two of Yao protocol.
		p2->run(&(ungarbledInput->at(0)), ungarbledInput->size(), yao_config.print_output);
	}
	auto end = std::chrono::system_clock::now();
	int elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - all).count();
	cout << "********************* PartyTwo ********\nRunning " << yao_config.number_of_iterations <<
		" iterations took: " << elapsed_ms << " milliseconds" << endl;
	cout << "Average time per iteration: " << elapsed_ms / (float)yao_config.number_of_iterations 
		<< " milliseconds" << endl;
	delete p2, server, circuit, otReceiver, ungarbledInput;
	io_service.stop();
	t.join();
}

YaoConfig read_yao_config(string config_file) {

	ConfigFile cf(config_file);
	int number_of_iterations = stoi(cf.Value("", "number_of_iterations"));
	string str_print_output = cf.Value("", "print_output");
	bool print_output;
	istringstream(str_print_output) >> std::boolalpha >> print_output;
	cout << "\nprintoutput:" << print_output << endl;
	string input_section = cf.Value("", "input_section");
	string circuit_file = cf.Value(input_section, "circuit_file");
	string input_file_1 = cf.Value(input_section, "input_file_party_1");
	string input_file_2 = cf.Value(input_section, "input_file_party_2");
	string sender_ip_str = cf.Value("", "sender_ip");
	string receiver_ip_str = cf.Value("", "receiver_ip");
	auto sender_ip = IpAdress::from_string(sender_ip_str);
	auto receiver_ip = IpAdress::from_string(receiver_ip_str);
	string circuit_type = cf.Value("", "circuit_type");
	return YaoConfig(number_of_iterations, print_output, circuit_file, input_file_1,
		input_file_2, sender_ip_str, receiver_ip_str, circuit_type);
}

void Usage(char * argv0) {
	std::cerr << "Usage: " << argv0 << " party_number config_path" << std::endl;
}

int main99898(int argc, char* argv[]) {
	Logger::configure_logging();
	if (argc != 3) {
		Usage(argv[0]);
		return 1;
	}
	YaoConfig yao_config = read_yao_config(argv[2]); 	//R"(C:\code\scapi\src\cpp\CodeExamples\Yao\YaoConfig.txt)"
	string partyNum(argv[1]);
	if (partyNum == "1")
		execute_party_one(yao_config);
	else if (partyNum == "2") 
		execute_party_two(yao_config);
	else {
		Usage(argv[0]);
		return 1;
	}
	return 0;
}

