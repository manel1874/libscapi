#include "examples_main.hpp"

int exampleUsage()
{
	auto usage = R"(
To run an example:
./libscapi_examples <example_name> [args...]

example_name can one of the followin: 
	* dlog
	* sha1
	* comm  <party_number (1|2)> <config_file_path>
	* yao   <party_number (1|2)> <config_file_path>
	* sigma <party_number (1|2)> <config_file_path>
	* maliciousOT <party_number (1|2)>
				)";
	cerr << usage << endl;
	return 1;
}

int main(int argc, char* argv[]) {
	if (argc < 2)
		return exampleUsage();
	string exampleName(argv[1]);
	if (exampleName == "dlog")
		return mainDlog();
	if (exampleName == "sha1")
		return mainSha1();
	if (exampleName == "maliciousOT")
		return mainOT(argv[2]);
	if (argc != 4)
		return exampleUsage();

	if (exampleName == "comm") 
		return mainComm(argv[2], argv[3]);
	if (exampleName == "yao")
		return mainYao(argv[2], argv[3]);
	if (exampleName == "sigma")
		return mainSigma(argv[2], argv[3]);
	
	return exampleUsage();
}



