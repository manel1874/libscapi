
#include "netxpto_linux_20190816.h"
#include "ip_tunnel_linux_20190816.h"
#include "sink_20190816.h"
#include "binary_source_20190816.h"

#include "Alice_QOKD_20190816.h"
#include "Bob_QOKD_20190816.h"


class AliceQOKDInputParameters : public SystemInputParameters {
public:

    // # INPUT PARAMETERS ###################################################

    std::string inputParametersFileName{ "input_parameters_tx.txt" };
    std::string remoteMachineIpAddress{ "127.0.0.1" };
    std::string localMachineIpAddress{ "127.0.0.1" };
    int numberOfSamplesToProcess{ 512 };

    // # Initializes default input parameters ###############################

    AliceQOKDInputParameters() : SystemInputParameters()
    {
        initializeInputParameterMap();
    }

    // # Initializes input parameters according to the program arguments ####
    // Usage: .\qokd_emulator_tx.exe <input_parameters_tx.txt> <output_directory>
    AliceQOKDInputParameters(int argc, char* argv[]) : SystemInputParameters(argc, argv)
    {
        if (argc == 1) setInputParametersFileName(inputParametersFileName);
        else setInputParametersFileName(argv[1]);
        initializeInputParameterMap();
        readSystemInputParameters();
    }

    // # Add parameter to the parameter map #################################

    void initializeInputParameterMap()
    {
        addInputParameter("remoteMachineIpAddress", &remoteMachineIpAddress);
        addInputParameter("localMachineIpAddress", &localMachineIpAddress);
        addInputParameter("numberOfSamplesToProcess", &numberOfSamplesToProcess);
    }
};

class BobQOKDInputParameters : public SystemInputParameters {
public:

    // # INPUT PARAMETERS ###################################################

    std::string inputParametersFileName{ "input_parameters_rx.txt" };
    std::string remoteMachineIpAddress{ "127.0.0.1" };
    std::string localMachineIpAddress{ "127.0.0.1" };
    int numberOfSamplesToProcess{ 512 };

    // # Initializes default input parameters ###############################

    BobQOKDInputParameters() : SystemInputParameters()
    {
        initializeInputParameterMap();
    }

    // # Initializes input parameters according to the program arguments ####
    // .\qokd_emulator_rx.exe <input_parameters_rx.txt> <output_directory>

    BobQOKDInputParameters(int argc, char* argv[]) : SystemInputParameters(argc, argv)
    {
        if (argc == 1) setInputParametersFileName(inputParametersFileName);
        else setInputParametersFileName(argv[1]);
        initializeInputParameterMap();
        readSystemInputParameters();
    }

    // # Add parameter to the parameter map #################################

    void initializeInputParameterMap()
    {
        addInputParameter("remoteMachineIpAddress", &remoteMachineIpAddress);
        addInputParameter("localMachineIpAddress", &localMachineIpAddress);
        addInputParameter("numberOfSamplesToProcess", &numberOfSamplesToProcess);
    }
};

namespace tx
{
    int main(int argc, char* argv[])
    {
        // # Variables Inicialization ######################################

        AliceQOKDInputParameters param = AliceQOKDInputParameters(argc, argv);

        // # Signals Declaration and Initialisation #########################

        Binary AliceRandomBits{ "AliceRandomBits.sgn" };
        Binary RandomBits{ "RandomBits.sgn" };
        Binary AliceObliviousKeys{ "AliceObliviousKeys.sgn" };
        Binary AliceControlSignal{ "AliceControlSignal.sgn" };

        // # Blocks Declaration and Initialisation ###########################

        BinarySource BinarySource_{ {}, {&AliceRandomBits} };
        BinarySource_.setMode(BinarySourceMode::Random);
        BinarySource_.setLogValue(false);

        AliceQOKD AliceQOKD_{ {&AliceRandomBits}, {&RandomBits, &AliceObliviousKeys, &AliceControlSignal } };
        AliceQOKD_.setLogValue(false);

        IPTunnel IPTunnel_{ {&RandomBits},{} };
        IPTunnel_.setRemoteMachineIpAddress(param.remoteMachineIpAddress);
        IPTunnel_.setLocalMachineIpAddress(param.localMachineIpAddress);
        IPTunnel_.setLogValue(false);

        Sink Sink_AliceObliviousKeys_{ {&AliceObliviousKeys}, {} };
        Sink_AliceObliviousKeys_.setNumberOfSamplesToProcess(param.numberOfSamplesToProcess);
        Sink_AliceObliviousKeys_.setLogValue(false);

        Sink Sink_AliceControlSignal_{ {&AliceControlSignal}, {} };
        Sink_AliceControlSignal_.setNumberOfSamplesToProcess(param.numberOfSamplesToProcess);
        Sink_AliceControlSignal_.setLogValue(false);

        // # System Declaration and Initialisation ############################

        System MainSystem{
            {
                &BinarySource_,
                &AliceQOKD_,
                &Sink_AliceObliviousKeys_,
                &Sink_AliceControlSignal_,
                &IPTunnel_
            }
        };

        MainSystem.setLogFileName("log_tx.txt");
        MainSystem.setLogValue(false);

        MainSystem.run();
        MainSystem.terminate();
        //system("pause");

        return 0;
    }
}

namespace rx
{
    int main(int argc, char* argv[])
    {
        // # Variables Inicialization ######################################

        BobQOKDInputParameters param = BobQOKDInputParameters(argc, argv);

        // # Signals Declaration and Initialisation #########################

        Binary RandomBits{ "RandomBits.sgn" };
        Binary BobRandomBits{ "BobRandomBits.sgn" };
        Binary BobObliviousKeys{ "BobObliviousKeys.sgn" };
        Binary BobControlSignal{ "BobControlSignal.sgn" };

        // # Blocks Declaration and Initialisation ###########################

        IPTunnel IPTunnel_{ {},{&RandomBits} };
        IPTunnel_.setRemoteMachineIpAddress(param.remoteMachineIpAddress);
        IPTunnel_.setLocalMachineIpAddress(param.localMachineIpAddress);
        IPTunnel_.setLogValue(false);

        BinarySource BinarySource_{ {}, {&BobRandomBits} };
        BinarySource_.setLogValue(false);

        BobQOKD BobQOKD_{ {&RandomBits, &BobRandomBits}, {&BobObliviousKeys, &BobControlSignal} };
        BobQOKD_.setLogValue(false);

        Sink Sink_BobObliviousKeys_{ {&BobObliviousKeys}, {} };
        Sink_BobObliviousKeys_.setNumberOfSamplesToProcess(param.numberOfSamplesToProcess);
        Sink_BobObliviousKeys_.setLogValue(false);

        Sink Sink_BobControlSignal_{ {&BobControlSignal}, {} };
        Sink_BobControlSignal_.setNumberOfSamplesToProcess(param.numberOfSamplesToProcess);
        Sink_BobControlSignal_.setLogValue(false);

        // # System Declaration and Initialisation ############################

        System MainSystem{
            {
                &IPTunnel_,
                &BinarySource_,
                &BobQOKD_,
                &Sink_BobObliviousKeys_,
                &Sink_BobControlSignal_
            }
        };

        MainSystem.setLogFileName("log_rx.txt");
        MainSystem.setLogValue(false);

        MainSystem.run();
        MainSystem.terminate();
        //system("pause");

        return 0;
    }
}

int main(int argc, char* argv[])
{
    rx::main(argc, argv);
    return 0;
}
