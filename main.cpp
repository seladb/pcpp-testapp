#include "stdlib.h"
#include "getopt.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include "PlatformSpecificUtils.h"

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	printUsage(); \
	exit(1); \
	} while(0)

static struct option TestAppOptions[] =
{
	{"interface",  required_argument, 0, 'i'},
	{"output-file", required_argument, 0, 'o'},
	{"iface-info", no_argument, 0, 'l'},
	{"silent-mode", no_argument, 0, 's'},	
	{"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};

struct CaptureArgs
{
	bool shouldStop;
	bool silentMode;
	uint32_t packetCount;
	pcpp::PcapFileWriterDevice* pcapWriter;

	CaptureArgs(pcpp::PcapFileWriterDevice* pcapWriter, bool silentMode)
	{
		shouldStop = false;
		packetCount = 0;
		this->pcapWriter = pcapWriter;
		this->silentMode = silentMode;
	}
};

/**
 * Print application usage
 */
void printUsage()
{
	printf("\nUsage:\n"
			"-------\n"
			"%s -i interface_name [-o output-file] [-s] [-h] [-l] [-v]\n\n", pcpp::AppName::get().c_str());
	exit(0);
}

/**
 * Print application version
 */
void printAppVersion()
{
	printf("%s %s\n", pcpp::AppName::get().c_str(), pcpp::getPcapPlusPlusVersionFull().c_str());
	printf("Built: %s\n", pcpp::getBuildDateTime().c_str());
	printf("Built from: %s\n", pcpp::getGitInfo().c_str());
	exit(0);
}

/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
void onApplicationInterrupted(void* cookie)
{
	CaptureArgs* args = (CaptureArgs*)cookie;
	args->shouldStop = true;
}

/**
 * a callback function for the blocking mode capture which is called each time a packet is captured
 */
static bool onPacketArrivesBlockingMode(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	// check if should stop
	CaptureArgs* args = (CaptureArgs*)cookie;

	// stop capturing packets and return
	if (args->shouldStop)
		return true;

	// parsed the raw packet
	pcpp::Packet parsedPacket(packet);

	args->packetCount++;

	if (!args->silentMode)
		printf("%s\n", parsedPacket.toString().c_str());

	if (args->pcapWriter != NULL)
	{
		args->pcapWriter->writePacket(*packet);
	}

	// return false means we don't want to stop capturing after this callback
	return false;
}

/**
 * main method of the application
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	std::string interfaceNameOrIP = "";
	std::string outputFile = "";
	bool printInterfaceInfo = false;
	bool silentMode = false;

	int optionIndex = 0;
	char opt = 0;

	while((opt = getopt_long (argc, argv, "i:o:slhv", TestAppOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'i':
				interfaceNameOrIP = optarg;
				break;
			case 'o':
				outputFile = optarg;
				break;
			case 'h':
				printUsage();
				break;
			case 'v':
				printAppVersion();
				break;
			case 'l':
				printInterfaceInfo = true;
				break;
			case 's':
				silentMode = true;
				break;
			default:
				printUsage();
				exit(-1);
		}
	}

	// extract pcap live device by interface name or IP address
	pcpp::PcapLiveDevice* dev = NULL;
	pcpp::IPv4Address interfaceIP(interfaceNameOrIP);
	if (interfaceIP.isValid())
	{
		dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP);
		if (dev == NULL)
			EXIT_WITH_ERROR("Couldn't find interface by provided IP");
	}
	else
	{
		dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interfaceNameOrIP);
		if (dev == NULL)
			EXIT_WITH_ERROR("Couldn't find interface by provided name");
	}

	if (printInterfaceInfo)
	{
		// before capturing packets let's print some info about this interface
		printf("Interface info:\n");
		// get interface name
		printf("   Interface name:        %s\n", dev->getName());
		// get interface description
		printf("   Interface description: %s\n", dev->getDesc());
		// get interface MAC address
		printf("   MAC address:           %s\n", dev->getMacAddress().toString().c_str());
		// get default gateway for interface
		printf("   Default gateway:       %s\n", dev->getDefaultGateway().toString().c_str());
		// get interface MTU
		printf("   Interface MTU:         %d\n", dev->getMtu());
		// get DNS server if defined for this interface
		if (dev->getDnsServers().size() > 0)
			printf("   DNS server:            %s\n", dev->getDnsServers().at(0).toString().c_str());

		exit(0);
	}

	// open the device before start capturing/sending packets
	if (!dev->open())
	{
		EXIT_WITH_ERROR("Cannot open device\n");
	}

	// if needed to save the captured packets to file - open a writer device
	pcpp::PcapFileWriterDevice* pcapWriter = NULL;
	if (outputFile != "")
	{
		pcapWriter = new pcpp::PcapFileWriterDevice(outputFile.c_str());
		if (!pcapWriter->open())
		{
			EXIT_WITH_ERROR("Could not open pcap file for writing");
		}
	}

	CaptureArgs args(pcapWriter, silentMode);

	// register the on app close event to print summary stats on app termination
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &args);

	printf("Starting packet capture, press Ctrl+C to stop...\n");
	while(!args.shouldStop)
	{
		dev->startCaptureBlockingMode(onPacketArrivesBlockingMode, &args, 5);
	}

	printf("Total packet count: %d\n", (int)args.packetCount);

	// close the device before application ends
	dev->close();

	// close output file
	if (pcapWriter != NULL)
	{
		pcapWriter->close();
		printf("Packets written to %s\n", outputFile.c_str());
	}
}
