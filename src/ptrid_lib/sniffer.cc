#include "sniffer.h"

namespace ptrid {

std::vector<std::string> Sniffer::GetAvailableInterfaceNames() {
	pcap_if_t *network_devises;		 /* pointer on linked list with information
										 about network devises */
	char errbuf[PCAP_ERRBUF_SIZE]; /* buffer for error */
	int result;

	/* getting name of network device */
	result = pcap_findalldevs(&network_devises, errbuf);
	if (result == PCAP_ERROR) {
		throw std::runtime_error(errbuf);
	}

	std::vector<std::string> interfaces_names;
	while (network_devises->next != NULL) {
		interfaces_names.push_back(network_devises->name);
		network_devises = network_devises->next;
	}

	return interfaces_names;
}

void Sniffer::OpenPcap() {
	try {
		char errbuf[PCAP_ERRBUF_SIZE];

		if (net_interface_name_ != "") {
			/* open device in promiscuous mode */
			descr_pcap_ =
					pcap_open_live(net_interface_name_.c_str(), BUFSIZ, 1, -1, errbuf);
			if (descr_pcap_ == NULL) throw std::runtime_error(errbuf);
		} else {
			throw std::runtime_error("Choose interface before running.");
		}
	} catch (std::exception &e) {
		throw std::runtime_error("ptrid::Sniffer::OpenPcap:\n" +
														 std::string(e.what()));
	}
}

std::string Sniffer::GetDumpName() {
		time_t t;
		time(&t);
		char *date = ctime(&t);
		std::string file_name = "";
		for (size_t i = 0; i < 24; i++) {
			file_name.append(1, (date[i] == ' ') ? '_' : date[i]);
		}
		file_name = path_to_save_ + "/" + file_name + ".pcap";
		return file_name;
	}


void Sniffer::OpenDump(const std::string &dump_name) {
	assert((descr_pcap_ != nullptr) && 
				 "ptrid::Sniffer::OpenDump: pcap descriptor is nullptr.");
	descr_dump_ = pcap_dump_open(descr_pcap_, dump_name.c_str());
	if (!descr_dump_)
		throw std::runtime_error("ptrid::Sniffer::OpenDump: Error of open dump - " + dump_name);
}

void Sniffer::Run(const std::chrono::seconds sniffing_time) {
	try {
		if (descr_pcap_ == nullptr)
			throw std::runtime_error("pcap descriptor is nullptr.");

		std::string dump_name = GetDumpName();
		std::cout << "Writing packets to " << dump_name << std::endl;
		OpenDump(dump_name);

		struct pcap_pkthdr *packet_header = nullptr;
		const u_char *packet_data = nullptr;
		auto start = std::chrono::system_clock::now();
		int reading_result = 0;
		uint32_t packet_num = 0;
		while (std::chrono::system_clock::now() - start < sniffing_time) {
			reading_result = ReadPacket(&packet_header, &packet_data);
			if (reading_result == 0)
				continue;
			std::cout << "Packet: " << ++packet_num << std::endl;
			action_->operator()(packet_header, packet_data);
			pcap_dump((u_char *)descr_dump_, packet_header, packet_data);
		}
			
		CloseDump();
		ClosePcap();
	} catch (std::exception &e) {
		throw std::runtime_error("ptrid::Sniffer::Run:\n" + std::string(e.what()));
	}
}

int Sniffer::ReadPacket(struct pcap_pkthdr **packet_header, const u_char **packet_data) {
	int result = pcap_next_ex(descr_pcap_, packet_header, packet_data);
	if (result == PCAP_ERROR_ACTIVATED || result == PCAP_ERROR)
		throw std::runtime_error("ptrid::Sniffer::ReadPacket: " +
														 std::string(pcap_geterr(descr_pcap_)));
	return result;
}

}	 // namespace ptrid