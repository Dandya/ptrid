#include <pcap.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <iostream>
#include <vector>
#include <filesystem>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>

#include "ptrid_lib/readers.h"
#include "ptrid_lib/probabilistic_scheme.h"
#include "ptrid_lib/markov_chain.h"
#include "ptrid_lib/math_func.h"
#include "ptrid_lib/sniffer.h"

#define TCP_PROTOCOL 6
#define ETHERNET_IPV4 0x0008

#define MARKOV_CHAIN
// #define INFO_DISTANCE
// #define CHISQ

std::pair<const uint8_t *, size_t> GetData(struct pcap_pkthdr * packet_header, const u_char * packet_data) {
	struct iphdr *ip_hdr =
			((struct ethhdr *)packet_data)->h_proto == ETHERNET_IPV4
				? (struct iphdr *)(packet_data + sizeof(struct ethhdr))
				: NULL;
	if (ip_hdr != NULL && ip_hdr->protocol == TCP_PROTOCOL) {
		struct tcphdr * tcp_hdr = (struct tcphdr *)(packet_data + sizeof(struct ethhdr) + (ip_hdr->ihl) * 4);
		return std::pair<const uint8_t *, size_t>(
				packet_data + sizeof(struct ethhdr) + (ip_hdr->ihl) * 4 +
						tcp_hdr->th_off * 4,
				packet_header->caplen - (sizeof(struct ethhdr) + (ip_hdr->ihl) * 4 + tcp_hdr->th_off * 4));
	}
	std::cout << "Unsupported packet" << std::endl;
	return std::pair<const uint8_t *, size_t>(NULL, 0);		
}

#if defined(MARKOV_CHAIN) 
struct CheckTypeEthIpv4MC : ptrid::ProcessorTraffic {
	std::vector<ptrid::MarkovChain> types;
	std::vector<std::string> type_names;

	void operator()(struct pcap_pkthdr * packet_header,
									const u_char * packet_data) noexcept {
		std::pair<const uint8_t *, size_t> data = GetData(packet_header, packet_data);
		if (!data.first || data.second < 100 || types.size() == 0)
			return;

		ptrid::ReaderBytes reader(2);
		reader.Read(data.first, data.second);
		std::vector<uint32_t> frequencies = reader.GetFrequencies();

		std::vector<long double> results(types.size(), 0.);
		for(size_t type_index = 0; type_index < types.size(); type_index++)
			for (size_t from = 0; from < 256; from++)
				for (size_t to = 0; to < 256; to++)
					if (frequencies[from + to * 256] != 0) 
						results[type_index] += (long double)frequencies[from + to * 256] *
										log10l(types[type_index].GetProbability(from, to));
		size_t max = 0;
		for (size_t i = 1; i < types.size(); i++) {
			if (results[i] > results[max]) {
				max = i;
			}
		}
		std::cout << "Data type is " + type_names[max] << std::endl;
	}
};

#elif defined(INFO_DISTANCE)

struct CheckTypeEthIpv4ID : ptrid::ProcessorTraffic {
	std::vector<ptrid::ProbabilisticScheme> types;
	std::vector<std::string> type_names;

	void operator()(struct pcap_pkthdr * packet_header,
									const u_char * packet_data) noexcept {
		std::pair<const uint8_t *, size_t> data = GetData(packet_header, packet_data);
		if (!data.first || data.second < 100 || types.size() == 0)
			return;

		ptrid::ReaderBytes reader(2);
		reader.Read(data.first, data.second);
		ptrid::ProbabilisticScheme data_scheme(2, 256, reader.GetFrequencies());

		std::vector<long double> results(types.size(), 0.);
		for(size_t type_index = 0; type_index < types.size(); type_index++)
			results[type_index] = ptrid::GetInfoDistance(types[type_index], data_scheme);
	
		size_t min = 0;
		for (size_t i = 1; i < types.size(); i++) {
			if (results[i] < results[min]) {
				min = i;
			}
		}
		std::cout << "Data type is " + type_names[min] << std::endl;
	}
};

#elif defined(CHISQ)

struct CheckTypeEthIpv4CH : ptrid::ProcessorTraffic {
	std::vector<ptrid::ProbabilisticScheme> types;
	std::vector<std::string> type_names;

	void operator()(struct pcap_pkthdr * packet_header,
									const u_char * packet_data) noexcept {
		std::pair<const uint8_t *, size_t> data = GetData(packet_header, packet_data);
		if (!data.first || data.second < 100 || types.size() == 0)
			return;

		ptrid::ReaderBytes reader(2);
		reader.Read(data.first, data.second);
		ptrid::ProbabilisticScheme data_scheme(2, 256, reader.GetFrequencies());
		data_scheme.useAdditiveSmoothing(1000);
		std::vector<long double> results(types.size(), 0.);
		for(size_t type_index = 0; type_index < types.size(); type_index++)
			results[type_index] = ptrid::GetChi2(data_scheme, types[type_index]);
	
		size_t min = 0;
		for (size_t i = 1; i < types.size(); i++) {
			if (results[i] < results[min]) {
				min = i;
			}
		}
		std::cout << "Data type is " + type_names[min] << std::endl;
	}
};

#endif

int main(int argc, char** argv) {
	boost::program_options::options_description opt_descr(
		"Usage: ptrid_new --types PATH_TO_TYPE_1 ... PATH_TO_TYPE_N " 
		"[--save PATH]");
	opt_descr.add_options()("help,h", "print usage message")(
			"save", boost::program_options::value<std::string>()->default_value("."),
			"path to directory for saving data")(
			"types",
			boost::program_options::value<std::vector<std::string>>()
					->multitoken()
					->required(),
			"paths to directories containing files of the same type");

	try {
		boost::program_options::variables_map vm;
		boost::program_options::store(
			boost::program_options::command_line_parser(argc, argv)
				.options(opt_descr)
				.run(),
			vm);
		
		/* checking input parameters */
		if (vm.count("help") > 0 || vm.count("types") == 0 || 
				vm["types"].as<std::vector<std::string>>().size() == 0) 
			throw std::logic_error("");

		std::cout << vm["types"].as<std::vector<std::string>>().size() << std::endl;
		for(auto str_path : vm["types"].as<std::vector<std::string>>()) {
			if (!std::filesystem::is_directory(
					std::filesystem::path(str_path)))
				throw std::runtime_error(str_path +
																" - doesn't directory.");
			std::cout << str_path << std::endl;
		}

		ptrid::ReaderBytes reader(2);

#if defined(MARKOV_CHAIN)
		std::vector<ptrid::MarkovChain> types(
				vm["types"].as<std::vector<std::string>>().size() + 1);
		
		for(size_t i = 0; i < types.size()-1; i++) {
			reader.Clean();
			reader.Read(vm["types"].as<std::vector<std::string>>()[i]);
			types[i].Create(ptrid::ProbabilisticScheme(2, 256, reader.GetFrequencies()));
			types[i].useAdditiveSmoothing(1000);
		}
		types[types.size()-1].Create(ptrid::ProbabilisticScheme(2, 256, std::vector<uint32_t>(256*256, 1)));


		CheckTypeEthIpv4MC action;
		action.types = std::move(types);
		action.type_names = vm["types"].as<std::vector<std::string>>();
		action.type_names.push_back(std::string("random"));

#elif defined(INFO_DISTANCE)

		std::vector<ptrid::ProbabilisticScheme> types(
				vm["types"].as<std::vector<std::string>>().size() + 1);
		
		for(size_t i = 0; i < types.size()-1; i++) {
			reader.Clean();
			reader.Read(vm["types"].as<std::vector<std::string>>()[i]);
			types[i].Create(2, 256, reader.GetFrequencies());
			types[i].useAdditiveSmoothing(1000);
		}
		types[types.size()-1].Create(2, 256, std::vector<uint32_t>(256*256, 1));


		CheckTypeEthIpv4ID action;
		action.types = std::move(types);
		action.type_names = vm["types"].as<std::vector<std::string>>();
		action.type_names.push_back(std::string("random"));

#elif defined(CHISQ)

	std::vector<ptrid::ProbabilisticScheme> types(
				vm["types"].as<std::vector<std::string>>().size() + 1);
		
		for(size_t i = 0; i < types.size()-1; i++) {
			reader.Clean();
			reader.Read(vm["types"].as<std::vector<std::string>>()[i]);
			types[i].Create(2, 256, reader.GetFrequencies());
			types[i].useAdditiveSmoothing(1000);
		}
		types[types.size()-1].Create(2, 256, std::vector<uint32_t>(256*256, 1));


		CheckTypeEthIpv4CH action;
		action.types = std::move(types);
		action.type_names = vm["types"].as<std::vector<std::string>>();
		action.type_names.push_back(std::string("random"));

#endif

		ptrid::Sniffer sniffer((ptrid::ProcessorTraffic *)&action);
		std::vector<std::string> interfaces = sniffer.GetAvailableInterfaceNames();
		sniffer.SetInterfaceName(interfaces[0]);
		sniffer.OpenInterface();
		if (sniffer.GetLinkLayerProtocol() != DLT_EN10MB)
			throw std::runtime_error("Ethernet protocol doesn't using on this interface.");
		std::chrono::seconds time_sniffing(20);
		sniffer.Run(time_sniffing);
		sniffer.CloseInterface();
	} catch (std::exception &e) {
		if (e.what()[0] == '\0')
			std::cout << opt_descr << std::endl;
		else
			std::cout << "Error: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}