#include <pcap.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>

#include <iostream>
#include <vector>
#include <filesystem>
#include <unordered_map>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/asio/ip/address_v4.hpp>

#include "ptrid_lib/readers.h"
#include "ptrid_lib/probabilistic_scheme.h"
#include "ptrid_lib/markov_chain.h"
#include "ptrid_lib/math_func.h"
#include "ptrid_lib/sniffer.h"

#define TCP_PROTOCOL 6
#define ETHERNET_IPV4 0x0008

// #define MARKOV_CHAIN
#define INFO_DISTANCE
// #define CHISQ

#define TIME_WAIT 600
#define TIME_AFTER_END 10

struct HttpSessionInfo {
	std::vector<uint32_t> frequencies;
	std::string get_request;

	HttpSessionInfo() = default;

	HttpSessionInfo(const std::string &request, std::vector<uint32_t> &freq)
			: get_request(request), frequencies(freq) {}

	HttpSessionInfo(const std::string &&request, std::vector<uint32_t> &&freq)
			: get_request(request), frequencies(freq) {}
};

struct TcpSessionName {
	boost::asio::ip::address_v4 ipaddr1;
	boost::asio::ip::address_v4 ipaddr2;
	uint16_t port1 = 0;
	uint16_t port2 = 0;

	TcpSessionName() = default;

	TcpSessionName(boost::asio::ip::address_v4::bytes_type &raw_ipaddr1,
									uint16_t port_1,
									boost::asio::ip::address_v4::bytes_type &raw_ipaddr2,
									uint16_t port_2) noexcept {
		if (raw_ipaddr1 < raw_ipaddr2 ||
				raw_ipaddr1 == raw_ipaddr2 && port_1 <= port_2) {
			ipaddr1 = boost::asio::ip::make_address_v4(raw_ipaddr1);
			ipaddr2 = boost::asio::ip::make_address_v4(raw_ipaddr2);
			port1 = port_1;
			port2 = port_2;
		} else {
			ipaddr1 = boost::asio::ip::make_address_v4(raw_ipaddr2);
			ipaddr2 = boost::asio::ip::make_address_v4(raw_ipaddr1);
			port1 = port_2;
			port2 = port_1;
		}
	}
};

template <>
struct std::hash<TcpSessionName> {
	size_t operator()(TcpSessionName const &tcp_name) const noexcept {
		size_t hash = 0;
		hash += std::hash<boost::asio::ip::address_v4>()(tcp_name.ipaddr1);
		hash += 31 * std::hash<boost::asio::ip::address_v4>()(tcp_name.ipaddr2);
		hash += 31 * 31 * tcp_name.port1 + 31 * 31 * 31 * tcp_name.port2;
		return hash;
	}
};

bool operator==(const TcpSessionName &a, const TcpSessionName &b) noexcept {
	return (a.ipaddr1 == b.ipaddr1 && a.ipaddr2 == b.ipaddr2 &&
					a.port1 == b.port1 && a.port2 == b.port2);
}

struct TypeAnalyzer {
	size_t count_types = 0;
	virtual size_t operator()(const std::vector<uint32_t> &frequencies) = 0;
};

struct MarkovTypeAnalyzer : TypeAnalyzer {
	std::vector<ptrid::MarkovChain> types;

	size_t operator()(const std::vector<uint32_t> &frequencies) {
		long double probabilities[count_types] = {0.};

		for (size_t type_index = 0; type_index < count_types; type_index++)
			for (size_t from = 0; from < 256; from++)
				for (size_t to = 0; to < 256; to++)
					if (frequencies[from + to * 256] != 0)
						probabilities[type_index] +=
								(long double)frequencies[from + to * 256] *
								log10l(types[type_index].GetProbability(from, to));
		
		size_t max = 0;
		for (size_t i = 1; i < count_types; i++) {
			if (probabilities[i] > probabilities[max]) {
				max = i;
			}
		}
		return max;
	}

	MarkovTypeAnalyzer() = delete;

	MarkovTypeAnalyzer(const std::vector<ptrid::MarkovChain> &vec) {
		types = vec;
		count_types = types.size();
	}

	MarkovTypeAnalyzer(const std::vector<ptrid::MarkovChain> &&vec) {
		types = vec;
		count_types = types.size();
	}
};

struct InfoDistTypeAnalyzer : TypeAnalyzer {
	std::vector<ptrid::ProbabilisticScheme> types;

	size_t operator()(const std::vector<uint32_t> &frequencies) {
		long double info_distances[count_types] = {0.};
		ptrid::ProbabilisticScheme data_scheme(2, 256, frequencies);
		data_scheme.useAdditiveSmoothing(1000);

		for(size_t type_index = 0; type_index < types.size(); type_index++)
			info_distances[type_index] = ptrid::GetInfoDistance(types[type_index], data_scheme);
	
		size_t min = 0;
		for (size_t i = 1; i < types.size(); i++) {
			if (info_distances[i] < info_distances[min]) {
				min = i;
			}
		}
		return min;
	}

	InfoDistTypeAnalyzer() = delete;

	InfoDistTypeAnalyzer(const std::vector<ptrid::ProbabilisticScheme> &vec) {
		types = vec;
		count_types = types.size();
	}

	InfoDistTypeAnalyzer(const std::vector<ptrid::ProbabilisticScheme> &&vec) {
		types = vec;
		count_types = types.size();
	}
};

struct ChiSqTypeAnalyzer : TypeAnalyzer {
	std::vector<ptrid::ProbabilisticScheme> types;

	size_t operator()(const std::vector<uint32_t> &frequencies) {
		long double chi2[count_types] = {0.};
		ptrid::ProbabilisticScheme data_scheme(2, 256, frequencies);
		data_scheme.useAdditiveSmoothing(1000);

		for(size_t type_index = 0; type_index < types.size(); type_index++)
			chi2[type_index] = ptrid::GetChi2(data_scheme, types[type_index]);
	
		size_t min = 0;
		for (size_t i = 1; i < types.size(); i++) {
			if (chi2[i] < chi2[min]) {
				min = i;
			}
		}
		return min;
	}

	ChiSqTypeAnalyzer() = delete;

	ChiSqTypeAnalyzer(const std::vector<ptrid::ProbabilisticScheme> &vec) {
		types = vec;
		count_types = types.size();
	}

	ChiSqTypeAnalyzer(const std::vector<ptrid::ProbabilisticScheme> &&vec) {
		types = vec;
		count_types = types.size();
	}
};

struct EthIpv4HttpTypeChecker : ptrid::ProcessorTraffic {
	TypeAnalyzer *analyzer = nullptr;
	std::vector<std::string> type_names;
	std::unordered_map<TcpSessionName, HttpSessionInfo> opened_http_sessions;

	bool IsHttpGetRequest(const u_char *data) {
		return (memcmp(data, "GET", 3) == 0);
	}

	bool IsHttpGetResponse(const u_char *data) {
		return (memcmp(data, "HTTP", 4) == 0);
	}

	std::vector<uint32_t> &AddFrequencies(std::vector<uint32_t> &dst,
																				std::vector<uint32_t> &src) {
		assert((dst.size() == src.size()) && "EthIpv4HttpTypeChecker::AddFrequencies: vector sizes not equal.");
		for (size_t i = 0; i < dst.size(); i++)
			dst[i] += src[i];
		
		return dst;
	}

	void operator()(struct pcap_pkthdr *packet_header,
									const u_char *packet_data) {
		try {
			if (!packet_header || !packet_data)
				throw std::runtime_error("@packet_header or @packet_data is nullptr.");
			
			std::pair<const uint8_t *, size_t> data(nullptr, 0);
			
			struct iphdr *ip_hdr =
					((struct ethhdr *)packet_data)->h_proto == ETHERNET_IPV4
							? (struct iphdr *)(packet_data + sizeof(struct ethhdr))
							: nullptr;
			struct tcphdr *tcp_hdr = nullptr;
			
			if (ip_hdr && ip_hdr->protocol == TCP_PROTOCOL) {
				tcp_hdr = (struct tcphdr *)(packet_data + sizeof(struct ethhdr) +
																		(ip_hdr->ihl) * 4);
				data.first = packet_data + sizeof(struct ethhdr) + (ip_hdr->ihl) * 4 +
										tcp_hdr->th_off * 4;
				data.second =
						packet_header->caplen -
						(sizeof(struct ethhdr) + (ip_hdr->ihl) * 4 + tcp_hdr->th_off * 4);
			}

			if (!data.first || !analyzer || analyzer->count_types == 0) return;

			boost::asio::ip::address_v4::bytes_type ipaddr_src;
			memcpy(ipaddr_src.data(), &(ip_hdr->saddr), ipaddr_src.size());

			boost::asio::ip::address_v4::bytes_type ipaddr_dst;
			memcpy(ipaddr_dst.data(), &(ip_hdr->daddr), ipaddr_dst.size());

			TcpSessionName tcp_name(ipaddr_src, tcp_hdr->source, ipaddr_dst,
																tcp_hdr->dest);

			try {
				HttpSessionInfo &http_info = opened_http_sessions.at(tcp_name);

				std::cout << http_info.get_request;

				if ((tcp_hdr->th_flags & TH_FIN) == 1 ||
						(tcp_hdr->th_flags & TH_RST) == 1)
					opened_http_sessions.erase(tcp_name);

				if (data.second < 20) return;

				
				ptrid::ReaderBytes reader(2);
				reader.Read(data.first, data.second);
				std::vector<uint32_t> data_frequencies = reader.GetFrequencies();
				size_t type_index = 0;
				if (IsHttpGetResponse(data.first))
					type_index = analyzer->operator()(data_frequencies);
				else
					type_index = analyzer->operator()(
							AddFrequencies(http_info.frequencies, data_frequencies));

				std::cout << "Data type is " + type_names[type_index] << std::endl;

			} catch (std::out_of_range &e) {
				if (IsHttpGetRequest(data.first)) {
					size_t newline_pos = 0;
					while (newline_pos != data.second && data.first[newline_pos] != '\n')
						newline_pos += 1;
					char get_request[newline_pos + 2];
					memcpy(get_request, data.first, newline_pos+1);
					get_request[newline_pos+1] = '\0';
					
					HttpSessionInfo http_info;
					http_info.get_request = get_request;
					http_info.frequencies =
							std::move(std::vector<uint32_t>(65536, 0.));
					std::cout << http_info.get_request << "Data type is plain_text"
										<< std::endl;
					opened_http_sessions[tcp_name] = std::move(http_info);
					return;
				}
			}
		} catch (std::exception &e) {
			throw std::runtime_error("EthIpv4HttpTypeChecker::operator(): " + 
															 std::string(e.what()));
		}
	}
};

int main(int argc, char** argv) {
	boost::program_options::options_description opt_descr(
		"Usage: ptrid_new --types PATH_TO_TYPE_1 ... PATH_TO_TYPE_N " 
		"[--save PATH] [--mode {MC, ID, CHI2}]");
	opt_descr.add_options()("help,h", "print usage message")(
			"save", boost::program_options::value<std::string>()->default_value("."),
			"path to directory for saving data")(
			"types",
			boost::program_options::value<std::vector<std::string>>()
					->multitoken()
					->required(),
			"paths to directories containing files of the same type")(
			"mode", boost::program_options::value<std::string>()->default_value("MC"),
			"mode of analyzing of data (MC - markov chain, ID - information distance, CHI2 - chi-squared)"
			);

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
		EthIpv4HttpTypeChecker checker;

		if (vm["mode"].as<std::string>() == "MC") {
			std::vector<ptrid::MarkovChain> types(
				vm["types"].as<std::vector<std::string>>().size() + 1);
			
			for(size_t i = 0; i < types.size()-1; i++) {
				reader.Clean();
				reader.Read(vm["types"].as<std::vector<std::string>>()[i]);
				types[i].Create(ptrid::ProbabilisticScheme(2, 256, reader.GetFrequencies()));
				types[i].useAdditiveSmoothing(1000);
			}
			types[types.size()-1].Create(ptrid::ProbabilisticScheme(2, 256, std::vector<uint32_t>(256*256, 1)));

			checker.analyzer = new MarkovTypeAnalyzer(types);
			checker.type_names = vm["types"].as<std::vector<std::string>>();
			checker.type_names.push_back(std::string("random"));
		} else if (vm["mode"].as<std::string>() == "ID" || 
							 vm["mode"].as<std::string>() == "CHI2") {
			std::vector<ptrid::ProbabilisticScheme> types(
					vm["types"].as<std::vector<std::string>>().size() + 1);
			
			for(size_t i = 0; i < types.size()-1; i++) {
				reader.Clean();
				reader.Read(vm["types"].as<std::vector<std::string>>()[i]);
				types[i].Create(2, 256, reader.GetFrequencies());
				types[i].useAdditiveSmoothing(1000);
			}
			types[types.size()-1].Create(2, 256, std::vector<uint32_t>(256*256, 1));

			if (vm["mode"].as<std::string>() == "ID")
				checker.analyzer = new InfoDistTypeAnalyzer(types);
			else
				checker.analyzer = new ChiSqTypeAnalyzer(types);
			checker.type_names = vm["types"].as<std::vector<std::string>>();
			checker.type_names.push_back(std::string("random"));
		} else {
			throw std::invalid_argument("parameter \'mode\' is incorrect.");
		}

		ptrid::Sniffer sniffer((ptrid::ProcessorTraffic *)&checker);
		std::vector<std::string> interfaces = sniffer.GetAvailableInterfaceNames();
		sniffer.SetInterfaceName(interfaces[0]);
		sniffer.OpenInterface();
		if (sniffer.GetLinkLayerProtocol() != DLT_EN10MB)
			throw std::runtime_error("Ethernet protocol doesn't using on this interface.");
		std::chrono::seconds time_sniffing(60);
		sniffer.Run(time_sniffing);
		sniffer.CloseInterface();
		delete checker.analyzer;
	} catch (std::exception &e) {
		if (e.what()[0] == '\0')
			std::cout << opt_descr << std::endl;
		else
			std::cout << "Error: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}