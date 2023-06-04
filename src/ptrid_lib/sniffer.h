#include <assert.h>
#include <pcap.h>
#include <stdint.h>
#include <time.h>

#include <chrono>
#include <iostream>
#include <vector>

namespace ptrid {

struct ProcessorTraffic {
	virtual void operator()(struct pcap_pkthdr *packet_header,
													const u_char *packet_data) noexcept = 0;
};

class Sniffer {
 private:
	pcap_t *descr_pcap_ = nullptr;
	pcap_dumper_t *descr_dump_ = nullptr;
	ProcessorTraffic *action_;
	std::string net_interface_name_ = "";
	std::string path_to_save_ = ".";

 public:
	Sniffer(ProcessorTraffic *action) noexcept {
		assert((action != nullptr) && "ptrid::Sniffer: action is nullptr.");
		action_ = action;
	}

	Sniffer(ProcessorTraffic *action, std::string path_to_save) noexcept {
		assert((action != nullptr) && "ptrid::Sniffer: action is nullptr.");
		action_ = action;
		path_to_save_ = path_to_save;
	}

	~Sniffer() { ClosePcap(); }

	std::vector<std::string> GetAvailableInterfaceNames();

	void SetInterfaceName(std::string &interface_name) {
		net_interface_name_ = interface_name;
	}

	std::string GetInterfaceName() noexcept { return net_interface_name_; }

	int GetLinkLayerProtocol() noexcept {
		assert((descr_pcap_ != nullptr) &&
					 "ptrid::Sniffer::GetLinkLayer: pcap descriptor is nullptr.");
		return pcap_datalink(descr_pcap_);
	}

	void OpenInterface() {
		try {
			if (net_interface_name_ == "")
				throw std::runtime_error("need set interface before opening");
			OpenPcap();
		} catch (std::exception &e) {
			throw std::runtime_error("ptrid::Sniffer::OpenInterface:\n" +
															 std::string(e.what()));
		}
	}

	void CloseInterface() noexcept { ClosePcap(); }

	void Run(const std::chrono::seconds sniffing_time);

 private:
	std::string GetDumpName();

	void OpenPcap();

	void OpenDump(const std::string &dump_name);

	int ReadPacket(struct pcap_pkthdr **packet_header, const u_char **packet_data);

	void ClosePcap() noexcept {
		if (descr_pcap_) {
			pcap_close(descr_pcap_);
			descr_pcap_ = nullptr;
		}
	}

	void CloseDump() {
		if (descr_dump_) {
			pcap_dump_close(descr_dump_);
			descr_dump_ = nullptr;
		}
	}
};

}	 // namespace ptrid