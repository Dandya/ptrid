#include "ptrid_lib/readers.h"
#include "ptrid_lib/probabilistic_scheme.h"
#include "ptrid_lib/markov_chain.h"
#include "ptrid_lib/math_func.h"

#include <iostream>
#include <vector>

// #define MARKOV_CHAIN
// #define CHISQ
#define INFO_DISTANCE

#if defined(MARKOV_CHAIN)

/* using likelihood function */
void PrintType(std::string& name_path, char** paths_to_types, int count_types) {
	std::vector<long double> results(count_types);
	ptrid::ReaderBytes reader(2);
	reader.Read(name_path);
	std::vector<uint32_t> frequencies = reader.GetFrequencies();
	for (int i = 0; i < count_types; i++) {
		reader.Clean();
		reader.Read(paths_to_types[i]);
		ptrid::ProbabilisticScheme scheme(2, 256, reader.GetFrequencies());
		scheme.useAdditiveSmoothing(1000);
		ptrid::MarkovChain chain_type(scheme);
		for (size_t from = 0; from < 256; from++) {
			for (size_t to = 0; to < 256; to++) {
				if (frequencies[from + to * 256] != 0) {
					results[i] += (long double)frequencies[from + to * 256] *
								  log10l(chain_type.GetProbability(from, to));
				}
			}
		}
	}

	size_t max = 0;
	for (size_t i = 1; i < count_types; i++) {
		if (results[i] > results[max]) {
			max = i;
		}
	}
	std::cout << "Type: " << max + 1 << " (MC)" << std::endl;
}

#elif defined(CHISQ)

/* using chi square */
void PrintType(std::string& name_path, char** paths_to_types, int count_types) {
	std::vector<long double> results(count_types);
	ptrid::ReaderBytes reader(2);
	reader.Read(name_path);
	ptrid::ProbabilisticScheme scheme_file(2, 256, reader.GetFrequencies());
	scheme_file.useAdditiveSmoothing(10000);
	for (size_t i = 0; i < count_types; i++) {
		reader.Clean();
		reader.Read(paths_to_types[i]);
		ptrid::ProbabilisticScheme scheme_type(2, 256, reader.GetFrequencies());
		scheme_type.useAdditiveSmoothing(10000);
		results[i] = GetChi2(scheme_file, scheme_type);
	}

	size_t min = 0;
	for (size_t i = 0; i < count_types; i++) {
		std::cout << "Type_" << i + 1 << ": " << results[i] << std::endl;
		if (results[i] < results[min]) {
			min = i;
		}
	}
	std::cout << "Type: " << min + 1 << " (CH)" << std::endl;
}

#elif defined(INFO_DISTANCE)

/* using information distance */
void PrintType(std::string& name_path, char** paths_to_types, int count_types) {
	std::vector<long double> results(count_types);
	ptrid::ReaderBytes reader(2);
	reader.Read(name_path);
	ptrid::ProbabilisticScheme scheme_file(2, 256, reader.GetFrequencies());
	scheme_file.useAdditiveSmoothing(1000); 
	
	for (size_t i = 0; i < count_types; i++) {
		reader.Clean();
		reader.Read(paths_to_types[i]);
		ptrid::ProbabilisticScheme scheme_type(2, 256, reader.GetFrequencies());
		scheme_type.useAdditiveSmoothing(1000);
		results[i] = GetInfoDistance(scheme_type, scheme_file);
	}

	size_t min = 0;
	std::cout << results[0] << std::endl;
	for (size_t i = 1; i < count_types; i++) {
		std::cout << results[i] << std::endl;
		if (results[i] < results[min]) {
			min = i;
		}
	}
	std::cout << "Type: " << min + 1 << " (ID)" << std::endl;
}

#endif

int main(int argc, char** argv) {
	if (argc == 1) {
		std::cout << "Usage: ptrid PATH_TO_DIR_WITH_TYPE_1 ... "
				"[PATH_TO_DIR_WITH_TYPE_N]"
			 << std::endl;
		return 0;
	}

	try {
		std::string sInputPath;
		std::cout << "Hello!" << std::endl
			 << "Write \'exit\' for work's end." << std::endl
			 << "Input path to file: ";
		std::cin >> sInputPath;
		while (sInputPath != std::string("exit")) {
			if (ptrid::ReaderBytes::CheckTypeOfFile(sInputPath) == S_IFREG) {
				try {
					PrintType(sInputPath, argv + 1, argc - 1);
				} catch (std::exception &e) {
					std::cout << "Couldn't read the file" << std::endl;
				}
			} else {
				std::cout << "Is don't file." << std::endl;
			}
			std::cout << "Input path to file: ";
			std::cin >> sInputPath;
		}
	} catch (std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}