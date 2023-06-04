#include "readers.h"

namespace ptrid {

std::string ReaderBytes::GetNameOfDump(const std::string &path, uint32_t type) {
	if (type == S_IFREG)
		return path + "_" + std::to_string(deep_) + ".dmp";	
	else if (type == S_IFDIR)
		return path + "/dir_" + std::to_string(deep_) + ".dmp";
	else
		return "";
}

bool ReaderBytes::IsDump(const std::string &path) {
	return std::filesystem::path(path).extension() == ".dmp";
}

bool ReaderBytes::CheckExistingDump(const std::string &path_to_dump) {
	return std::filesystem::is_regular_file(path_to_dump);	
}

void ReaderBytes::ReadFrequenciesFromDump(const std::string &path_to_dump, std::vector<uint32_t> &dst) {
	std::cout << "Reading frequencies from dump: " << path_to_dump << std::endl;
	std::ifstream ifs(path_to_dump, std::ifstream::binary);
	boost::archive::text_iarchive input_archive(ifs);
	input_archive >> dst;
}

void ReaderBytes::WriteFrequenciesToDump(const std::string &path_to_dump, std::vector<uint32_t> &src) {
	std::cout << "Writing frequencies to dump: " << path_to_dump << std::endl;
	std::ofstream ofs(path_to_dump, std::ofstream::binary);
	boost::archive::text_oarchive output_archive(ofs);
	output_archive << src;
}

void ReaderBytes::ReadFile(const std::string &path, std::vector<uint32_t> &dst_frequencies) {
	std::cout << "Reading file: " << path << std::endl;
	std::vector<uint32_t> frequencies_from_file;
	std::string path_to_dump = GetNameOfDump(path, S_IFREG);
	if (!CheckExistingDump(path_to_dump)) {
		frequencies_from_file.resize(frequencies_.size(), 0);
		ReadData(path, frequencies_from_file);
		WriteFrequenciesToDump(path_to_dump, frequencies_from_file);
	}	else {
		ReadFrequenciesFromDump(path_to_dump, frequencies_from_file);
	}
	for (size_t i = 0; i < frequencies_.size(); i++)
			dst_frequencies[i] += frequencies_from_file[i];
}

void ReaderBytes::ReadDirectory(const std::string &path) {
	std::filesystem::path path_to_directory{path};
	std::cout << "Reading directory:" << path << ":" << std::endl;
	std::string path_to_dump = GetNameOfDump(path, S_IFDIR);
	std::vector<uint32_t> frequencies_from_dir;
	if (!CheckExistingDump(path_to_dump)) {
		frequencies_from_dir.resize(frequencies_.size(), 0);

		for (const std::filesystem::directory_entry &entry :
				 std::filesystem::directory_iterator(path_to_directory)) {
			std::string path_to_file = entry.path().string();
			if (entry.is_regular_file() && !IsDump(path_to_file))
				ReadFile(path_to_file, frequencies_from_dir);
		}
		WriteFrequenciesToDump(path_to_dump, frequencies_from_dir);
	} else {
		std::cout << "\tRead dump: " << path_to_dump << std::endl;
		ReadFrequenciesFromDump(path_to_dump, frequencies_from_dir);
	}
	for (size_t i = 0; i < frequencies_.size(); i++)
			frequencies_[i] += frequencies_from_dir[i];
}

int32_t ReaderBytes::CheckTypeOfFile(const std::string &name_source) {
	struct stat settings;
	int32_t result = stat(name_source.c_str(), &settings);
	if (result != 0) {
		throw std::invalid_argument(
				"ptrid::ReaderBytes::CheckTypeOfFile: Unsupported type of file or file don't exist: " +
				name_source);
	}
	return settings.st_mode & S_IFMT;
}

void ReaderBytes::Read(const std::string &name_source) {
	try {
		int32_t result = CheckTypeOfFile(name_source);
		if (result == S_IFREG)
			ReadFile(name_source, frequencies_);
		else if (result == S_IFDIR)
			ReadDirectory(name_source);
	} catch (std::exception &e) {
		throw std::runtime_error("ptrid::ReaderBytes::Read:\n" + std::string(e.what()));
	}
}

void ReaderBytes::Read(const uint8_t *data, size_t len) {
	if (!data)
		throw std::runtime_error("ptrid::ReaderBytes::Read: @data is nullptr");

	if (deep_ == 1) {
		for(size_t i = 0; i < len; i++)
			frequencies_[data[i]] += 1;
	} else {
		for(size_t i = 0, j = 1; j < len; i++, j++)
			frequencies_[data[i] + data[j] * 256] += 1;
	}
}

void ReaderBytes::ReadData(const std::string &name_file, std::vector<uint32_t> &frequencies) {
	std::ifstream f_in(name_file, std::ifstream::in | std::ifstream::binary);
	if (!f_in.is_open()) {
		std::cerr << "Error of read file: " << name_file << std::endl;
		return;
	}

	if (deep_ == 1) {
		uint8_t value;

		while (true) {
			f_in.read((char *)&value, 1);
			if (!f_in.eof() && !f_in.fail()) {
				frequencies[value] += 1;
			} else {
				frequencies[(uint8_t)EOF] += 1;
				break;
			}
		}
	} else {
		uint8_t pValue[2];
		/* reading the first two bytes */
		f_in.read((char *)pValue, 2);
		if (!f_in.eof() && !f_in.fail()) {
			frequencies[pValue[0] + pValue[1] * 256] += 1;
		} else {
			frequencies[(uint8_t)EOF + ((uint8_t)EOF) * 256] += 1;
			f_in.close();
			return;
		}
		/* reading the rest part */
		while (true) {
			pValue[0] = pValue[1];
			f_in.read((char *)pValue + 1, 1);
			if (!f_in.eof() && !f_in.fail()) {
				frequencies[pValue[0] + pValue[1] * 256] += 1;
			} else {
				frequencies[pValue[0] + ((uint8_t)EOF) * 256] += 1;
				break;
			}
		}
	}

	f_in.close();
	return;
}
}	 // namespace ptrid