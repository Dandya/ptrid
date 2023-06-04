#pragma once

#include <assert.h>
#include <stdint.h>
#include <sys/stat.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/base_object.hpp>
#include <boost/serialization/vector.hpp>

namespace ptrid {

// Abstract class
class ReaderBytes {
	friend class boost::serialization::access;

 protected:
	int8_t deep_ = 0;
	std::vector<uint32_t> frequencies_;
	
	std::string GetNameOfDump(const std::string &path, uint32_t type);

	bool IsDump(const std::string &path);

	bool CheckExistingDump(const std::string &path_to_dump);

	void ReadFrequenciesFromDump(const std::string &path_to_dump, std::vector<uint32_t> &dst);

	void WriteFrequenciesToDump(const std::string &path_to_dump, std::vector<uint32_t> &src);

	void ReadFile(const std::string &name_file, std::vector<uint32_t> &dst);

	void ReadDirectory(const std::string &name_dir);

	void ReadData(const std::string &name_file, std::vector<uint32_t> &frequencies);

 public:

	static int32_t CheckTypeOfFile(const std::string &name_file);
	
	ReaderBytes(const int8_t deep) {
		assert((deep == 1 || deep == 2) && "ptrid::ReaderBytes: Unsupported deep.");
		deep_ = deep;
		frequencies_.resize((deep_ == 2) ? 65536 : 256, 0);
	}

	ReaderBytes(const ReaderBytes &other) {
		this->deep_ = other.deep_;
		this->frequencies_ = other.frequencies_;
	}

	ReaderBytes(const ReaderBytes &&other) {
		this->deep_ = other.deep_;
		this->frequencies_ = std::move(other.frequencies_);
	}

	ReaderBytes &operator=(const ReaderBytes &other) {
		this->deep_ = other.deep_;
		this->frequencies_ = other.frequencies_;
		return *this;
	}

	ReaderBytes &operator=(const ReaderBytes &&other) {
		this->deep_ = other.deep_;
		this->frequencies_ = std::move(other.frequencies_);
		return *this;
	}

	void Read(const std::string &name_source);

	void Read(const uint8_t *data, size_t len);

	std::vector<uint32_t> GetFrequencies() {
		return frequencies_;
	}

	uint8_t GetDeep() { return deep_; }

	uint32_t GetFrequency(size_t i) {
		assert((i < frequencies_.size()) &&
					 "ReaderBytes: going beyond the boundaries of the std::vector.");
		return frequencies_[i];
	}

	uint64_t GetCountElements() {
		uint64_t count = 0;
		for (size_t i = 0; i < frequencies_.size(); i++)
			count += frequencies_[i];
		return count;
	}

	uint32_t GetSizeSet() { return 256; }

	void Clean() {
		for (size_t i = 0; i < frequencies_.size(); i++) frequencies_[i] = 0;
	}

};

}	 // namespace ptrid
