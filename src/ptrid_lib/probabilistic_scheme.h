#pragma once

#include <assert.h>
#include <stdint.h>

#include <iostream>
#include <vector>

namespace ptrid {

class ProbabilisticScheme {
 protected:
	uint8_t deep_ = 0;
	std::vector<long double> scheme_;
	std::vector<long double> numerators_;
	long double denominator_ = 0.;
	size_t size_base_set_ = 0;

	void CreateProbabilities() {
		for (int i = 0; i < scheme_.size(); i++)
			scheme_[i] = numerators_[i] / denominator_;
	}

 public:
	ProbabilisticScheme() {
		deep_ = 1;
		size_base_set_ = 1;
		scheme_.push_back(1.);
		numerators_.push_back(1.);
		denominator_ = 1.;
	}

	ProbabilisticScheme(uint8_t deep, size_t size_base_set,
											std::vector<uint32_t> frequencies) {
		Create(deep, size_base_set, frequencies);
	}

	ProbabilisticScheme(const ProbabilisticScheme &other);

	ProbabilisticScheme(const ProbabilisticScheme &&other);

	ProbabilisticScheme &operator=(const ProbabilisticScheme &other);

	ProbabilisticScheme &operator=(const ProbabilisticScheme &&other);

	void Create(uint8_t deep, size_t size_base_set,
							std::vector<uint32_t> frequencies);

	long double GetDenominator() const { return denominator_; }

	uint8_t GetDeep() const { return deep_; }

	size_t GetSizeScheme() const { return scheme_.size(); }

	size_t GetSizeSet() const { return size_base_set_; }

	long double GetProbability(size_t i, size_t j) const;

	long double GetProbability(size_t i) const;

	long double GetNumerator(size_t i, size_t j) const;

	long double GetNumerator(size_t i) const;

	void useAdditiveSmoothing(long double koef = 10.);
};

}	 // namespace ptrid
