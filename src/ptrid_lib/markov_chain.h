#pragma once

#include <assert.h>
#include <stdint.h>

#include <iostream>
#include <vector>

#include "probabilistic_scheme.h"

namespace ptrid {

class MarkovChain {
 private:
	std::vector<std::vector<long double>> matrix_;
	ptrid::ProbabilisticScheme original_scheme_;

 public:
	MarkovChain() {
		ptrid::ProbabilisticScheme scheme(2, 1, std::vector<uint32_t>({1}));
		original_scheme_ = std::move(scheme);
		matrix_.push_back(std::vector<long double>({1.}));
	}

	MarkovChain(const ptrid::ProbabilisticScheme &scheme_deep_2) {
		Create(scheme_deep_2);
	}

	MarkovChain(const MarkovChain &other) {
		matrix_ = other.matrix_;
		original_scheme_ = other.original_scheme_;
	}

	MarkovChain(const MarkovChain &&other) {
		matrix_ = std::move(other.matrix_);
		original_scheme_ = std::move(other.original_scheme_);
	}

	MarkovChain &operator=(const MarkovChain &other) {
		matrix_ = other.matrix_;
		original_scheme_ = other.original_scheme_;
		return *this;
	}

	MarkovChain &operator=(const MarkovChain &&other) {
		matrix_ = std::move(other.matrix_);
		original_scheme_ = std::move(other.original_scheme_);
		return *this;
	}

	void Create(const ptrid::ProbabilisticScheme &scheme_deep_2);

	long double GetProbability(size_t from, size_t to)  const {
		assert(
				(from < matrix_.size() && to < matrix_.size()) &&
				"ptrid::MarkovChain::GetProbability: @from or @to is out of bounds.");
		return matrix_[from][to];
	}

	long double GetProbability(size_t condition)  const {
		assert((condition < matrix_.size()) &&
					 "ptrid::MarkovChain::GetProbability: @condition is out of bounds.");
		return original_scheme_.GetProbability(condition);
	}

	size_t GetSizeSet()  const { return matrix_.size(); }

	void useAdditiveSmoothing(long double koef = 10.);
};

}	 // namespace ptrid
