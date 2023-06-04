#include "probabilistic_scheme.h"

namespace ptrid {

ProbabilisticScheme::ProbabilisticScheme(const ProbabilisticScheme &other) {
	deep_ = other.deep_;
	scheme_ = other.scheme_;
	numerators_ = other.numerators_;
	denominator_ = other.denominator_;
	size_base_set_ = other.size_base_set_;
}

ProbabilisticScheme::ProbabilisticScheme(const ProbabilisticScheme &&other) {
	deep_ = other.deep_;
	scheme_ = std::move(other.scheme_);
	numerators_ = std::move(other.numerators_);
	denominator_ = other.denominator_;
	size_base_set_ = other.size_base_set_;
}

ProbabilisticScheme &ProbabilisticScheme::operator=(
		const ProbabilisticScheme &other) {
	deep_ = other.deep_;
	scheme_ = other.scheme_;
	numerators_ = other.numerators_;
	denominator_ = other.denominator_;
	size_base_set_ = other.size_base_set_;
	return *this;
}

ProbabilisticScheme &ProbabilisticScheme::operator=(
		const ProbabilisticScheme &&other) {
	deep_ = other.deep_;
	scheme_ = std::move(other.scheme_);
	numerators_ = std::move(other.numerators_);
	denominator_ = other.denominator_;
	size_base_set_ = other.size_base_set_;
	return *this;
}

void ProbabilisticScheme::Create(uint8_t deep, size_t size_base_set,
																 std::vector<uint32_t> frequencies) {
	deep_ = deep;
	size_base_set_ = size_base_set;
	scheme_.resize(frequencies.size());
	numerators_.resize(frequencies.size());
	uint32_t sum = 0;
	for (int i = 0; i < frequencies.size(); i++) {
		numerators_[i] = frequencies[i];
		sum += frequencies[i];
	}
	denominator_ = sum;
	CreateProbabilities();
}

long double ProbabilisticScheme::GetProbability(size_t i, size_t j) const {
	assert((i < size_base_set_ && j < size_base_set_) &&
				 "ptrid::ProbabilisticScheme::GetProbability: indexes out of bounds.");
	if (deep_ == 2)
		return scheme_[i + j * size_base_set_];
	else
		throw std::runtime_error(
				"ptrid::ProbabilisticScheme::GetProbability for using "
				"GetProbability(size_t, "
				"size_t) need have deep equal of two");
}

long double ProbabilisticScheme::GetProbability(size_t i) const {
	assert((i < size_base_set_) &&
				 "ptrid::ProbabilisticScheme::GetProbability: indexes out of bounds.");
	if (deep_ == 1) {
		return scheme_[i];
	} else {
		long double prob = 0.;
		for (int j = 0; j < size_base_set_; j++)
			prob += scheme_[i + j * size_base_set_];
		return prob;
	}
}

long double ProbabilisticScheme::GetNumerator(size_t i, size_t j) const {
	assert((i < size_base_set_ && j < size_base_set_) &&
				 "ptrid::ProbabilisticScheme::GetProbability: indexes out of bounds.");
	if (deep_ == 2)
		return numerators_[i + j * size_base_set_];
	else
		throw std::runtime_error(
				"ptrid::ProbabilisticSchemeBytes: for using GetNumerator(size_t, "
				"size_t) need have deep equal of two");
}

long double ProbabilisticScheme::GetNumerator(size_t i) const {
	assert((i < size_base_set_) &&
				 "ptrid::ProbabilisticScheme::GetProbability: indexes out of bounds.");
	if (deep_ == 1) {
		return numerators_[i];
	} else {
		long double num = 0.;
		for (int j = 0; j < size_base_set_; j++)
			num += numerators_[i + j * size_base_set_];
		return num;
	}
}

void ProbabilisticScheme::useAdditiveSmoothing(long double koef) {
	denominator_ = 0;
	for (int i = 0; i < scheme_.size(); i++) {
		if (numerators_[i] > 0)
			numerators_[i] *= koef;
		else
			numerators_[i] += 1;
		denominator_ += numerators_[i];
	}
	for (int i = 0; i < scheme_.size(); i++)
		scheme_[i] = numerators_[i] / denominator_;
}

}	 // namespace ptrid
