#include "markov_chain.h"


namespace ptrid {

void MarkovChain::Create(const ptrid::ProbabilisticScheme &scheme_deep_2) {
	if (scheme_deep_2.GetDeep() != 2)
		throw std::invalid_argument(
				"ptrid::MarkovChain::Create: @scheme_deep_2 must has deep equal 2");

	original_scheme_ = scheme_deep_2;
	auto size_base_set = scheme_deep_2.GetSizeSet();
	matrix_.resize(size_base_set);
	for (size_t i = 0; i < size_base_set; i++) {
		matrix_[i].resize(size_base_set);
		for (int j = 0; j < 256; j++) {
			if (scheme_deep_2.GetProbability(i, j) < 1e-10) {
				matrix_[i][j] = 0;
				continue;
			}
			matrix_[i][j] =
					scheme_deep_2.GetProbability(i, j) / scheme_deep_2.GetProbability(i);
		}
	}
}

void MarkovChain::useAdditiveSmoothing(long double koef) {
	original_scheme_.useAdditiveSmoothing(koef);
	for (int i = 0; i < original_scheme_.GetSizeSet(); i++)
		for (int j = 0; j < original_scheme_.GetSizeSet(); j++)
			matrix_[i][j] = original_scheme_.GetProbability(i, j) /
											original_scheme_.GetProbability(i);
}

}	 // namespace ptrid
