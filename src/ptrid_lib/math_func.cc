#include "math_func.h"

namespace ptrid {

long double GetInfoDistance(const ProbabilisticScheme &scheme_numerator,
														const ProbabilisticScheme &scheme_denominator) {
	assert(
			(scheme_numerator.GetDeep() == scheme_denominator.GetDeep()) &&
			"ptrid::GetInfoDistance: probabilistic schemes must have equal deeps.");
	assert(
			(scheme_numerator.GetSizeScheme() ==
			 scheme_denominator.GetSizeScheme()) &&
			"ptrid::GetInfoDistance: probabilistic schemes must have equal sizes.");

	long double info_distance = 0.;
	if (scheme_numerator.GetDeep() == 1) {
		for (size_t i = 0; i < scheme_numerator.GetSizeSet(); i++)
			if (scheme_numerator.GetProbability(i) > 0 &&
					scheme_denominator.GetProbability(i) > 0)
				info_distance += scheme_numerator.GetProbability(i) *
												 (log2l(scheme_numerator.GetProbability(i) /
												 				scheme_denominator.GetProbability(i)));
	} else if (scheme_numerator.GetDeep() == 2) {
		for (size_t i = 0; i < scheme_numerator.GetSizeSet(); i++)
			for (size_t j = 0; j < scheme_numerator.GetSizeSet(); j++)
				if (scheme_numerator.GetProbability(i, j) > 0 &&
						scheme_denominator.GetProbability(i, j) > 0)
					info_distance += scheme_numerator.GetProbability(i, j) *
													 (log2l(scheme_numerator.GetProbability(i, j) /
																	scheme_denominator.GetProbability(i, j)));
	}
	return info_distance;
}

long double GetChi2(const ProbabilisticScheme &scheme_test,
										const ProbabilisticScheme &scheme_theory) {
	assert((scheme_test.GetDeep() == scheme_theory.GetDeep()) &&
				 "GetChi2: probabilistic schemes must have equal deeps.");
	assert((scheme_test.GetSizeScheme() == scheme_theory.GetSizeScheme()) &&
				 "GetChi2: probabilistic schemes must have equal sizes.");

	long double xi2 = 0.;
	if (scheme_test.GetDeep() == 1) {
		for (size_t i = 0; i < scheme_test.GetSizeSet(); i++)
			if (scheme_theory.GetNumerator(i) > 0)
				xi2 += powl(scheme_test.GetNumerator(i) - scheme_theory.GetNumerator(i),
										2) /
							 scheme_theory.GetNumerator(i);
	} else if (scheme_test.GetDeep() == 2) {
		for (size_t i = 0; i < scheme_test.GetSizeSet(); i++)
			for (size_t j = 0; j < scheme_test.GetSizeSet(); j++)
				if (scheme_theory.GetNumerator(i, j) > 0)
					xi2 += powl(scheme_test.GetNumerator(i, j) -
													scheme_theory.GetNumerator(i, j),
											2) /
								 scheme_theory.GetNumerator(i, j);
	}
	return xi2;
}

long double GetEntropy(const ProbabilisticScheme &PS) {
		long double entropy = 0.;
		if (PS.GetDeep() == 1) {
			for (int i = 0; i < 256; i++) {
				if (PS.GetProbability(i) > 0)
					entropy += PS.GetProbability(i) * log2l(PS.GetProbability(i));
				else 
					continue;
			}
		} else if (PS.GetDeep() == 2) {
			for (int i = 0; i < 256; i++)
				for (int j = 0; j < 256; j++)
					if (PS.GetProbability(i, j) > 0)
						entropy += PS.GetProbability(i, j) * log2l(PS.GetProbability(i, j));
					else
						continue;
		}

		return entropy * -1.;
	}

long double GetEntropy(const MarkovChain &MC) {
		long double entropy = 0.;
		for (int i = 0; i < MC.GetSizeSet(); i++) {
			long double condition_entropy = 0.;
			if (MC.GetProbability(i) > 0) {
				for (int j = 0; j < MC.GetSizeSet(); j++) {
					if (MC.GetProbability(i, j) > 0)
						condition_entropy += MC.GetProbability(i, j) *
																log2l(MC.GetProbability(i, j));
					else
						continue;
				}

				entropy += MC.GetProbability(i) * condition_entropy;
			}
			
		}

		return entropy * -1.;
}

}	 // namespace ptrid
