#pragma once

#include <assert.h>
#include <stdint.h>
#include <math.h>

#include <iostream>
#include <vector>

#include "markov_chain.h"
#include "probabilistic_scheme.h"

namespace ptrid {

long double GetInfoDistance(const ProbabilisticScheme &scheme_numerator,
														const ProbabilisticScheme &scheme_denominator);

long double GetChi2(const ProbabilisticScheme &scheme_test,
										const ProbabilisticScheme &scheme_theory);

long double GetEntropy(const ProbabilisticScheme &PS);

long double GetEntropy(const MarkovChain &MC);

}