#include <gtest/gtest.h>

#include "../src/ptrid_lib/readers.h"
#include "../src/ptrid_lib/probabilistic_scheme.h"
#include "../src/ptrid_lib/markov_chain.h"
#include "../src/ptrid_lib/math_func.h"

TEST(ReaderBytesTests, CreateReader) {
	ptrid::ReaderBytes reader1(1);
	ptrid::ReaderBytes reader2(2);

	EXPECT_EQ(256, reader1.GetFrequencies().size());
	EXPECT_EQ(256, reader1.GetSizeSet());
	EXPECT_EQ(256 * 256, reader2.GetFrequencies().size());
	EXPECT_EQ(256, reader2.GetSizeSet());

	ptrid::ReaderBytes reader3 = reader1;
	EXPECT_EQ(reader1.GetFrequencies(), reader3.GetFrequencies());
	reader3.Read("../test/files_for_simple_tests/empty.txt");
	EXPECT_NE(reader1.GetFrequencies(), reader3.GetFrequencies());
}

TEST(ReaderBytesTests, ReadEmptyFile) {
	ptrid::ReaderBytes reader1(1);
	ptrid::ReaderBytes reader2(2);

	reader1.Read("../test/files_for_simple_tests/empty.txt");
	reader2.Read("../test/files_for_simple_tests/empty.txt");

	std::vector<uint32_t> result1, result2;

	result1.resize(256, 0);
	result1[(uint8_t)EOF] = 1;
	EXPECT_EQ(result1, reader1.GetFrequencies());
	EXPECT_EQ(1, reader1.GetCountElements());

	result2.resize(65536, 0);
	result2[(uint8_t)EOF + ((uint8_t)EOF) * reader2.GetSizeSet()] = 1;
	EXPECT_EQ(result2, reader2.GetFrequencies());
	EXPECT_EQ(1, reader2.GetCountElements());
}

TEST(ReaderBytesTests, ReadFile) {
	ptrid::ReaderBytes reader1(1);
	ptrid::ReaderBytes reader2(2);

	reader1.Read("../test/files_for_simple_tests/10a.txt");
	reader2.Read("../test/files_for_simple_tests/10a.txt");

	std::vector<uint32_t> result1, result2;

	result1.resize(256, 0);
	result1['a'] = 10;
	result1[(uint8_t)EOF] = 1;
	EXPECT_EQ(result1, reader1.GetFrequencies());
	EXPECT_EQ(11, reader1.GetCountElements());

	result2.resize(65536, 0);
	result2['a' + 'a' * reader2.GetSizeSet()] = 9;
	result2['a' + ((uint8_t)EOF) * reader2.GetSizeSet()] = 1;
	EXPECT_EQ(result2, reader2.GetFrequencies());
	EXPECT_EQ(10, reader2.GetCountElements());

	uint32_t sum = 0;
	for(auto freq: reader1.GetFrequencies()) {
		sum += freq;
	}
	EXPECT_EQ(reader1.GetCountElements(), sum);
	sum = 0;
	for(auto freq: reader2.GetFrequencies()) {
		sum += freq;
	}
	EXPECT_EQ(reader2.GetCountElements(), sum);
}

TEST(ReaderBytesTests, ReadDirectory) {
	ptrid::ReaderBytes reader1(1);
	ptrid::ReaderBytes reader2(2);

	reader1.Read("../test/files_for_simple_tests/dir");
	reader2.Read("../test/files_for_simple_tests/dir");

	std::vector<uint32_t> result1, result2;

	result1.resize(256, 0);
	result1['a'] = 10;
	result1['b'] = 5;
	result1[(uint8_t)EOF] = 2;
	EXPECT_EQ(result1, reader1.GetFrequencies());
	EXPECT_EQ(17, reader1.GetCountElements());

	result2.resize(65536, 0);
	result2['a' + 'a' * reader2.GetSizeSet()] = 9;
	result2['a' + ((uint8_t)EOF) * reader2.GetSizeSet()] = 1;
	result2['b' + 'b' * reader2.GetSizeSet()] = 4;
	result2['b' + ((uint8_t)EOF) * reader2.GetSizeSet()] = 1;
	EXPECT_EQ(result2, reader2.GetFrequencies());
	EXPECT_EQ(15, reader2.GetCountElements());
}

TEST(ProbabilisticSchemeTests, FromEmptyFile) {
	ptrid::ReaderBytes reader1(1);
	ptrid::ReaderBytes reader2(2);

	reader1.Read("../test/files_for_simple_tests/empty.txt");
	reader2.Read("../test/files_for_simple_tests/empty.txt");

	ptrid::ProbabilisticScheme scheme1(reader1.GetDeep(), reader1.GetSizeSet(), reader1.GetFrequencies());
	ptrid::ProbabilisticScheme scheme2(reader2.GetDeep(), reader2.GetSizeSet(), reader2.GetFrequencies());

	EXPECT_TRUE(1. - scheme1.GetProbability((uint8_t)EOF) < 1e-10);
	EXPECT_TRUE(1. - scheme2.GetProbability((uint8_t)EOF, (uint8_t)EOF) < 1e-10);

	long double sum = 0.;
	for(int i = 0; i < scheme1.GetSizeSet(); i++) {
		sum += scheme1.GetProbability(i);
	}
	EXPECT_TRUE(1. - sum < 1e-10);
	sum = 0.;
	for(int i = 0; i < scheme2.GetSizeSet(); i++) {
		for(int j = 0; j < scheme2.GetSizeSet(); j++) {
			sum += scheme2.GetProbability(i, j);
		}
	}
	EXPECT_TRUE(1. - sum < 1e-10);
}

TEST(ProbabilisticSchemeTests, FromFile) {
	ptrid::ReaderBytes reader1(1);
	ptrid::ReaderBytes reader2(2);

	reader1.Read("../test/files_for_simple_tests/10a.txt");
	reader2.Read("../test/files_for_simple_tests/10a.txt");

	ptrid::ProbabilisticScheme scheme1(reader1.GetDeep(), reader1.GetSizeSet(), reader1.GetFrequencies());
	ptrid::ProbabilisticScheme scheme2(reader2.GetDeep(), reader2.GetSizeSet(), reader2.GetFrequencies());

	EXPECT_EQ(10., scheme1.GetNumerator('a'));
	EXPECT_EQ(9., scheme2.GetNumerator('a', 'a'));

	long double sum = 0.;
	for(int i = 0; i < scheme1.GetSizeSet(); i++) {
		sum += scheme1.GetProbability(i);
	}
	EXPECT_TRUE(1. - sum < 1e-10);
	sum = 0.;
	for(int i = 0; i < scheme2.GetSizeSet(); i++) {
		for(int j = 0; j < scheme2.GetSizeSet(); j++) {
			sum += scheme2.GetProbability(i, j);
		}
	}
	EXPECT_TRUE(1. - sum < 1e-10);
}

TEST(ProbabilisticSchemeTests, FromDirectory) {
	ptrid::ReaderBytes reader1(1);
	ptrid::ReaderBytes reader2(2);

	reader1.Read("../test/files_for_simple_tests/dir");
	reader2.Read("../test/files_for_simple_tests/dir");

	ptrid::ProbabilisticScheme scheme1(reader1.GetDeep(), reader1.GetSizeSet(), reader1.GetFrequencies());
	ptrid::ProbabilisticScheme scheme2(reader2.GetDeep(), reader2.GetSizeSet(), reader2.GetFrequencies());

	EXPECT_TRUE(5. - scheme1.GetNumerator('b') < 1e-10);
	EXPECT_TRUE(9. - scheme2.GetNumerator('a', 'a') < 1e-10);

	long double sum = 0.;
	for(int i = 0; i < scheme1.GetSizeSet(); i++) {
		sum += scheme1.GetProbability(i);
	}
	EXPECT_TRUE(1. - sum < 1e-10);
	sum = 0.;
	for(int i = 0; i < scheme2.GetSizeSet(); i++) {
		for(int j = 0; j < scheme2.GetSizeSet(); j++) {
			sum += scheme2.GetProbability(i, j);
		}
	}
	EXPECT_TRUE(1. - sum < 1e-10);
}

TEST(MarkovChainTests, Create) {
	ptrid::ReaderBytes reader(2);
	
	reader.Read("../test/files_for_simple_tests/dir");
	ptrid::ProbabilisticScheme scheme(2, 256, reader.GetFrequencies());

	ptrid::MarkovChain chain(scheme);
	
	for (int i = 0; i < chain.GetSizeSet(); i++)
	{
		long double sum = 0.;
		for (int j = 0; j < chain.GetSizeSet(); j++)
		{
			sum += chain.GetProbability(i, j);
		}
		EXPECT_TRUE(1 - sum < 1e-10 || sum < 1e-10);
	}
}

TEST(MarkovChainTests, Smoothing) {
	ptrid::ReaderBytes reader(2);
	
	reader.Read("../test/files_for_simple_tests/dir");
	ptrid::ProbabilisticScheme scheme(2, 256, reader.GetFrequencies());
	ptrid::MarkovChain chain(scheme);
	chain.useAdditiveSmoothing();
	for (int i = 0; i < chain.GetSizeSet(); i++)
	{
		long double sum = 0.;
		for (int j = 0; j < chain.GetSizeSet(); j++)
		{
			sum += chain.GetProbability(i, j);
		}
		EXPECT_TRUE(1 - sum < 1e-10);
	}
}

TEST(InfoDistanceTests, DeepOne) {
	ptrid::ProbabilisticScheme scheme_numerator((uint8_t)1, (size_t)5, std::vector<uint32_t>({3, 5, 2, 0, 0}));
	ptrid::ProbabilisticScheme scheme_denominator((uint8_t)1, (size_t)5, std::vector<uint32_t>({5, 3, 1, 0, 1}));

	EXPECT_NEAR(0.3, ptrid::GetInfoDistance(scheme_numerator, scheme_denominator), 1e-1);
}

TEST(InfoDistanceTests, DeepTwo) {
	ptrid::ProbabilisticScheme scheme_numerator((uint8_t)2, (size_t)2, std::vector<uint32_t>({3, 5, 2, 0}));
	ptrid::ProbabilisticScheme scheme_denominator((uint8_t)2, (size_t)2, std::vector<uint32_t>({5, 3, 1, 1}));

	EXPECT_NEAR(0.3, ptrid::GetInfoDistance(scheme_numerator, scheme_denominator), 1e-1);
}

TEST(ChiTwoTests, DeepOne) {
	ptrid::ProbabilisticScheme scheme_numerator((uint8_t)1, (size_t)5, std::vector<uint32_t>({3, 5, 2, 0, 0}));
	ptrid::ProbabilisticScheme scheme_denominator((uint8_t)1, (size_t)5, std::vector<uint32_t>({5, 3, 1, 0, 1}));

	EXPECT_NEAR(4.13, ptrid::GetChi2(scheme_numerator, scheme_denominator), 1e-2);
}

TEST(ChiTwoTests, DeepTwo) {
	ptrid::ProbabilisticScheme scheme_numerator((uint8_t)2, (size_t)2, std::vector<uint32_t>({3, 5, 2, 0}));
	ptrid::ProbabilisticScheme scheme_denominator((uint8_t)2, (size_t)2, std::vector<uint32_t>({5, 3, 1, 1}));

	EXPECT_NEAR(4.13, ptrid::GetChi2(scheme_numerator, scheme_denominator), 1e-2);
}