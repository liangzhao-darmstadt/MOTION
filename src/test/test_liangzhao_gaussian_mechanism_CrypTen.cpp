// MIT License
//
// Copyright (c) 2021 Oleksandr Tkachenko, Arianne Roselina Prananto
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <fstream>
#include <random>

#include <gtest/gtest.h>

#include "algorithm/algorithm_description.h"
#include "base/party.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "secure_dp_mechanism/secure_discrete_gaussian_mechanism_CKS.h"
#include "secure_dp_mechanism/secure_discrete_laplace_mechanism_CKS.h"
#include "secure_dp_mechanism/secure_dp_mechanism_PrivaDA.h"
#include "secure_dp_mechanism/secure_gaussian_mechanism_CrypTen.h"
#include "secure_dp_mechanism/secure_integer_scaling_gaussian_mechanism.h"
#include "secure_dp_mechanism/secure_integer_scaling_laplace_mechanism.h"
#include "secure_dp_mechanism/secure_sampling_algorithm_optimized.h"
#include "secure_dp_mechanism/secure_snapping_mechanism.h"
#include "secure_type/secure_unsigned_integer.h"
#include "test_helpers.h"
#include "utility/MOTION_dp_mechanism_helper/discrete_gaussian_mechanism.h"
#include "utility/MOTION_dp_mechanism_helper/dp_mechanism_helper.h"
#include "utility/MOTION_dp_mechanism_helper/integer_scaling_mechanism.h"
#include "utility/MOTION_dp_mechanism_helper/snapping_mechanism.h"
#include "utility/config.h"

#include "test_constants.h"

using namespace encrypto::motion;

namespace {
  
TEST(SecureGaussianMechanismCrypTen, SecureGaussianMechanism_CrypTen_GC_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    // using T_int = get_int_type_t<T>;
    using T_int = std::int64_t;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_gau = 10;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_gau);
      std::size_t fixed_point_bit_size = 64;
      std::size_t fixed_point_fraction_bit_size = 16;

      // only for debugging
      // std::cout << "fD_vector: " << std::endl;
      // for (std::size_t i = 0; i < fD_vector.size(); ++i) {
      //   std::cout << fD_vector[i] << std::endl;
      // }

      std::vector<double> random_floating_point_0_1_u1_vector =
          rand_range_double_vector(0, 1, num_of_simd_gau);

      std::vector<double> random_floating_point_0_1_u2_vector =
          rand_range_double_vector(0, 1, num_of_simd_gau);

      // only for debugging
      std::cout << "random_floating_point_0_1_u1_vector" << std::endl;
      for (std::size_t i = 0; i < num_of_simd_gau; i++) {
        std::cout << random_floating_point_0_1_u1_vector[i] << std::endl;
      }
      std::cout << "random_floating_point_0_1_u2_vector" << std::endl;
      for (std::size_t i = 0; i < num_of_simd_gau; i++) {
        std::cout << random_floating_point_0_1_u2_vector[i] << std::endl;
      }

      double sensitivity = 1;
      double mu = 0;
      double sigma = 1;

      std::vector<double> expect_gau_result(2 * num_of_simd_gau);
      for (std::size_t i = 0; i < num_of_simd_gau; i++) {
        expect_gau_result[2 * i] =
            gaussian_distribution_box_muller(mu, sigma, random_floating_point_0_1_u1_vector[i],
                                             random_floating_point_0_1_u2_vector[i])[0];
        expect_gau_result[2 * i + 1] =
            gaussian_distribution_box_muller(mu, sigma, random_floating_point_0_1_u1_vector[i],
                                             random_floating_point_0_1_u2_vector[i])[1];
      }

      //   std::cout << "after plaintext"<< std::endl;

      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(std::mt19937{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point32_0_1_u1_vector(
              num_of_simd_gau);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point32_0_1_u2_vector(
              num_of_simd_gau);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point64_0_1_u1_vector(
              num_of_simd_gau);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point64_0_1_u2_vector(
              num_of_simd_gau);
          for (std::size_t i = 0; i < num_of_simd_gau; i++) {
            share_random_floating_point32_0_1_u1_vector[i] =
                motion_parties.at(party_id)->In<kGarbledCircuit>(
                    ToInput<float, std::true_type>(float(random_floating_point_0_1_u1_vector[i])),
                    0);
            share_random_floating_point32_0_1_u2_vector[i] =
                motion_parties.at(party_id)->In<kGarbledCircuit>(
                    ToInput<float, std::true_type>(float(random_floating_point_0_1_u2_vector[i])),
                    0);
            share_random_floating_point64_0_1_u1_vector[i] =
                motion_parties.at(party_id)->In<kGarbledCircuit>(
                    ToInput<double, std::true_type>(random_floating_point_0_1_u1_vector[i]), 0);
            share_random_floating_point64_0_1_u2_vector[i] =
                motion_parties.at(party_id)->In<kGarbledCircuit>(
                    ToInput<double, std::true_type>(random_floating_point_0_1_u2_vector[i]), 0);
          }
          encrypto::motion::ShareWrapper share_fD =
              motion_parties.at(party_id)->In<kGarbledCircuit>(ToInput<T>(fD_vector), 0);

          SecureGaussianMechanism_CrypTen secure_gaussian_mechanism =
              SecureGaussianMechanism_CrypTen(share_fD);
          secure_gaussian_mechanism.ParameterSetup(sensitivity, mu, sigma, num_of_simd_gau,
                                                   fixed_point_bit_size,
                                                   fixed_point_fraction_bit_size);

          //   std::cout << "after parameter setup" << std::endl;

          SecureFloatingPointCircuitABY floating_point32_gaussian_noise =
              secure_gaussian_mechanism.FL32GaussianNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_u1_vector),
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_u2_vector));
          SecureFloatingPointCircuitABY floating_point64_gaussian_noise =
              secure_gaussian_mechanism.FL64GaussianNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_u1_vector),
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_u2_vector));

          SecureFloatingPointCircuitABY floating_point32_gaussian_noise_out =
              floating_point32_gaussian_noise.Out();
          SecureFloatingPointCircuitABY floating_point64_gaussian_noise_out =
              floating_point64_gaussian_noise.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();
          std::cout << "party finish" << std::endl;

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<float> floating_point32_gaussian_noise_out_as =
                floating_point32_gaussian_noise_out.AsFloatingPointVector<float>();
            std::vector<double> floating_point64_gaussian_noise_out_as =
                floating_point64_gaussian_noise_out.AsFloatingPointVector<double>();

            for (std::size_t i = 0; i < num_of_simd_gau; ++i) {
              std::cout << "expect_gau_result[2 * i]: " << expect_gau_result[2 * i] << std::endl;
              std::cout << "expect_gau_result[2 * i + 1]: " << expect_gau_result[2 * i + 1]
                        << std::endl;
              std::cout << "floating_point32_gaussian_noise_out_as[i]: "
                        << floating_point32_gaussian_noise_out_as[i] << std::endl;
              std::cout << "floating_point64_gaussian_noise_out_as[i]: "
                        << floating_point64_gaussian_noise_out_as[i] << std::endl;

              double abs_error = 0.01;
              EXPECT_NEAR(expect_gau_result[2 * i], floating_point32_gaussian_noise_out_as[i],
                          abs_error);
              EXPECT_NEAR(expect_gau_result[2 * i], floating_point64_gaussian_noise_out_as[i],
                          abs_error);
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(SecureGaussianMechanismCrypTen, SecureGaussianMechanism_CrypTen_BGMW_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    // using T_int = get_int_type_t<T>;
    using T_int = std::int64_t;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_gau = 10;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_gau);
      std::size_t fixed_point_bit_size = 64;
      std::size_t fixed_point_fraction_bit_size = 16;

      // only for debugging
      // std::cout << "fD_vector: " << std::endl;
      // for (std::size_t i = 0; i < fD_vector.size(); ++i) {
      //   std::cout << fD_vector[i] << std::endl;
      // }

      std::vector<double> random_floating_point_0_1_u1_vector =
          rand_range_double_vector(0, 1, num_of_simd_gau);

      std::vector<double> random_floating_point_0_1_u2_vector =
          rand_range_double_vector(0, 1, num_of_simd_gau);

      // only for debugging
      std::cout << "random_floating_point_0_1_u1_vector" << std::endl;
      for (std::size_t i = 0; i < num_of_simd_gau; i++) {
        std::cout << random_floating_point_0_1_u1_vector[i] << std::endl;
      }
      std::cout << "random_floating_point_0_1_u2_vector" << std::endl;
      for (std::size_t i = 0; i < num_of_simd_gau; i++) {
        std::cout << random_floating_point_0_1_u2_vector[i] << std::endl;
      }

      double sensitivity = 1;
      double mu = 0;
      double sigma = 1;

      std::vector<double> expect_gau_result(2 * num_of_simd_gau);
      for (std::size_t i = 0; i < num_of_simd_gau; i++) {
        expect_gau_result[2 * i] =
            gaussian_distribution_box_muller(mu, sigma, random_floating_point_0_1_u1_vector[i],
                                             random_floating_point_0_1_u2_vector[i])[0];
        expect_gau_result[2 * i + 1] =
            gaussian_distribution_box_muller(mu, sigma, random_floating_point_0_1_u1_vector[i],
                                             random_floating_point_0_1_u2_vector[i])[1];
      }

      //   std::cout << "after plaintext"<< std::endl;

      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(std::mt19937{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point32_0_1_u1_vector(
              num_of_simd_gau);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point32_0_1_u2_vector(
              num_of_simd_gau);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point64_0_1_u1_vector(
              num_of_simd_gau);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point64_0_1_u2_vector(
              num_of_simd_gau);
          for (std::size_t i = 0; i < num_of_simd_gau; i++) {
            share_random_floating_point32_0_1_u1_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<float, std::true_type>(float(random_floating_point_0_1_u1_vector[i])),
                    0);
            share_random_floating_point32_0_1_u2_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<float, std::true_type>(float(random_floating_point_0_1_u2_vector[i])),
                    0);
            share_random_floating_point64_0_1_u1_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<double, std::true_type>(random_floating_point_0_1_u1_vector[i]), 0);
            share_random_floating_point64_0_1_u2_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<double, std::true_type>(random_floating_point_0_1_u2_vector[i]), 0);
          }
          encrypto::motion::ShareWrapper share_fD =
              motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<T>(fD_vector), 0);

          SecureGaussianMechanism_CrypTen secure_gaussian_mechanism =
              SecureGaussianMechanism_CrypTen(share_fD);
          secure_gaussian_mechanism.ParameterSetup(sensitivity, mu, sigma, num_of_simd_gau,
                                                   fixed_point_bit_size,
                                                   fixed_point_fraction_bit_size);

          //   std::cout << "after parameter setup" << std::endl;

          SecureFloatingPointCircuitABY floating_point32_gaussian_noise =
              secure_gaussian_mechanism.FL32GaussianNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_u1_vector),
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_u2_vector));
          SecureFloatingPointCircuitABY floating_point64_gaussian_noise =
              secure_gaussian_mechanism.FL64GaussianNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_u1_vector),
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_u2_vector));

          SecureFloatingPointCircuitABY floating_point32_gaussian_noise_out =
              floating_point32_gaussian_noise.Out();
          SecureFloatingPointCircuitABY floating_point64_gaussian_noise_out =
              floating_point64_gaussian_noise.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();
          std::cout << "party finish" << std::endl;

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<float> floating_point32_gaussian_noise_out_as =
                floating_point32_gaussian_noise_out.AsFloatingPointVector<float>();
            std::vector<double> floating_point64_gaussian_noise_out_as =
                floating_point64_gaussian_noise_out.AsFloatingPointVector<double>();

            for (std::size_t i = 0; i < num_of_simd_gau; ++i) {
              std::cout << "expect_gau_result[2 * i]: " << expect_gau_result[2 * i] << std::endl;
              std::cout << "expect_gau_result[2 * i + 1]: " << expect_gau_result[2 * i + 1]
                        << std::endl;
              std::cout << "floating_point32_gaussian_noise_out_as[i]: "
                        << floating_point32_gaussian_noise_out_as[i] << std::endl;
              std::cout << "floating_point64_gaussian_noise_out_as[i]: "
                        << floating_point64_gaussian_noise_out_as[i] << std::endl;

              double abs_error = 0.01;
              EXPECT_NEAR(expect_gau_result[2 * i], floating_point32_gaussian_noise_out_as[i],
                          abs_error);
              EXPECT_NEAR(expect_gau_result[2 * i], floating_point64_gaussian_noise_out_as[i],
                          abs_error);
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(SecureGaussianMechanismCrypTen, SecureGaussianMechanism_CrypTen_BMR_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    // using T_int = get_int_type_t<T>;
    using T_int = std::int64_t;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_gau = 10;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_gau);
      std::size_t fixed_point_bit_size = 64;
      std::size_t fixed_point_fraction_bit_size = 16;

      // only for debugging
      // std::cout << "fD_vector: " << std::endl;
      // for (std::size_t i = 0; i < fD_vector.size(); ++i) {
      //   std::cout << fD_vector[i] << std::endl;
      // }

      std::vector<double> random_floating_point_0_1_u1_vector =
          rand_range_double_vector(0, 1, num_of_simd_gau);

      std::vector<double> random_floating_point_0_1_u2_vector =
          rand_range_double_vector(0, 1, num_of_simd_gau);

      // only for debugging
      std::cout << "random_floating_point_0_1_u1_vector" << std::endl;
      for (std::size_t i = 0; i < num_of_simd_gau; i++) {
        std::cout << random_floating_point_0_1_u1_vector[i] << std::endl;
      }
      std::cout << "random_floating_point_0_1_u2_vector" << std::endl;
      for (std::size_t i = 0; i < num_of_simd_gau; i++) {
        std::cout << random_floating_point_0_1_u2_vector[i] << std::endl;
      }

      double sensitivity = 1;
      double mu = 0;
      double sigma = 1;

      std::vector<double> expect_gau_result(2 * num_of_simd_gau);
      for (std::size_t i = 0; i < num_of_simd_gau; i++) {
        expect_gau_result[2 * i] =
            gaussian_distribution_box_muller(mu, sigma, random_floating_point_0_1_u1_vector[i],
                                             random_floating_point_0_1_u2_vector[i])[0];
        expect_gau_result[2 * i + 1] =
            gaussian_distribution_box_muller(mu, sigma, random_floating_point_0_1_u1_vector[i],
                                             random_floating_point_0_1_u2_vector[i])[1];
      }

      //   std::cout << "after plaintext"<< std::endl;

      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(std::mt19937{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point32_0_1_u1_vector(
              num_of_simd_gau);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point32_0_1_u2_vector(
              num_of_simd_gau);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point64_0_1_u1_vector(
              num_of_simd_gau);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point64_0_1_u2_vector(
              num_of_simd_gau);
          for (std::size_t i = 0; i < num_of_simd_gau; i++) {
            share_random_floating_point32_0_1_u1_vector[i] =
                motion_parties.at(party_id)->In<kBmr>(
                    ToInput<float, std::true_type>(float(random_floating_point_0_1_u1_vector[i])),
                    0);
            share_random_floating_point32_0_1_u2_vector[i] =
                motion_parties.at(party_id)->In<kBmr>(
                    ToInput<float, std::true_type>(float(random_floating_point_0_1_u2_vector[i])),
                    0);
            share_random_floating_point64_0_1_u1_vector[i] =
                motion_parties.at(party_id)->In<kBmr>(
                    ToInput<double, std::true_type>(random_floating_point_0_1_u1_vector[i]), 0);
            share_random_floating_point64_0_1_u2_vector[i] =
                motion_parties.at(party_id)->In<kBmr>(
                    ToInput<double, std::true_type>(random_floating_point_0_1_u2_vector[i]), 0);
          }
          encrypto::motion::ShareWrapper share_fD =
              motion_parties.at(party_id)->In<kBmr>(ToInput<T>(fD_vector), 0);

          SecureGaussianMechanism_CrypTen secure_gaussian_mechanism =
              SecureGaussianMechanism_CrypTen(share_fD);
          secure_gaussian_mechanism.ParameterSetup(sensitivity, mu, sigma, num_of_simd_gau,
                                                   fixed_point_bit_size,
                                                   fixed_point_fraction_bit_size);

          //   std::cout << "after parameter setup" << std::endl;

          SecureFloatingPointCircuitABY floating_point32_gaussian_noise =
              secure_gaussian_mechanism.FL32GaussianNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_u1_vector),
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_u2_vector));
          SecureFloatingPointCircuitABY floating_point64_gaussian_noise =
              secure_gaussian_mechanism.FL64GaussianNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_u1_vector),
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_u2_vector));

          SecureFloatingPointCircuitABY floating_point32_gaussian_noise_out =
              floating_point32_gaussian_noise.Out();
          SecureFloatingPointCircuitABY floating_point64_gaussian_noise_out =
              floating_point64_gaussian_noise.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();
          std::cout << "party finish" << std::endl;

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<float> floating_point32_gaussian_noise_out_as =
                floating_point32_gaussian_noise_out.AsFloatingPointVector<float>();
            std::vector<double> floating_point64_gaussian_noise_out_as =
                floating_point64_gaussian_noise_out.AsFloatingPointVector<double>();

            for (std::size_t i = 0; i < num_of_simd_gau; ++i) {
              std::cout << "expect_gau_result[2 * i]: " << expect_gau_result[2 * i] << std::endl;
              std::cout << "expect_gau_result[2 * i + 1]: " << expect_gau_result[2 * i + 1]
                        << std::endl;
              std::cout << "floating_point32_gaussian_noise_out_as[i]: "
                        << floating_point32_gaussian_noise_out_as[i] << std::endl;
              std::cout << "floating_point64_gaussian_noise_out_as[i]: "
                        << floating_point64_gaussian_noise_out_as[i] << std::endl;

              double abs_error = 0.01;
              EXPECT_NEAR(expect_gau_result[2 * i], floating_point32_gaussian_noise_out_as[i],
                          abs_error);
              EXPECT_NEAR(expect_gau_result[2 * i], floating_point64_gaussian_noise_out_as[i],
                          abs_error);
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0));
  }
}

// not check correctness of the calculation
// only check if implementation is correct
TEST(SecureGaussianMechanismCrypTen, GaussianNoiseGeneration_BGMW_GC_BMR_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    // using T_int = get_int_type_t<T>;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    std::size_t fixed_point_bit_size = 64;
    std::size_t fixed_point_fraction_bit_size = 16;

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_gau = 1;
      std::vector<T> fD_vector;

      if constexpr (std::is_same_v<T, float>) {
        fD_vector = rand_range_float_vector(0, 5, num_of_simd_gau);
      } else if constexpr (std::is_same_v<T, double>) {
        fD_vector = rand_range_double_vector(0, 5, num_of_simd_gau);
      }

      std::cout << "fD_vector: " << std::endl;
      for (std::size_t i = 0; i < fD_vector.size(); ++i) {
        std::cout << fD_vector[i] << std::endl;
      }

      double sensitivity = 1;
      double mu = 0;
      double sigma = 1;

      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(std::mt19937{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          encrypto::motion::ShareWrapper share_fD_bgmw =
              motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<T, std::true_type>(fD_vector),
                                                           0);
          encrypto::motion::ShareWrapper share_fD_gc =
              motion_parties.at(party_id)->In<kGarbledCircuit>(
                  ToInput<T, std::true_type>(fD_vector), 0);
          encrypto::motion::ShareWrapper share_fD_bmr =
              motion_parties.at(party_id)->In<kBmr>(ToInput<T, std::true_type>(fD_vector), 0);

          SecureGaussianMechanism_CrypTen secure_gaussian_mechanism_CrypTen_bgmw =
              SecureGaussianMechanism_CrypTen(share_fD_bgmw);
          secure_gaussian_mechanism_CrypTen_bgmw.ParameterSetup(
              sensitivity, mu, sigma, num_of_simd_gau, fixed_point_bit_size,
              fixed_point_fraction_bit_size);
          SecureGaussianMechanism_CrypTen secure_gaussian_mechanism_CrypTen_gc =
              SecureGaussianMechanism_CrypTen(share_fD_gc);
          secure_gaussian_mechanism_CrypTen_gc.ParameterSetup(sensitivity, mu, sigma,
                                                              num_of_simd_gau, fixed_point_bit_size,
                                                              fixed_point_fraction_bit_size);
          SecureGaussianMechanism_CrypTen secure_gaussian_mechanism_CrypTen_bmr =
              SecureGaussianMechanism_CrypTen(share_fD_bmr);
          secure_gaussian_mechanism_CrypTen_bmr.ParameterSetup(
              sensitivity, mu, sigma, num_of_simd_gau, fixed_point_bit_size,
              fixed_point_fraction_bit_size);

          SecureFloatingPointCircuitABY floating_point_gaussian_noise_bgmw;
          SecureFloatingPointCircuitABY floating_point_gaussian_noise_gc;
          SecureFloatingPointCircuitABY floating_point_gaussian_noise_bmr;

          SecureFloatingPointCircuitABY floating_point_noisy_fD_bgmw;
          SecureFloatingPointCircuitABY floating_point_noisy_fD_gc;
          SecureFloatingPointCircuitABY floating_point_noisy_fD_bmr;

          if constexpr (std::is_same_v<T, float>) {
            floating_point_gaussian_noise_bgmw =
                secure_gaussian_mechanism_CrypTen_bgmw.FL32GaussianNoiseGeneration();
            floating_point_gaussian_noise_gc =
                secure_gaussian_mechanism_CrypTen_gc.FL32GaussianNoiseGeneration();
            floating_point_gaussian_noise_bmr =
                secure_gaussian_mechanism_CrypTen_bmr.FL32GaussianNoiseGeneration();

            floating_point_noisy_fD_bgmw =
                secure_gaussian_mechanism_CrypTen_bgmw.FL32GaussianNoiseAddition();
            floating_point_noisy_fD_gc =
                secure_gaussian_mechanism_CrypTen_gc.FL32GaussianNoiseAddition();
            floating_point_noisy_fD_bmr =
                secure_gaussian_mechanism_CrypTen_bmr.FL32GaussianNoiseAddition();
          } else if constexpr (std::is_same_v<T, double>) {
            floating_point_gaussian_noise_bgmw =
                secure_gaussian_mechanism_CrypTen_bgmw.FL64GaussianNoiseGeneration();
            floating_point_gaussian_noise_gc =
                secure_gaussian_mechanism_CrypTen_gc.FL64GaussianNoiseGeneration();
            floating_point_gaussian_noise_bmr =
                secure_gaussian_mechanism_CrypTen_bmr.FL64GaussianNoiseGeneration();

            floating_point_noisy_fD_bgmw =
                secure_gaussian_mechanism_CrypTen_bgmw.FL64GaussianNoiseAddition();
            floating_point_noisy_fD_gc =
                secure_gaussian_mechanism_CrypTen_gc.FL64GaussianNoiseAddition();
            floating_point_noisy_fD_bmr =
                secure_gaussian_mechanism_CrypTen_bmr.FL64GaussianNoiseAddition();
          }

          SecureFloatingPointCircuitABY floating_point_gaussian_noise_out_bgmw =
              floating_point_gaussian_noise_bgmw.Out();
          SecureFloatingPointCircuitABY floating_point_noisy_fD_out_bgmw =
              floating_point_noisy_fD_bgmw.Out();

          SecureFloatingPointCircuitABY floating_point_gaussian_noise_out_gc =
              floating_point_gaussian_noise_gc.Out();
          SecureFloatingPointCircuitABY floating_point_noisy_fD_out_gc =
              floating_point_noisy_fD_gc.Out();

          SecureFloatingPointCircuitABY floating_point_gaussian_noise_out_bmr =
              floating_point_gaussian_noise_bmr.Out();
          SecureFloatingPointCircuitABY floating_point_noisy_fD_out_bmr =
              floating_point_noisy_fD_bmr.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<T> share_result_0_out_as_bgmw =
                floating_point_gaussian_noise_out_bgmw.AsFloatingPointVector<T>();

            for (std::size_t i = 0; i < share_result_0_out_as_bgmw.size(); ++i) {
              std::cout << "share_result_0_out_as_bgmw[i]: " << T(share_result_0_out_as_bgmw[i])
                        << std::endl;
            }
            std::vector<T> floating_point_noisy_fD_out_as_bgmw =
                floating_point_noisy_fD_out_bgmw.AsFloatingPointVector<T>();

            for (std::size_t i = 0; i < floating_point_noisy_fD_out_as_bgmw.size(); ++i) {
              std::cout << "floating_point_noisy_fD_out_as_bgmw[i]: "
                        << T(floating_point_noisy_fD_out_as_bgmw[i]) << std::endl;
            }

            std::vector<T> share_result_0_out_as_gc =
                floating_point_gaussian_noise_out_gc.AsFloatingPointVector<T>();

            for (std::size_t i = 0; i < share_result_0_out_as_gc.size(); ++i) {
              std::cout << "share_result_0_out_as_gc[i]: " << T(share_result_0_out_as_gc[i])
                        << std::endl;
            }
            std::vector<T> floating_point_noisy_fD_out_as_gc =
                floating_point_noisy_fD_out_gc.AsFloatingPointVector<T>();

            for (std::size_t i = 0; i < floating_point_noisy_fD_out_as_gc.size(); ++i) {
              std::cout << "floating_point_noisy_fD_out_as_gc[i]: "
                        << T(floating_point_noisy_fD_out_as_gc[i]) << std::endl;
            }

            std::vector<T> share_result_0_out_as_bmr =
                floating_point_gaussian_noise_out_bmr.AsFloatingPointVector<T>();

            for (std::size_t i = 0; i < share_result_0_out_as_bmr.size(); ++i) {
              std::cout << "share_result_0_out_as_bmr[i]: " << T(share_result_0_out_as_bmr[i])
                        << std::endl;
            }
            std::vector<T> floating_point_noisy_fD_out_as_bmr =
                floating_point_noisy_fD_out_bmr.AsFloatingPointVector<T>();

            for (std::size_t i = 0; i < floating_point_noisy_fD_out_as_bmr.size(); ++i) {
              std::cout << "floating_point_noisy_fD_out_as_bmr[i]: "
                        << T(floating_point_noisy_fD_out_as_bmr[i]) << std::endl;
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<float>(0));
    template_test(static_cast<double>(0));
  }
}

}  // namespace
