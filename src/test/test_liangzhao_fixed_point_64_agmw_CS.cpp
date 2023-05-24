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
#include "secure_type/secure_fixed_point_64_agmw_CS.h"
#include "utility/config.h"

#include "test_constants.h"
#include "test_helpers.h"
#include "utility/MOTION_dp_mechanism_helper/print_uint128_t.h"

using namespace encrypto::motion;

namespace {

// only test if SecureFixedPointAgmwCS wrap fixed-point arithmetic correctly, the test may fail as
// fixed-point operation is less accurate than double precision floating point operation. intensive
// test is in "test_liangzhao_FxAdd_FxSub_FxMul_FxDivSimple_FxDiv_FxExp2_FxLog2_FxSqrt.cpp"
template <typename T>
class SecureFixedPointAgmwCSTest : public ::testing::Test {};
using all_fixed_point = ::testing::Types<std::uint64_t>;
TYPED_TEST_SUITE(SecureFixedPointAgmwCSTest, all_fixed_point);

TYPED_TEST(SecureFixedPointAgmwCSTest, AdditionInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  //  using FixedPointNumberField = std::uint32_t;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::vector<T> raw_global_input = ::RandomVector<T>(2);

  // only keep 32 bits: 16 + 16
  T fixed_point_mask = T(1) << (32);

  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};

  //   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
  //       encrypto::motion::ToInput<T, std::true_type>(raw_global_input.at(0)),
  //       encrypto::motion::ToInput<T, std::true_type>(raw_global_input.at(1))};

  // std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
  // std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

  //   std::vector<encrypto::motion::BitVector<>> dummy_input(
  //       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
  kPortOffset))); for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input, k, f]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[0], k, f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[0], k, f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[1], k, f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[1], k, f, 0));

      const auto share_result = share_0 + share_1;
      encrypto::motion::SecureFixedPointAgmwCS share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      const long double expect_result = FixedPointToDouble<T>(raw_global_input.at(0), k, f) +
                                        FixedPointToDouble<T>(raw_global_input.at(1), k, f);
      std::cout << "raw_global_input.at(0)_double: "
                << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
      std::cout << "raw_global_input.at(1)_double: "
                << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;
      std::cout << "expect_result: " << expect_result << std::endl;

      long double result_T;

      result_T = share_output.AsFixedPoint<T>();
      std::cout << "result_double: " << result_T << std::endl;
      EXPECT_DOUBLE_EQ(result_T, expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, AdditionInGmw_Simd) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::size_t num_of_simd = 100;

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
  T fixed_point_mask = T(1) << (32);

  for (std::size_t i = 0; i < num_of_simd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }
  constexpr auto kNumberOfWires{sizeof(T) * 8};

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
  kPortOffset))); for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
                          &raw_global_input_2, k, f, num_of_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
          k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
                  k,
                                                                              f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
          k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
                  k,
                                                                              f, 0));

      const auto share_result = share_0 + share_1;
      encrypto::motion::SecureFixedPointAgmwCS share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      for (std::size_t i = 0; i < num_of_simd; i++) {
        const long double expect_result =
            FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) +
            FixedPointToDouble<T, T_int>(raw_global_input_2.at(i), k, f);

        std::vector<long double> result_T_vector;

        result_T_vector = share_output.AsFixedPointVector<T>();
        // std::cout << "result_double: " << result_T_vector[i] << std::endl;
        EXPECT_DOUBLE_EQ(result_T_vector[i], expect_result);
        // std::cout << std::endl;
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}


TYPED_TEST(SecureFixedPointAgmwCSTest, AdditionConstantInGmw_Simd) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::size_t num_of_simd = 100;

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
  T fixed_point_mask = T(1) << (32);

  for (std::size_t i = 0; i < num_of_simd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }
  constexpr auto kNumberOfWires{sizeof(T) * 8};

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
  kPortOffset))); for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
                          &raw_global_input_2, k, f, num_of_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
          k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
                  k,
                                                                              f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
          k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
                  k,
                                                                              f, 0));

      const auto share_result = share_0 + FixedPointToDouble<T, T_int>(raw_global_input_2.at(0), k, f);
      encrypto::motion::SecureFixedPointAgmwCS share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      for (std::size_t i = 0; i < num_of_simd; i++) {
        const long double expect_result =
            FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) +
            FixedPointToDouble<T, T_int>(raw_global_input_2.at(0), k, f);

        std::vector<long double> result_T_vector;

        result_T_vector = share_output.AsFixedPointVector<T>();
        // std::cout << "result_double: " << result_T_vector[i] << std::endl;
        EXPECT_DOUBLE_EQ(result_T_vector[i], expect_result);
        // std::cout << std::endl;
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, SubtractionInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  //  using FixedPointNumberField = std::uint32_t;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::vector<T> raw_global_input = ::RandomVector<T>(2);

  // only keep 32 bits: 16 + 16
  T fixed_point_mask = T(1) << (32);

  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};

  //   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
  //       encrypto::motion::ToInput<T, std::true_type>(raw_global_input.at(0)),
  //       encrypto::motion::ToInput<T, std::true_type>(raw_global_input.at(1))};

  // std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
  // std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

  //   std::vector<encrypto::motion::BitVector<>> dummy_input(
  //       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
  kPortOffset))); for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input, k, f]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[0], k, f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[0], k, f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[1], k, f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[1], k, f, 0));

      const auto share_result = share_0 - share_1;
      encrypto::motion::SecureFixedPointAgmwCS share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      const long double expect_result = FixedPointToDouble<T>(raw_global_input.at(0), k, f) -
                                        FixedPointToDouble<T>(raw_global_input.at(1), k, f);
      std::cout << "raw_global_input.at(0)_double: "
                << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
      std::cout << "raw_global_input.at(1)_double: "
                << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;
      std::cout << "expect_result: " << expect_result << std::endl;

      long double result_T;

      result_T = share_output.AsFixedPoint<T>();
      std::cout << "result_double: " << result_T << std::endl;
      EXPECT_DOUBLE_EQ(result_T, expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, SubtractionInGmw_Simd) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::size_t num_of_simd = 100;

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
  T fixed_point_mask = T(1) << (32);

  for (std::size_t i = 0; i < num_of_simd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }
  constexpr auto kNumberOfWires{sizeof(T) * 8};

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
  kPortOffset))); for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
                          &raw_global_input_2, k, f, num_of_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
          k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
                  k,
                                                                              f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
          k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
                  k,
                                                                              f, 0));

      const auto share_result = share_0 - share_1;
      encrypto::motion::SecureFixedPointAgmwCS share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      for (std::size_t i = 0; i < num_of_simd; i++) {
        const long double expect_result =
            FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) -
            FixedPointToDouble<T, T_int>(raw_global_input_2.at(i), k, f);

        std::vector<long double> result_T_vector;

        result_T_vector = share_output.AsFixedPointVector<T>();
        // std::cout << "result_double: " << result_T_vector[i] << std::endl;
        EXPECT_DOUBLE_EQ(result_T_vector[i], expect_result);
        // std::cout << std::endl;
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, SubtractionConstantInGmw_Simd) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::size_t num_of_simd = 100;

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
  T fixed_point_mask = T(1) << (32);

  for (std::size_t i = 0; i < num_of_simd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }
  constexpr auto kNumberOfWires{sizeof(T) * 8};

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
  kPortOffset))); for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
                          &raw_global_input_2, k, f, num_of_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
          k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
                  k,
                                                                              f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
          k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
                  k,
                                                                              f, 0));

      const auto share_result = share_0 - FixedPointToDouble<T, T_int>(raw_global_input_2.at(0), k, f);
      encrypto::motion::SecureFixedPointAgmwCS share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      for (std::size_t i = 0; i < num_of_simd; i++) {
        const long double expect_result =
            FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) -
            FixedPointToDouble<T, T_int>(raw_global_input_2.at(0), k, f);

        std::vector<long double> result_T_vector;

        result_T_vector = share_output.AsFixedPointVector<T>();
        // std::cout << "result_double: " << result_T_vector[i] << std::endl;
        EXPECT_DOUBLE_EQ(result_T_vector[i], expect_result);
        // std::cout << std::endl;
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, MultiplicationInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  //  using FixedPointNumberField = std::uint32_t;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::vector<T> raw_global_input = ::RandomVector<T>(2);

  T fixed_point_mask = T(1) << (32-1);

  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};

  //   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
  //       encrypto::motion::ToInput<T, std::true_type>(raw_global_input.at(0)),
  //       encrypto::motion::ToInput<T, std::true_type>(raw_global_input.at(1))};

  // std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
  // std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

  //   std::vector<encrypto::motion::BitVector<>> dummy_input(
  //       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
  kPortOffset))); for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input, k, f]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[0], k, f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[0], k, f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[1], k, f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[1], k, f, 0));

      const auto share_result = share_0 * share_1;
      encrypto::motion::SecureFixedPointAgmwCS share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      const long double expect_result = FixedPointToDouble<T>(raw_global_input.at(0), k, f) *
                                        FixedPointToDouble<T>(raw_global_input.at(1), k, f);
      std::cout << "raw_global_input.at(0)_double: "
                << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
      std::cout << "raw_global_input.at(1)_double: "
                << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;
      std::cout << "expect_result: " << expect_result << std::endl;

      long double result_T;

      result_T = share_output.AsFixedPoint<T>();
      std::cout << "result_double: " << result_T << std::endl;
      // EXPECT_DOUBLE_EQ(result_T, expect_result);

      double abs_error = 1.0 / std::exp2(f / 2);
      EXPECT_NEAR(result_T, expect_result, abs_error);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, MultiplicationInGmw_Simd) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::size_t num_of_simd = 100;

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
  T fixed_point_mask = T(1) << (32-1);

  for (std::size_t i = 0; i < num_of_simd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }
  constexpr auto kNumberOfWires{sizeof(T) * 8};

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
  kPortOffset))); for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
                          &raw_global_input_2, k, f, num_of_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
          k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
                  k,
                                                                              f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
          k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
                  k,
                                                                              f, 0));

      const auto share_result = share_0 * share_1;
      encrypto::motion::SecureFixedPointAgmwCS share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      for (std::size_t i = 0; i < num_of_simd; i++) {
        const long double expect_result =
            FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) *
            FixedPointToDouble<T, T_int>(raw_global_input_2.at(i), k, f);

        std::vector<long double> result_T_vector;

        result_T_vector = share_output.AsFixedPointVector<T>();
        // std::cout << "result_double: " << result_T_vector[i] << std::endl;
        // EXPECT_DOUBLE_EQ(result_T_vector[i], expect_result);
        // std::cout << std::endl;

        double abs_error = 1.0 / std::exp2(f / 2);
        EXPECT_NEAR(result_T_vector[i], expect_result, abs_error);
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, MultiplicationConstantInGmw_Simd) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::size_t num_of_simd = 100;

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
  T fixed_point_mask = T(1) << (32-1);

  for (std::size_t i = 0; i < num_of_simd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }
  constexpr auto kNumberOfWires{sizeof(T) * 8};

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
  kPortOffset))); for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
                          &raw_global_input_2, k, f, num_of_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
          k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
                  k,
                                                                              f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
          k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
                  k,
                                                                              f, 0));

      const auto share_result = share_0 * FixedPointToDouble<T, T_int>(raw_global_input_2.at(0), k, f);
      encrypto::motion::SecureFixedPointAgmwCS share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      for (std::size_t i = 0; i < num_of_simd; i++) {
        const long double expect_result =
            FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) *
            FixedPointToDouble<T, T_int>(raw_global_input_2.at(0), k, f);

        std::vector<long double> result_T_vector;

        result_T_vector = share_output.AsFixedPointVector<T>();
        // std::cout << "result_double: " << result_T_vector[i] << std::endl;
        // EXPECT_DOUBLE_EQ(result_T_vector[i], expect_result);
        // std::cout << std::endl;

        double abs_error = 1.0 / std::exp2(f / 2);
        EXPECT_NEAR(result_T_vector[i], expect_result, abs_error);
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, LessThanInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  //  using FixedPointNumberField = std::uint32_t;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::vector<T> raw_global_input = ::RandomVector<T>(2);

  T fixed_point_mask = T(1) << (32 - 1);

  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};

  //   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
  //       encrypto::motion::ToInput<T, std::true_type>(raw_global_input.at(0)),
  //       encrypto::motion::ToInput<T, std::true_type>(raw_global_input.at(1))};

  // std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
  // std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

  //   std::vector<encrypto::motion::BitVector<>> dummy_input(
  //       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input, k, f]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[0], k, f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[0], k, f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[1], k, f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[1], k, f, 0));

      encrypto::motion::ShareWrapper share_result = share_0 < share_1;
      encrypto::motion::ShareWrapper share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      bool expect_result = FixedPointToDouble<T>(raw_global_input.at(0), k, f) <
                           FixedPointToDouble<T>(raw_global_input.at(1), k, f);
      std::cout << "raw_global_input.at(0)_double: "
                << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
      std::cout << "raw_global_input.at(1)_double: "
                << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;
      std::cout << "expect_result: " << expect_result << std::endl;

      BitVector<> result_T = share_output.As<BitVector<>>();
      std::cout << "result: " << result_T.Get(0) << std::endl;

      EXPECT_EQ(expect_result, result_T.Get(0));

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, LessThanInGmw_Simd) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::size_t num_of_simd = 100;

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
  T fixed_point_mask = T(1) << (32 - 1);

  for (std::size_t i = 0; i < num_of_simd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }
  constexpr auto kNumberOfWires{sizeof(T) * 8};

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
                          &raw_global_input_2, k, f, num_of_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1, k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1, k,
                                                                              f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2, k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2, k,
                                                                              f, 0));

      const auto share_result = share_0 < share_1;
      encrypto::motion::ShareWrapper share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      for (std::size_t i = 0; i < num_of_simd; i++) {
        bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) <
                             FixedPointToDouble<T, T_int>(raw_global_input_2.at(i), k, f);

        BitVector<> result_T_vector;

        result_T_vector = share_output.As<BitVector<>>();
        // std::cout << "result_double: " << result_T_vector[i] << std::endl;
        EXPECT_EQ(result_T_vector[i], expect_result);
        // std::cout << std::endl;
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, LessThanConstantInGmw_Simd) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::size_t num_of_simd = 100;

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
  T fixed_point_mask = T(1) << (32 - 1);

  for (std::size_t i = 0; i < num_of_simd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }
  constexpr auto kNumberOfWires{sizeof(T) * 8};

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
                          &raw_global_input_2, k, f, num_of_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1, k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1, k,
                                                                              f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2, k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2, k,
                                                                              f, 0));

      const auto share_result = share_0 < FixedPointToDouble<T, T_int>(raw_global_input_2.at(0), k, f);
      encrypto::motion::ShareWrapper share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      for (std::size_t i = 0; i < num_of_simd; i++) {
        bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) <
                             FixedPointToDouble<T, T_int>(raw_global_input_2.at(0), k, f);

        BitVector<> result_T_vector;

        result_T_vector = share_output.As<BitVector<>>();
        // std::cout << "result_double: " << result_T_vector[i] << std::endl;
        EXPECT_EQ(result_T_vector[i], expect_result);
        // std::cout << std::endl;
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}


TYPED_TEST(SecureFixedPointAgmwCSTest, GreaterThanInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  //  using FixedPointNumberField = std::uint32_t;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::vector<T> raw_global_input = ::RandomVector<T>(2);

  T fixed_point_mask = T(1) << (32 - 1);

  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};

  //   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
  //       encrypto::motion::ToInput<T, std::true_type>(raw_global_input.at(0)),
  //       encrypto::motion::ToInput<T, std::true_type>(raw_global_input.at(1))};

  // std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
  // std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

  //   std::vector<encrypto::motion::BitVector<>> dummy_input(
  //       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input, k, f]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[0], k, f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[0], k, f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[1], k, f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[1], k, f, 0));

      encrypto::motion::ShareWrapper share_result = share_0 > share_1;
      encrypto::motion::ShareWrapper share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      bool expect_result = FixedPointToDouble<T>(raw_global_input.at(0), k, f) >
                           FixedPointToDouble<T>(raw_global_input.at(1), k, f);
      std::cout << "raw_global_input.at(0)_double: "
                << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
      std::cout << "raw_global_input.at(1)_double: "
                << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;
      std::cout << "expect_result: " << expect_result << std::endl;

      BitVector<> result_T = share_output.As<BitVector<>>();
      std::cout << "result: " << result_T.Get(0) << std::endl;

      EXPECT_EQ(expect_result, result_T.Get(0));

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, GreaterThanInGmw_Simd) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::size_t num_of_simd = 100;

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
  T fixed_point_mask = T(1) << (32 - 1);

  for (std::size_t i = 0; i < num_of_simd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }
  constexpr auto kNumberOfWires{sizeof(T) * 8};

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
                          &raw_global_input_2, k, f, num_of_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1, k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1, k,
                                                                              f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2, k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2, k,
                                                                              f, 0));

      const auto share_result = share_0 > share_1;
      encrypto::motion::ShareWrapper share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      for (std::size_t i = 0; i < num_of_simd; i++) {
        bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) >
                             FixedPointToDouble<T, T_int>(raw_global_input_2.at(i), k, f);

        BitVector<> result_T_vector;

        result_T_vector = share_output.As<BitVector<>>();
        // std::cout << "result_double: " << result_T_vector[i] << std::endl;
        EXPECT_EQ(result_T_vector[i], expect_result);
        // std::cout << std::endl;
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, GreaterThanConstantInGmw_Simd) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::size_t num_of_simd = 100;

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
  T fixed_point_mask = T(1) << (32 - 1);

  for (std::size_t i = 0; i < num_of_simd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }
  constexpr auto kNumberOfWires{sizeof(T) * 8};

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
                          &raw_global_input_2, k, f, num_of_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1, k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1, k,
                                                                              f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2, k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2, k,
                                                                              f, 0));

      const auto share_result = share_0 > FixedPointToDouble<T, T_int>(raw_global_input_2.at(0), k, f);
      encrypto::motion::ShareWrapper share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      for (std::size_t i = 0; i < num_of_simd; i++) {
        bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) >
                             FixedPointToDouble<T, T_int>(raw_global_input_2.at(0), k, f);

        BitVector<> result_T_vector;

        result_T_vector = share_output.As<BitVector<>>();
        // std::cout << "result_double: " << result_T_vector[i] << std::endl;
        EXPECT_EQ(result_T_vector[i], expect_result);
        // std::cout << std::endl;
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}



TYPED_TEST(SecureFixedPointAgmwCSTest, EqualityInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  //  using FixedPointNumberField = std::uint32_t;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::vector<T> raw_global_input = ::RandomVector<T>(2);

  T fixed_point_mask = T(1) << (32 - 1);

  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};

  //   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
  //       encrypto::motion::ToInput<T, std::true_type>(raw_global_input.at(0)),
  //       encrypto::motion::ToInput<T, std::true_type>(raw_global_input.at(1))};

  // std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
  // std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

  //   std::vector<encrypto::motion::BitVector<>> dummy_input(
  //       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input, k, f]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[0], k, f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[0], k, f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[1], k, f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw, T>(
                        raw_global_input[1], k, f, 0));

      encrypto::motion::ShareWrapper share_result = share_0 == share_1;
      encrypto::motion::ShareWrapper share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      bool expect_result = FixedPointToDouble<T>(raw_global_input.at(0), k, f) ==
                           FixedPointToDouble<T>(raw_global_input.at(1), k, f);
      std::cout << "raw_global_input.at(0)_double: "
                << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
      std::cout << "raw_global_input.at(1)_double: "
                << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;
      std::cout << "expect_result: " << expect_result << std::endl;

      BitVector<> result_T = share_output.As<BitVector<>>();
      std::cout << "result: " << result_T.Get(0) << std::endl;

      EXPECT_EQ(expect_result, result_T.Get(0));

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, EqualityThanInGmw_Simd) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::size_t num_of_simd = 100;

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
  T fixed_point_mask = T(1) << (32 - 1);

  for (std::size_t i = 0; i < num_of_simd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }
  constexpr auto kNumberOfWires{sizeof(T) * 8};

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
                          &raw_global_input_2, k, f, num_of_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1, k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1, k,
                                                                              f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2, k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2, k,
                                                                              f, 0));

      const auto share_result = share_0 == share_1;
      encrypto::motion::ShareWrapper share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      for (std::size_t i = 0; i < num_of_simd; i++) {
        bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) ==
                             FixedPointToDouble<T, T_int>(raw_global_input_2.at(i), k, f);

        BitVector<> result_T_vector;

        result_T_vector = share_output.As<BitVector<>>();
        // std::cout << "result_double: " << result_T_vector[i] << std::endl;
        EXPECT_EQ(result_T_vector[i], expect_result);
        // std::cout << std::endl;
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointAgmwCSTest, EqualityConstantInGmw_Simd) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;

  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::srand(std::time(nullptr));
  std::size_t k = 64;
  std::size_t f = 16;
  std::size_t num_of_simd = 100;

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
  T fixed_point_mask = T(1) << (32 - 1);

  for (std::size_t i = 0; i < num_of_simd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }
  constexpr auto kNumberOfWires{sizeof(T) * 8};

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
                          &raw_global_input_2, k, f, num_of_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1, k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1, k,
                                                                              f, 0));
      encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
          party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2, k,
                                                                              f, 0)
                  : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2, k,
                                                                              f, 0));

      const auto share_result = share_0 == FixedPointToDouble<T, T_int>(raw_global_input_2.at(0), k, f);
      encrypto::motion::ShareWrapper share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      for (std::size_t i = 0; i < num_of_simd; i++) {
        bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) ==
                             FixedPointToDouble<T, T_int>(raw_global_input_2.at(0), k, f);

        BitVector<> result_T_vector;

        result_T_vector = share_output.As<BitVector<>>();
        // std::cout << "result_double: " << result_T_vector[i] << std::endl;
        EXPECT_EQ(result_T_vector[i], expect_result);
        // std::cout << std::endl;
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}











































// TYPED_TEST(SecureFixedPointAgmwCSTest, LTZInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   std::srand(std::time(nullptr));
//   std::size_t k = 41;
//   std::size_t f = 20;

//   std::vector<T> raw_global_input = ::RandomVector<T>(2);
//   T fixed_point_mask = T(1) << (k);

//   raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
//   raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

//   // adjust the sign
//   bool v1_sign = std::rand() % 2;
//   bool v2_sign = std::rand() % 2;
//   raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
//   raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

//   // edge case
//   std::size_t edge_case = std::rand() % 5;
//   switch (edge_case) {
//     case 0:
//       raw_global_input[0] = -raw_global_input[0];
//       break;
//     case 1:
//       raw_global_input[0] = 0;
//       break;
//     default:
//       break;
//   }

//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1};

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input, k, f]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
//           party_0 ?
//           motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input[0],
//                                                                               k, f, 0)
//                   :
//                   motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input[0],
//                                                                               k, f, 0));
//       encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
//           party_0 ?
//           motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input[1],
//                                                                               k, f, 0)
//                   :
//                   motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input[1],
//                                                                               k, f, 0));

//       const auto share_result = share_0.LTZ();
//       encrypto::motion::ShareWrapper share_output = share_result.Out();

//       std::cout << "party run" << std::endl;
//       motion_parties.at(party_id)->Run();
//       const bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) < 0;
//       // std::cout << "raw_global_input.at(0): " << T_int(raw_global_input.at(0)) << std::endl;
//       // std::cout << "raw_global_input.at(1): " << T_int(raw_global_input.at(1)) << std::endl;
//       std::cout << "raw_global_input.at(0)_double: "
//                 << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
//       // std::cout << "raw_global_input.at(1)_double: "
//       //           << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;
//       std::cout << "expect_result: " << expect_result << std::endl;

//       bool result_T;

//       result_T = share_output.As<T>();
//       std::cout << "result_bool: " << result_T << std::endl;
//       EXPECT_EQ(result_T, expect_result);

//       motion_parties.at(party_id)->Finish();
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointAgmwCSTest, LTZInGmw_Simd) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   std::srand(std::time(nullptr));
//   std::size_t k = 41;
//   std::size_t f = 20;
//   std::size_t num_of_simd = 100;

//   std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
//   std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
//   T fixed_point_mask = T(1) << (k);

//   for (std::size_t i = 0; i < num_of_simd; i++) {
//     raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
//     raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

//     // adjust the sign
//     bool v1_sign = std::rand() % 2;
//     bool v2_sign = std::rand() % 2;
//     raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
//     raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
//   }
//   constexpr auto kNumberOfWires{sizeof(T) * 8};

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
//                           &raw_global_input_2, k, f, num_of_simd]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
//           party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
//           k,
//                                                                               f, 0)
//                   : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
//                   k,
//                                                                               f, 0));
//       encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
//           party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
//           k,
//                                                                               f, 0)
//                   : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
//                   k,
//                                                                               f, 0));

//       const auto share_result = share_0.LTZ();
//       encrypto::motion::SecureFixedPointAgmwCS share_output = share_result.Out();

//       std::cout << "party run" << std::endl;
//       motion_parties.at(party_id)->Run();
//       motion_parties.at(party_id)->Finish();
//       std::cout << "party finish" << std::endl;

//       for (std::size_t i = 0; i < num_of_simd; i++) {
//         bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) < 0;

//         std::vector<T> result_T_vector;

//         result_T_vector = share_output.As<std::vector<__uint128_t>>();
//         // std::cout << "result_double: " << result_T_vector[i] << std::endl;
//         EXPECT_EQ(result_T_vector[i], expect_result);
//       }
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointAgmwCSTest, EQZInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   std::srand(std::time(nullptr));
//   std::size_t k = 41;
//   std::size_t f = 20;

//   std::vector<T> raw_global_input = ::RandomVector<T>(2);
//   T fixed_point_mask = T(1) << (k);

//   raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
//   raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

//   // adjust the sign
//   bool v1_sign = std::rand() % 2;
//   bool v2_sign = std::rand() % 2;
//   raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
//   raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

//   // edge case
//   std::size_t edge_case = std::rand() % 5;
//   switch (edge_case) {
//     case 0:
//       raw_global_input[0] = -raw_global_input[0];
//       break;
//     case 1:
//       raw_global_input[0] = 0;
//       break;
//     default:
//       break;
//   }

//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1};

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input, k, f]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
//           party_0 ?
//           motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input[0],
//                                                                               k, f, 0)
//                   :
//                   motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input[0],
//                                                                               k, f, 0));
//       encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
//           party_0 ?
//           motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input[1],
//                                                                               k, f, 0)
//                   :
//                   motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input[1],
//                                                                               k, f, 0));

//       const auto share_result = share_0.EQZ();
//       encrypto::motion::ShareWrapper share_output = share_result.Out();

//       std::cout << "party run" << std::endl;
//       motion_parties.at(party_id)->Run();
//       const bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) == 0;
//       std::cout << "raw_global_input.at(0)_double: "
//                 << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
//       // std::cout << "raw_global_input.at(1)_double: "
//       //           << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;
//       std::cout << "expect_result: " << expect_result << std::endl;

//       bool result_T;

//       result_T = share_output.As<T>();
//       std::cout << "result_bool: " << result_T << std::endl;
//       EXPECT_EQ(result_T, expect_result);

//       motion_parties.at(party_id)->Finish();
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointAgmwCSTest, EQZInGmw_Simd) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   std::srand(std::time(nullptr));
//   std::size_t k = 41;
//   std::size_t f = 20;
//   std::size_t num_of_simd = 100;

//   std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
//   std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
//   T fixed_point_mask = T(1) << (k);

//   for (std::size_t i = 0; i < num_of_simd; i++) {
//     raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
//     raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

//     // adjust the sign
//     bool v1_sign = std::rand() % 2;
//     bool v2_sign = std::rand() % 2;
//     raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
//     raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
//   }
//   constexpr auto kNumberOfWires{sizeof(T) * 8};

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
//                           &raw_global_input_2, k, f, num_of_simd]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
//           party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
//           k,
//                                                                               f, 0)
//                   : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
//                   k,
//                                                                               f, 0));
//       encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
//           party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
//           k,
//                                                                               f, 0)
//                   : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
//                   k,
//                                                                               f, 0));

//       const auto share_result = share_0.EQZ();
//       encrypto::motion::SecureFixedPointAgmwCS share_output = share_result.Out();

//       std::cout << "party run" << std::endl;
//       motion_parties.at(party_id)->Run();
//       motion_parties.at(party_id)->Finish();
//       std::cout << "party finish" << std::endl;

//       for (std::size_t i = 0; i < num_of_simd; i++) {
//         bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) == 0;

//         std::vector<T> result_T_vector;

//         result_T_vector = share_output.As<std::vector<__uint128_t>>();
//         // std::cout << "result_double: " << result_T_vector[i] << std::endl;
//         EXPECT_EQ(result_T_vector[i], expect_result);
//       }
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointAgmwCSTest, EqualityInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   std::srand(std::time(nullptr));
//   std::size_t k = 41;
//   std::size_t f = 20;

//   std::vector<T> raw_global_input = ::RandomVector<T>(2);
//   T fixed_point_mask = T(1) << (k);

//   raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
//   raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

//   // adjust the sign
//   bool v1_sign = std::rand() % 2;
//   bool v2_sign = std::rand() % 2;
//   raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
//   raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

//   // edge case
//   std::size_t edge_case = std::rand() % 5;
//   switch (edge_case) {
//     case 0:
//       raw_global_input[0] = -raw_global_input[0];
//       break;
//     case 1:
//       raw_global_input[0] = -raw_global_input[0];
//       raw_global_input[1] = -raw_global_input[1];
//       break;
//     case 2:
//       raw_global_input[1] = -raw_global_input[1];
//       break;
//     case 3:
//       raw_global_input[0] = raw_global_input[1];
//       break;
//     default:
//       break;
//   }

//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1};

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input, k, f]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
//           party_0 ?
//           motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input[0],
//                                                                               k, f, 0)
//                   :
//                   motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input[0],
//                                                                               k, f, 0));
//       encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
//           party_0 ?
//           motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input[1],
//                                                                               k, f, 0)
//                   :
//                   motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input[1],
//                                                                               k, f, 0));

//       const auto share_result = share_0 == share_1;
//       encrypto::motion::ShareWrapper share_output = share_result.Out();

//       std::cout << "party run" << std::endl;
//       motion_parties.at(party_id)->Run();
//       const bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) ==
//                                  FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);
//       std::cout << "raw_global_input.at(0)_double: "
//                 << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
//       std::cout << "raw_global_input.at(1)_double: "
//                 << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;
//       std::cout << "expect_result: " << expect_result << std::endl;

//       bool result_T;

//       result_T = share_output.As<T>();
//       std::cout << "result_bool: " << result_T << std::endl;
//       EXPECT_EQ(result_T, expect_result);

//       motion_parties.at(party_id)->Finish();
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointAgmwCSTest, EqualityInGmw_Simd) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
//   std::srand(std::time(nullptr));
//   std::size_t k = 41;
//   std::size_t f = 20;
//   std::size_t num_of_simd = 100;

//   std::vector<T> raw_global_input_1 = ::RandomVector<T>(num_of_simd);
//   std::vector<T> raw_global_input_2 = ::RandomVector<T>(num_of_simd);
//   T fixed_point_mask = T(1) << (k);

//   for (std::size_t i = 0; i < num_of_simd; i++) {
//     raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
//     raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

//     // adjust the sign
//     bool v1_sign = std::rand() % 2;
//     bool v2_sign = std::rand() % 2;
//     raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
//     raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
//   }
//   constexpr auto kNumberOfWires{sizeof(T) * 8};

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &raw_global_input_1,
//                           &raw_global_input_2, k, f, num_of_simd]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointAgmwCS share_0 = SecureFixedPointAgmwCS(
//           party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
//           k,
//                                                                               f, 0)
//                   : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_1,
//                   k,
//                                                                               f, 0));
//       encrypto::motion::SecureFixedPointAgmwCS share_1 = SecureFixedPointAgmwCS(
//           party_0 ? motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
//           k,
//                                                                               f, 0)
//                   : motion_parties.at(party_id)->InFixedPoint<kArithmeticGmw>(raw_global_input_2,
//                   k,
//                                                                               f, 0));

//       const auto share_result = share_0 == share_1;
//       encrypto::motion::SecureFixedPointAgmwCS share_output = share_result.Out();

//       std::cout << "party run" << std::endl;
//       motion_parties.at(party_id)->Run();
//       motion_parties.at(party_id)->Finish();
//       std::cout << "party finish" << std::endl;

//       for (std::size_t i = 0; i < num_of_simd; i++) {
//         bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input_1.at(i), k, f) ==
//                              FixedPointToDouble<T, T_int>(raw_global_input_2.at(i), k, f);

//         std::vector<T> result_T_vector;

//         result_T_vector = share_output.As<std::vector<__uint128_t>>();
//         // std::cout << "result_double: " << result_T_vector[i] << std::endl;
//         EXPECT_EQ(result_T_vector[i], expect_result);
//       }
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

}  // namespace
