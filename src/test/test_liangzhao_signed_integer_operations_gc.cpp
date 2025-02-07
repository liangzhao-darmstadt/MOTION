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
// #include "secure_type/secure_floating_point_circuit_ESAT.h"
#include "secure_type/secure_unsigned_integer.h"
#include "test_helpers.h"
#include "utility/config.h"

#include "test_constants.h"

using namespace encrypto::motion;

namespace {
TEST(AlgorithmDescription, FromBristolFormatIntAdd8Size) {
  const auto int_add8 = encrypto::motion::AlgorithmDescription::FromBristol(
      std::string(encrypto::motion::kRootDir) + "/circuits/signed_integer/int8_add_size.bristol");
  EXPECT_EQ(int_add8.number_of_gates, 34);
  EXPECT_EQ(int_add8.gates.size(), 34);
  EXPECT_EQ(int_add8.number_of_output_wires, 8);
  EXPECT_EQ(int_add8.number_of_input_wires_parent_a, 8);
  ASSERT_NO_THROW([&int_add8]() { EXPECT_EQ(*int_add8.number_of_input_wires_parent_b, 8); }());
  EXPECT_EQ(int_add8.number_of_wires, 50);

  const auto& gate0 = int_add8.gates.at(0);
  EXPECT_EQ(gate0.parent_a, 0);
  ASSERT_NO_THROW([&gate0]() { EXPECT_EQ(*gate0.parent_b, 8); }());
  EXPECT_EQ(gate0.output_wire, 42);
  EXPECT_EQ(gate0.type == encrypto::motion::PrimitiveOperationType::kXor, 1);
  EXPECT_EQ(gate0.selection_bit.has_value(), false);

  const auto& gate1 = int_add8.gates.at(1);
  EXPECT_EQ(gate1.parent_a, 0);
  ASSERT_NO_THROW([&gate1]() { EXPECT_EQ(*gate1.parent_b, 8); }());
  EXPECT_EQ(gate1.output_wire, 16);
  EXPECT_EQ(gate1.type == encrypto::motion::PrimitiveOperationType::kAnd, 1);
  EXPECT_EQ(gate1.selection_bit.has_value(), false);

  const auto& gate32 = int_add8.gates.at(32);
  EXPECT_EQ(gate32.parent_a, 15);
  ASSERT_NO_THROW([&gate32]() { EXPECT_EQ(*gate32.parent_b, 40); }());
  EXPECT_EQ(gate32.output_wire, 41);
  EXPECT_EQ(gate32.type == encrypto::motion::PrimitiveOperationType::kXor, 1);
  EXPECT_EQ(gate32.selection_bit.has_value(), false);

  const auto& gate33 = int_add8.gates.at(33);
  EXPECT_EQ(gate33.parent_a, 7);
  ASSERT_NO_THROW([&gate33]() { EXPECT_EQ(*gate33.parent_b, 41); }());
  EXPECT_EQ(gate33.output_wire, 49);
  EXPECT_EQ(gate33.type == encrypto::motion::PrimitiveOperationType::kXor, 1);
  EXPECT_EQ(gate33.selection_bit.has_value(), false);
}
template <typename T>
class SecureIntTest_8_16_32_64_gc : public ::testing::Test {};

template <typename T>
class SecureIntTest_8_16_32_64_128_gc : public ::testing::Test {};

template <typename T>
class SecureIntTest_32_64_gc : public ::testing::Test {};

template <typename T>
class SecureIntTest_128_gc : public ::testing::Test {};

using uint_32_64 = ::testing::Types<std::uint32_t, std::uint64_t>;
using uint_8_16_32_64 = ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t>;
using uint_8_16_32_64_128 =
    ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t, __uint128_t>;
using uint_128 = ::testing::Types<__uint128_t>;

TYPED_TEST_SUITE(SecureIntTest_32_64_gc, uint_32_64);
TYPED_TEST_SUITE(SecureIntTest_128_gc, uint_128);
TYPED_TEST_SUITE(SecureIntTest_8_16_32_64_128_gc, uint_8_16_32_64_128);

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, AdditionSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  // std::cout << "raw_global_input_1: " << T_int(raw_global_input_1[0]) << std::endl;
  // std::cout << "raw_global_input_2: " << T_int(raw_global_input_2[0]) << std::endl;

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 + share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T_int result_check =
            T_int(raw_global_input_1.at(i)) + T_int(raw_global_input_2.at(i));
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(T_int(result[i]), result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, AdditionConstantSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  // std::cout << "raw_global_input_1: " << T_int(raw_global_input_1[0]) << std::endl;
  // std::cout << "raw_global_input_2: " << T_int(raw_global_input_2[0]) << std::endl;

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      encrypto::motion::SecureSignedInteger share_result = share_0 + raw_global_input_2[0];
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T_int result_check =
            T_int(raw_global_input_1.at(i)) + T_int(raw_global_input_2.at(0));
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(T_int(result[i]), result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, SubtractionSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 - share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T_int result_check =
            T_int(raw_global_input_1.at(i)) - T_int(raw_global_input_2.at(i));
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(T_int(result[i]), result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, MultiplicationSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  using T_int = get_int_type_t<T>;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 * share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T_int result_check =
            T_int(raw_global_input_1.at(i)) * T_int(raw_global_input_2.at(i));
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(T_int(result[i]), result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, DivisionSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    if (raw_global_input_2[i] == 0) {
      raw_global_input_2[i] == 1;
    }
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 / share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T_int result_check =
            T_int(raw_global_input_1.at(i)) / T_int(raw_global_input_2.at(i));
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(T_int(result[i]), result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, LessThanSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  // std::cout << "raw_global_input_1: " << T_int(raw_global_input_1[0]) << std::endl;
  //   std::cout << "raw_global_input_2: " << T_int(raw_global_input_2[0]) << std::endl;

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 < share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool result_check = T_int(raw_global_input_1.at(i)) < T_int(raw_global_input_2.at(i));
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, GreaterThanSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 > share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool result_check = T_int(raw_global_input_1.at(i)) > T_int(raw_global_input_2.at(i));
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, EqualitySIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 == share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool result_check =
            T_int(raw_global_input_1.at(i)) == T_int(raw_global_input_2.at(i));
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, MulBooleanBitSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  std::vector<bool> raw_global_input_2 = RandomBoolVector(kNumberOfSimd);

  BitVector<> boolean_bit = BitVector(raw_global_input_2);
  BitVector<> dummy_boolean_bit = boolean_bit ^ boolean_bit;

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &boolean_bit, &dummy_boolean_bit]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_boolean_bit, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(boolean_bit, 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.MulBooleanBit(share_1.Get());
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T_int result_check = T_int((raw_global_input_1.at(i)) * (boolean_bit[i]));
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(T_int(result[i]), result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, IsZeroSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.IsZero();
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool result_check = T_int(raw_global_input_1.at(i)) == 0;
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}
TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, IsNegSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.IsNeg();
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool result_check = T_int(raw_global_input_1.at(i)) < 0;
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, InRangeSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{2};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(T(0), max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.InRange(share_1);
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool result_check =
            (T_int(raw_global_input_1.at(i)) < T_int(raw_global_input_2.at(i))) &&
            (T_int(raw_global_input_1.at(i)) > -T_int(raw_global_input_2.at(i)));
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, NegSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  std::size_t m = raw_global_input_2[0];

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &m]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Neg();
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T_int result_check = -T_int(raw_global_input_1[i]);
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(T_int(result[i]), result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, NegConditionSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  std::vector<bool> raw_global_input_2 = RandomBoolVector(kNumberOfSimd);

  BitVector<> boolean_bit = BitVector(raw_global_input_2);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2, &boolean_bit]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger share_0 =
          party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                  : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0);
      encrypto::motion::ShareWrapper share_1 =
          party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(boolean_bit, 1)
                  : motion_parties.at(party_id)->In<kGarbledCircuit>(boolean_bit, 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Neg(share_1);
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T_int result_check =
            T_int(1 - 2 * raw_global_input_2[i]) * T_int(raw_global_input_1.at(i));
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(T_int(result[i]), result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, GESIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.GE(share_1);
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool result_check =
            T_int(raw_global_input_1.at(i)) >= T_int(raw_global_input_2.at(i));
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_8_16_32_64_128_gc, LESIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.LE(share_1);
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool result_check =
            T_int(raw_global_input_1.at(i)) <= T_int(raw_global_input_2.at(i));
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], result_check);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_32_64_gc, Int2FLSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  // only for debug
  raw_global_input_1[0] = 0;

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result_32 = share_0.Int2FL(32);
      const auto share_result_64 = share_0.Int2FL(64);
      auto share_output_32 = share_result_32.Out();
      auto share_output_64 = share_result_64.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      std::vector<float> result_32 = share_output_32.AsFloatingPointVector<float>();
      std::vector<double> result_64 = share_output_64.AsFloatingPointVector<double>();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const float result_check_32 = float(T_int(raw_global_input_1.at(i)));
        const double result_check_64 = double(T_int(raw_global_input_1.at(i)));

        EXPECT_EQ(result_32[i], result_check_32);
        EXPECT_EQ(result_64[i], result_check_64);
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_128_gc, Int2FLSIMDInGC) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = -T(1) << (sizeof(T) * 8 - 3);
  T max = T(1) << (sizeof(T) * 8 - 3);
  std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  // only for debug
  raw_global_input_1[0] = 0;

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result_32 = share_0.Int2FL(32);
      const auto share_result_64 = share_0.Int2FL(64);
      auto share_output_32 = share_result_32.Out();
      auto share_output_64 = share_result_64.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      std::vector<float> result_32 = share_output_32.AsFloatingPointVector<float>();
      std::vector<double> result_64 = share_output_64.AsFloatingPointVector<double>();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const float result_check_32 = float(T_int(raw_global_input_1.at(i)));
        const double result_check_64 = double(T_int(raw_global_input_1.at(i)));

        // if (T_int(raw_global_input_1.at(i)) < 0) {
        //   print_u128_u("-raw_global_input_1.at(i): ", -raw_global_input_1.at(i));
        // } else {
        //   print_u128_u("raw_global_input_1.at(i): ", raw_global_input_1.at(i));
        // }

        // std::cout << "result_check_32: " << result_check_32 << std::endl;
        // std::cout << "result_check_64: " << result_check_64 << std::endl;
        // std::cout<<std::endl;

        EXPECT_LE(result_32[i], std::nextafter(result_check_32, +INFINITY));
        EXPECT_GE(result_32[i], std::nextafter(result_check_32, -INFINITY));
        EXPECT_LE(result_64[i], std::nextafter(result_check_64, +INFINITY));
        EXPECT_GE(result_64[i], std::nextafter(result_check_64, -INFINITY));
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureIntTest_32_64_gc, Int2FxSIMDInGC) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 3 - 16);
  std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  // only for debugging
  for (std::size_t i = 0; i < kNumberOfSimd; ++i) {
    raw_global_input_1[i] = -raw_global_input_1[i];
  }
  // raw_global_input_1[0] = -10;
  std::cout << "raw_global_input_1: " << T_int(raw_global_input_1[0]) << std::endl;

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Int2Fx(16);
      auto share_output = share_result.Out();

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::cout << "party finish" << std::endl;

      std::vector<double> result = share_output.AsFixedPointVector<std::uint64_t, std::int64_t>();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const double result_check = double(T_int(raw_global_input_1.at(i)));
        // std::cout << "result_check: " << result_check << std::endl;
        // std::cout << "result: " << result[i] << std::endl;
        EXPECT_EQ(result[i], result_check);
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

}  // namespace
