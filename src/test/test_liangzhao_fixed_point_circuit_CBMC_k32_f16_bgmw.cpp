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
#include "secure_type/secure_fixed_point_circuit_CBMC.h"
#include "utility/config.h"

#include "test_constants.h"
#include "test_helpers.h"
#include "utility/helpers.h"

using namespace encrypto::motion;

namespace {
TEST(AlgorithmDescription, FromBristolFormatFixedPointAdd32) {
  const auto fx_add32 = encrypto::motion::AlgorithmDescription::FromBristol(
      std::string(encrypto::motion::kRootDir) +
      "/circuits/fixed_point_CBMC_k32_f16/fix32_add_depth.bristol");
  EXPECT_EQ(fx_add32.number_of_gates, 301);
  EXPECT_EQ(fx_add32.gates.size(), 301);

  EXPECT_EQ(fx_add32.number_of_output_wires, 32);
  EXPECT_EQ(fx_add32.number_of_input_wires_parent_a, 32);
  ASSERT_NO_THROW([&fx_add32]() { EXPECT_EQ(*fx_add32.number_of_input_wires_parent_b, 32); }());
  EXPECT_EQ(fx_add32.number_of_wires, 365);

  const auto& gate0 = fx_add32.gates.at(0);
  EXPECT_EQ(gate0.parent_a, 0);
  ASSERT_NO_THROW([&gate0]() { EXPECT_EQ(*gate0.parent_b, 32); }());
  EXPECT_EQ(gate0.output_wire, 333);
  EXPECT_EQ(gate0.type == encrypto::motion::PrimitiveOperationType::kXor, true);
  EXPECT_EQ(gate0.selection_bit.has_value(), false);

  const auto& gate2 = fx_add32.gates.at(2);
  EXPECT_EQ(gate2.parent_a, 0);
  ASSERT_NO_THROW([&gate2]() { EXPECT_EQ(*gate2.parent_b, 32); }());
  EXPECT_EQ(gate2.output_wire, 65);
  EXPECT_EQ(gate2.type == encrypto::motion::PrimitiveOperationType::kAnd, true);
  EXPECT_EQ(gate2.selection_bit.has_value(), false);

  const auto& gate6 = fx_add32.gates.at(6);
  EXPECT_EQ(gate6.parent_a, 64);
  ASSERT_NO_THROW([&gate6]() { EXPECT_EQ(*gate6.parent_b, 65); }());
  EXPECT_EQ(gate6.output_wire, 68);
  EXPECT_EQ(gate6.type == encrypto::motion::PrimitiveOperationType::kAnd, true);
  EXPECT_EQ(gate6.selection_bit.has_value(), false);
}

template <typename T>
class SecureFixedPointCircuitCBMCk32f16BgmwTest : public ::testing::Test {};
//
using all_fixed_point = ::testing::Types<std::uint32_t>;
TYPED_TEST_SUITE(SecureFixedPointCircuitCBMCk32f16BgmwTest, all_fixed_point);

// TYPED_TEST(SecureFixedPointCircuitCBMCk32f16BgmwTest, AddInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   std::srand(std::time(nullptr));

//   std::vector<T> raw_global_input = ::RandomVector<T>(2);
//   T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);
//   raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
//   raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

//   // adjust the sign
//   bool v1_sign = std::rand() % 2;
//   bool v2_sign = std::rand() % 2;
//   raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
//   raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1};

//   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
//       encrypto::motion::ToInput(raw_global_input.at(0)),
//       encrypto::motion::ToInput(raw_global_input.at(1))};

//   //  std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
//   //  std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

//   std::vector<encrypto::motion::BitVector<>> dummy_input(
//       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
//                           &raw_global_input]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointCircuitCBMC
//           share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
//           share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
//                             1);
//       EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

//       std::size_t k = 32;
//       std::size_t f = 16;

//       share_0.SetFixedPointFormat(k, f);
//       share_1.SetFixedPointFormat(k, f);

//       const auto share_result = share_0 + share_1;
//       auto share_output = share_result.Out();

//       // std::size_t k = share_0.k_;
//       // std::size_t f = share_0.f_;

//       // std::cout << "k: " << k << std::endl;
//       // std::cout << "f: " << f << std::endl;

//       motion_parties.at(party_id)->Run();
//       const double expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) +
//                                    FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);
//       std::cout << "raw_global_input.at(0): " << T_int(raw_global_input.at(0)) << std::endl;
//       std::cout << "raw_global_input.at(1): " << T_int(raw_global_input.at(1)) << std::endl;
//       std::cout << "raw_global_input.at(0)_double: "
//                 << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
//       std::cout << "raw_global_input.at(1)_double: "
//                 << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;
//       std::cout << "expect_result: " << expect_result << std::endl;

//       double result_T;

//       result_T = share_output.AsFixedPoint<T, T_int>();
//       std::cout << "result_double: " << result_T << std::endl;
//       // EXPECT_DOUBLE_EQ(result_T, expect_result);

//       // double abs_error = 0.02;
//       // EXPECT_NEAR(result_T, expect_result, abs_error);              // error: 0.015625

//       double rel_error = 0.00001;
//       EXPECT_LT(std::abs((result_T - expect_result) / result_T), rel_error);

//       motion_parties.at(party_id)->Finish();
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointCircuitCBMCk32f16BgmwTest, AddSIMDInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   using A = std::allocator<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1000};
//   std::srand(std::time(nullptr));

//   std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
//   std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
//   T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);

//   for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//     raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
//     raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

//     // adjust the sign
//     bool v1_sign = std::rand() % 2;
//     bool v2_sign = std::rand() % 2;
//     raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
//     raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
//   }

//   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
//       encrypto::motion::ToInput(raw_global_input_1),
//       encrypto::motion::ToInput(raw_global_input_2)};

//   //  std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
//   //  std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

//   std::vector<encrypto::motion::BitVector<>> dummy_input(
//       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
//                           &raw_global_input_1, &raw_global_input_2]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointCircuitCBMC
//           share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
//           share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
//                             1);
//       EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

//       std::size_t k = 32;
//       std::size_t f = 16;

//       share_0.SetFixedPointFormat(k, f);
//       share_1.SetFixedPointFormat(k, f);

//       const auto share_result = share_0 + share_1;
//       auto share_output = share_result.Out();

//       // std::size_t k = share_0.k_;
//       // std::size_t f = share_0.f_;

//       motion_parties.at(party_id)->Run();
//       motion_parties.at(party_id)->Finish();
//       if (party_0) {
//         std::vector<double> result_T;
//         result_T = share_output.AsFixedPointVector<T, T_int>();

//         for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//           double expect_result_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) +
//                                    FixedPointToDouble<T, T_int>(raw_global_input_2[i], k, f);
//           // std::cout << "result_double_i: " << result_T[i] << std::endl;
//           // std::cout << "expect_result_i: " << expect_result_i << std::endl;
//           // std::cout << "(result_T[i] - expect_result_i) / result_T[i]: "
//           //           << (result_T[i] - expect_result_i) / result_T[i] << std::endl;

//           // double abs_error = 0.02;
//           // EXPECT_NEAR(result_T[i], expect_result_i, abs_error);  // error: 0.015625

//           double rel_error = 0.00001;
//           EXPECT_LT(std::abs((result_T[i] - expect_result_i) / result_T[i]), rel_error);
//         }
//       }
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointCircuitCBMCk32f16BgmwTest, AddConstantSIMDInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   using A = std::allocator<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1000};
//   std::srand(std::time(nullptr));

//   std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
//   std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
//   T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);

//   for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//     raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
//     raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

//     // adjust the sign
//     bool v1_sign = std::rand() % 2;
//     bool v2_sign = std::rand() % 2;
//     raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
//     raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);

//     raw_global_input_2[i] = raw_global_input_2[0];
//   }

//   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
//       encrypto::motion::ToInput(raw_global_input_1),
//       encrypto::motion::ToInput(raw_global_input_2)};

//   //  std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
//   //  std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

//   std::vector<encrypto::motion::BitVector<>> dummy_input(
//       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
//                           &raw_global_input_1, &raw_global_input_2]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointCircuitCBMC
//           share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
//           share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
//                             1);
//       EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

//       std::size_t k = 32;
//       std::size_t f = 16;

//       share_0.SetFixedPointFormat(k, f);
//       share_1.SetFixedPointFormat(k, f);

//       // std::size_t k = share_0.k_;
//       // std::size_t f = share_0.f_;

//       const auto share_result =
//           share_0 + double(FixedPointToDouble<T, T_int>(raw_global_input_2[0], k, f));
//       auto share_output = share_result.Out();

//       motion_parties.at(party_id)->Run();
//       motion_parties.at(party_id)->Finish();
//       if (party_0) {
//         std::vector<double> result_T;
//         result_T = share_output.AsFixedPointVector<T, T_int>();

//         for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//           double expect_result_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) +
//                                    FixedPointToDouble<T, T_int>(raw_global_input_2[0], k, f);
//           // std::cout << "result_double_i: " << result_T[i] << std::endl;
//           // std::cout << "expect_result_i: " << expect_result_i << std::endl;
//           // double abs_error = 0.02;
//           // EXPECT_NEAR(result_T[i], expect_result_i, abs_error);  // error: 0.015625

//           double rel_error = 0.00001;
//           EXPECT_LT(std::abs((result_T[i] - expect_result_i) / result_T[i]), rel_error);
//         }
//       }
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointCircuitCBMCk32f16BgmwTest, LessThanInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1};
//   std::srand(std::time(nullptr));

//   std::vector<T> raw_global_input = ::RandomVector<T>(2);
//   T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

//   raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
//   raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

//   // adjust the sign
//   bool v1_sign = std::rand() % 2;
//   bool v2_sign = std::rand() % 2;
//   raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
//   raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

//   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
//       encrypto::motion::ToInput(raw_global_input.at(0)),
//       encrypto::motion::ToInput(raw_global_input.at(1))};

//   //  std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
//   //  std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

//   std::vector<encrypto::motion::BitVector<>> dummy_input(
//       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
//                           &raw_global_input]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointCircuitCBMC
//           share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
//           share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
//                             1);
//       EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

//       std::size_t k = 32;
//       std::size_t f = 16;

//       share_0.SetFixedPointFormat(k, f);
//       share_1.SetFixedPointFormat(k, f);

//       const auto share_result = share_0 < share_1;
//       auto share_output = share_result.Out();

//       // std::size_t k = share_0.k_;
//       // std::size_t f = share_0.f_;

//       // std::cout << "k: " << k << std::endl;
//       // std::cout << "f: " << f << std::endl;

//       motion_parties.at(party_id)->Run();
//       const bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) <
//                                  FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);
//       std::cout << "raw_global_input.at(0): " << T_int(raw_global_input.at(0)) << std::endl;
//       std::cout << "raw_global_input.at(1): " << T_int(raw_global_input.at(1)) << std::endl;
//       std::cout << "raw_global_input.at(0)_double: "
//                 << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
//       std::cout << "raw_global_input.at(1)_double: "
//                 << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;
//       std::cout << "expect_result: " << expect_result << std::endl;

//       bool result_T;

//       result_T = share_output.As<bool>();
//       std::cout << "result_T: " << result_T << std::endl;

//       EXPECT_EQ(result_T, expect_result);

//       motion_parties.at(party_id)->Finish();
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointCircuitCBMCk32f16BgmwTest, LessThanSIMDInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   using A = std::allocator<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1000};
//   std::srand(std::time(nullptr));

//   std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
//   std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
//   T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

//   for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//     raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
//     raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

//     // adjust the sign
//     bool v1_sign = std::rand() % 2;
//     bool v2_sign = std::rand() % 2;
//     raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
//     raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
//   }

//   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
//       encrypto::motion::ToInput(raw_global_input_1),
//       encrypto::motion::ToInput(raw_global_input_2)};

//   //  std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
//   //  std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

//   std::vector<encrypto::motion::BitVector<>> dummy_input(
//       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
//                           &raw_global_input_1, &raw_global_input_2]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointCircuitCBMC
//           share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
//           share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
//                             1);
//       EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

//       std::size_t k = 32;
//       std::size_t f = 16;

//       share_0.SetFixedPointFormat(k, f);
//       share_1.SetFixedPointFormat(k, f);

//       const auto share_result = share_0 < share_1;
//       auto share_output = share_result.Out();

//       // std::size_t k = share_0.k_;
//       // std::size_t f = share_0.f_;

//       motion_parties.at(party_id)->Run();
//       motion_parties.at(party_id)->Finish();
//       if (party_0) {
//         BitVector<> result_T;
//         result_T = share_output.As<BitVector<>>();

//         for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//           bool expect_result_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) <
//                                  FixedPointToDouble<T, T_int>(raw_global_input_2[i], k, f);
//           EXPECT_EQ(result_T[i], expect_result_i);
//         }
//       }
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointCircuitCBMCk32f16BgmwTest, LessThanConstantSIMDInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   using A = std::allocator<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1000};
//   std::srand(std::time(nullptr));

//   std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
//   std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
//   T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

//   for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//     raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
//     raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

//     // adjust the sign
//     bool v1_sign = std::rand() % 2;
//     bool v2_sign = std::rand() % 2;
//     raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
//     raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
//   }

//   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
//       encrypto::motion::ToInput(raw_global_input_1),
//       encrypto::motion::ToInput(raw_global_input_2)};

//   //  std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
//   //  std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

//   std::vector<encrypto::motion::BitVector<>> dummy_input(
//       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
//                           &raw_global_input_1, &raw_global_input_2]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointCircuitCBMC
//           share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
//           share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
//                             1);
//       EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

//       std::size_t k = 32;
//       std::size_t f = 16;

//       share_0.SetFixedPointFormat(k, f);
//       share_1.SetFixedPointFormat(k, f);

//       const auto share_result =
//           share_0 < double(FixedPointToDouble<T, T_int>(raw_global_input_2[0], k, f));
//       auto share_output = share_result.Out();

//       // std::size_t k = share_0.k_;
//       // std::size_t f = share_0.f_;

//       motion_parties.at(party_id)->Run();
//       motion_parties.at(party_id)->Finish();
//       if (party_0) {
//         BitVector<> result_T;
//         result_T = share_output.As<BitVector<>>();

//         for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//           bool expect_result_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) <
//                                  FixedPointToDouble<T, T_int>(raw_global_input_2[0], k, f);
//           EXPECT_EQ(result_T[i], expect_result_i);
//         }
//       }
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointCircuitCBMCk32f16BgmwTest, GreaterThanInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1};
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   std::srand(std::time(nullptr));

//   std::vector<T> raw_global_input = ::RandomVector<T>(2);
//   T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

//   raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
//   raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

//   // adjust the sign
//   bool v1_sign = std::rand() % 2;
//   bool v2_sign = std::rand() % 2;
//   raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
//   raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

//   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
//       encrypto::motion::ToInput(raw_global_input.at(0)),
//       encrypto::motion::ToInput(raw_global_input.at(1))};

//   //  std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
//   //  std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

//   std::vector<encrypto::motion::BitVector<>> dummy_input(
//       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
//                           &raw_global_input]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointCircuitCBMC
//           share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
//           share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
//                             1);
//       EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

//       std::size_t k = 32;
//       std::size_t f = 16;

//       share_0.SetFixedPointFormat(k, f);
//       share_1.SetFixedPointFormat(k, f);

//       const auto share_result = share_0 > share_1;
//       auto share_output = share_result.Out();

//       // std::size_t k = share_0.k_;
//       // std::size_t f = share_0.f_;

//       // std::cout << "k: " << k << std::endl;
//       // std::cout << "f: " << f << std::endl;

//       motion_parties.at(party_id)->Run();
//       const bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) >
//                                  FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);
//       std::cout << "raw_global_input.at(0): " << T_int(raw_global_input.at(0)) << std::endl;
//       std::cout << "raw_global_input.at(1): " << T_int(raw_global_input.at(1)) << std::endl;
//       std::cout << "raw_global_input.at(0)_double: "
//                 << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
//       std::cout << "raw_global_input.at(1)_double: "
//                 << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;
//       std::cout << "expect_result: " << expect_result << std::endl;

//       bool result_T;

//       result_T = share_output.As<bool>();
//       std::cout << "result_T: " << result_T << std::endl;

//       EXPECT_EQ(result_T, expect_result);

//       motion_parties.at(party_id)->Finish();
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointCircuitCBMCk32f16BgmwTest, GreaterThanSIMDInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   using A = std::allocator<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1000};
//   std::srand(std::time(nullptr));

//   std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
//   std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
//   T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

//   for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//     raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
//     raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

//     // adjust the sign
//     bool v1_sign = std::rand() % 2;
//     bool v2_sign = std::rand() % 2;
//     raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
//     raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
//   }

//   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
//       encrypto::motion::ToInput(raw_global_input_1),
//       encrypto::motion::ToInput(raw_global_input_2)};

//   //  std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
//   //  std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

//   std::vector<encrypto::motion::BitVector<>> dummy_input(
//       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
//                           &raw_global_input_1, &raw_global_input_2]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointCircuitCBMC
//           share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
//           share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
//                             1);
//       EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

//       std::size_t k = 32;
//       std::size_t f = 16;

//       share_0.SetFixedPointFormat(k, f);
//       share_1.SetFixedPointFormat(k, f);

//       const auto share_result = share_0 > share_1;
//       auto share_output = share_result.Out();

//       // std::size_t k = share_0.k_;
//       // std::size_t f = share_0.f_;

//       motion_parties.at(party_id)->Run();
//       motion_parties.at(party_id)->Finish();
//       if (party_0) {
//         BitVector<> result_T;
//         result_T = share_output.As<BitVector<>>();

//         for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//           bool expect_result_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) >
//                                  FixedPointToDouble<T, T_int>(raw_global_input_2[i], k, f);
//           EXPECT_EQ(result_T[i], expect_result_i);
//         }
//       }
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointCircuitCBMCk32f16BgmwTest, EqualityInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1};
//   std::srand(std::time(nullptr));

//   std::vector<T> raw_global_input = ::RandomVector<T>(2);
//   T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

//   raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
//   raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

//   // adjust the sign
//   bool v1_sign = std::rand() % 2;
//   bool v2_sign = std::rand() % 2;
//   raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
//   raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

//   std::size_t edge_case = std::rand() % 5;
//   if (edge_case == 0) {
//     raw_global_input.at(0) = raw_global_input.at(1);
//   } else if (edge_case == 1) {
//     raw_global_input.at(0) = 0;
//   } else if (edge_case == 2) {
//     raw_global_input.at(1) = 0;
//   } else if (edge_case == 3) {
//     raw_global_input.at(0) = 0;
//     raw_global_input.at(1) = 0;
//   }

//   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
//       encrypto::motion::ToInput(raw_global_input.at(0)),
//       encrypto::motion::ToInput(raw_global_input.at(1))};

//   //  std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
//   //  std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

//   std::vector<encrypto::motion::BitVector<>> dummy_input(
//       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
//                           &raw_global_input]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointCircuitCBMC
//           share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
//           share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
//                             1);
//       EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

//       std::size_t k = 32;
//       std::size_t f = 16;

//       share_0.SetFixedPointFormat(k, f);
//       share_1.SetFixedPointFormat(k, f);

//       const auto share_result = share_0 == share_1;
//       auto share_output = share_result.Out();

//       // std::size_t k = share_0.k_;
//       // std::size_t f = share_0.f_;

//       // std::cout << "k: " << k << std::endl;
//       // std::cout << "f: " << f << std::endl;

//       motion_parties.at(party_id)->Run();
//       const bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) ==
//                                  FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);
//       std::cout << "raw_global_input.at(0): " << T_int(raw_global_input.at(0)) << std::endl;
//       std::cout << "raw_global_input.at(1): " << T_int(raw_global_input.at(1)) << std::endl;
//       std::cout << "raw_global_input.at(0)_double: "
//                 << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
//       std::cout << "raw_global_input.at(1)_double: "
//                 << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;
//       std::cout << "expect_result: " << expect_result << std::endl;

//       bool result_T;

//       result_T = share_output.As<bool>();
//       std::cout << "result_T: " << result_T << std::endl;

//       EXPECT_EQ(result_T, expect_result);

//       motion_parties.at(party_id)->Finish();
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointCircuitCBMCk32f16BgmwTest, EqualitySIMDInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   using A = std::allocator<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1000};
//   std::srand(std::time(nullptr));

//   std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
//   std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
//   T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

//   for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//     raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
//     raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

//     // adjust the sign
//     bool v1_sign = std::rand() % 2;
//     bool v2_sign = std::rand() % 2;
//     raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
//     raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
//   }

//   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
//       encrypto::motion::ToInput(raw_global_input_1),
//       encrypto::motion::ToInput(raw_global_input_2)};

//   //  std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
//   //  std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

//   std::vector<encrypto::motion::BitVector<>> dummy_input(
//       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
//                           &raw_global_input_1, &raw_global_input_2]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointCircuitCBMC
//           share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
//           share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
//                             1);
//       EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

//       std::size_t k = 32;
//       std::size_t f = 16;

//       share_0.SetFixedPointFormat(k, f);
//       share_1.SetFixedPointFormat(k, f);

//       const auto share_result = share_0 == share_1;
//       auto share_output = share_result.Out();

//       // std::size_t k = share_0.k_;
//       // std::size_t f = share_0.f_;

//       motion_parties.at(party_id)->Run();
//       motion_parties.at(party_id)->Finish();
//       if (party_0) {
//         BitVector<> result_T;
//         result_T = share_output.As<BitVector<>>();

//         for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//           bool expect_result_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) ==
//                                  FixedPointToDouble<T, T_int>(raw_global_input_2[i], k, f);
//           EXPECT_EQ(result_T[i], expect_result_i);
//         }
//       }
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

// TYPED_TEST(SecureFixedPointCircuitCBMCk32f16BgmwTest, EqualityConstantSIMDInGmw) {
//   using T = TypeParam;
//   using T_int = get_int_type_t<T>;
//   using A = std::allocator<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{1000};
//   std::srand(std::time(nullptr));

//   std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
//   std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
//   T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

//   for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//     raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
//     raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

//     // adjust the sign
//     bool v1_sign = std::rand() % 2;
//     bool v2_sign = std::rand() % 2;
//     raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
//     raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
//   }

//   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
//       encrypto::motion::ToInput(raw_global_input_1),
//       encrypto::motion::ToInput(raw_global_input_2)};

//   //  std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
//   //  std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

//   std::vector<encrypto::motion::BitVector<>> dummy_input(
//       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
//                           &raw_global_input_1, &raw_global_input_2]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointCircuitCBMC
//           share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
//           share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
//                             1);
//       EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

//       std::size_t k = 32;
//       std::size_t f = 16;

//       share_0.SetFixedPointFormat(k, f);
//       share_1.SetFixedPointFormat(k, f);

//       const auto share_result =
//           share_0 == double(FixedPointToDouble<T, T_int>(raw_global_input_2[0], k, f));
//       auto share_output = share_result.Out();

//       // std::size_t k = share_0.k_;
//       // std::size_t f = share_0.f_;

//       motion_parties.at(party_id)->Run();
//       motion_parties.at(party_id)->Finish();
//       if (party_0) {
//         BitVector<> result_T;
//         result_T = share_output.As<BitVector<>>();

//         for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//           bool expect_result_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) ==
//                                  FixedPointToDouble<T, T_int>(raw_global_input_2[0], k, f);
//           EXPECT_EQ(result_T[i], expect_result_i);
//         }
//       }
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

TYPED_TEST(SecureFixedPointCircuitCBMCk32f16BgmwTest, BitonicSortInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(std::time(nullptr));

  // number of elements in sequences
  std::size_t n = 8;
  //  std::size_t n=16;
  //  std::size_t n=32;
  // std::size_t n = 128;

  std::vector<T> raw_global_input = ::RandomVector<T>(n);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  for (std::size_t i = 0; i < n; i++) {
    raw_global_input[i] = raw_global_input[i] % fixed_point_mask;

    bool vi_sign = std::rand() % 2;
    raw_global_input[i] = raw_global_input[i] * (1 - 2 * vi_sign);
  }

  // // adjust the sign
  // bool v1_sign = std::rand() % 2;
  // bool v2_sign = std::rand() % 2;
  // raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  // raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

  std::size_t edge_case = std::rand() % 5;
  if (edge_case == 0) {
    raw_global_input.at(0) = raw_global_input.at(1);
  } else if (edge_case == 1) {
    raw_global_input.at(0) = 0;
  } else if (edge_case == 2) {
    raw_global_input.at(1) = 0;
  } else if (edge_case == 3) {
    raw_global_input.at(0) = 0;
    raw_global_input.at(1) = 0;
  }

  // std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
  //     encrypto::motion::ToInput(raw_global_input.at(0)),
  //     encrypto::motion::ToInput(raw_global_input.at(1))};

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input;
  global_input.reserve(n);
  for (std::size_t i = 0; i < n; i++) {
    global_input.emplace_back(encrypto::motion::ToInput(raw_global_input.at(i)));
  }

  //  std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
  //  std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

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
                          &raw_global_input, n]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      // encrypto::motion::SecureFixedPointCircuitCBMC
      //     share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
      //                       : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
      //     share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
      //                       : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
      //                       1);

      std::size_t k = 32;
      std::size_t f = 16;

      std::vector<encrypto::motion::ShareWrapper> share_sequence_vector;
      share_sequence_vector.reserve(n);
      for (std::size_t i = 0; i < n; ++i) {
        encrypto::motion::ShareWrapper share_0 =
            party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(i), 0)
                    : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0);

        // share_0.SetFixedPointFormat(k, f);

        EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

        share_sequence_vector.emplace_back(share_0);
      }

      std::vector<encrypto::motion::ShareWrapper> share_result_vector =
          share_sequence_vector[0].BitonicSort(share_sequence_vector, 0, n, 1);

      std::vector<encrypto::motion::SecureFixedPointCircuitCBMC> share_output_vector;
      share_output_vector.reserve(n);

      for (std::size_t i = 0; i < share_result_vector.size(); i++) {
        share_output_vector.emplace_back(
            encrypto::motion::SecureFixedPointCircuitCBMC(share_result_vector[i]).Out());
      }

      // std::size_t k = share_0.k_;
      // std::size_t f = share_0.f_;

      // std::cout << "k: " << k << std::endl;
      // std::cout << "f: " << f << std::endl;

      motion_parties.at(party_id)->Run();
      // const bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) ==
      //                            FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);
      // std::cout << "raw_global_input.at(0): " << T_int(raw_global_input.at(0)) << std::endl;
      // std::cout << "raw_global_input.at(1): " << T_int(raw_global_input.at(1)) << std::endl;
      // std::cout << "raw_global_input.at(0)_double: "
      //           << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
      // std::cout << "raw_global_input.at(1)_double: "
      //           << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;

      if (party_id == 0) {
        std::vector<double> global_input_fixed_point_vector;
        global_input_fixed_point_vector.reserve(n);

        std::cout << "raw_global_input: " << std::endl;
        for (std::size_t i = 0; i < n; ++i) {
          double global_input_fixed_point =
              FixedPointToDouble<T, T_int>(raw_global_input.at(i), k, f);
          std::cout << global_input_fixed_point << ", ";
          global_input_fixed_point_vector.emplace_back(global_input_fixed_point);
        }
        std::cout << std::endl;

        std::cout << "raw_global_input after sorting: " << std::endl;
        BitonicSort<double>(global_input_fixed_point_vector, 0, n, 1);
        for (std::size_t i = 0; i < n; ++i) {
          std::cout << global_input_fixed_point_vector[i] << ", ";
        }
        std::cout << std::endl;

        std::cout << "output_sequence: " << std::endl;
        for (std::size_t i = 0; i < n; ++i) {
          double result_T = share_output_vector[i].AsFixedPoint<T, T_int>();
          std::cout << result_T << ", ";

          EXPECT_EQ(result_T, global_input_fixed_point_vector[i]);
        }
        std::cout << std::endl;
      }

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCk32f16BgmwTest, BitonicSortExtensionInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(std::time(nullptr));

  // number of elements in sequences
  // std::size_t n = 2;
  //  std::size_t n=16;
  //  std::size_t n=32;
  std::size_t n = 128;

  std::vector<T> raw_global_input = ::RandomVector<T>(n);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  for (std::size_t i = 0; i < n; i++) {
    raw_global_input[i] = raw_global_input[i] % fixed_point_mask;

    bool vi_sign = std::rand() % 2;
    raw_global_input[i] = raw_global_input[i] * (1 - 2 * vi_sign);
  }

  std::vector<T> raw_global_input_accompany = ::RandomVector<T>(n);
  // T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  for (std::size_t i = 0; i < n; i++) {
    raw_global_input_accompany[i] = raw_global_input_accompany[i] % fixed_point_mask;

    bool vi_sign = std::rand() % 2;
    raw_global_input_accompany[i] = raw_global_input_accompany[i] * (1 - 2 * vi_sign);
  }

  // // adjust the sign
  // bool v1_sign = std::rand() % 2;
  // bool v2_sign = std::rand() % 2;
  // raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  // raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

  std::size_t edge_case = std::rand() % 5;
  if (edge_case == 0) {
    raw_global_input.at(0) = raw_global_input.at(1);
  } else if (edge_case == 1) {
    raw_global_input.at(0) = 0;
  } else if (edge_case == 2) {
    raw_global_input.at(1) = 0;
  } else if (edge_case == 3) {
    raw_global_input.at(0) = 0;
    raw_global_input.at(1) = 0;
  }

  // std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
  //     encrypto::motion::ToInput(raw_global_input.at(0)),
  //     encrypto::motion::ToInput(raw_global_input.at(1))};

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input;
  global_input.reserve(n);
  for (std::size_t i = 0; i < n; i++) {
    global_input.emplace_back(encrypto::motion::ToInput(raw_global_input.at(i)));
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input_accompany;
  global_input_accompany.reserve(n);
  for (std::size_t i = 0; i < n; i++) {
    global_input_accompany.emplace_back(
        encrypto::motion::ToInput(raw_global_input_accompany.at(i)));
  }

  //  std::cout << "raw_global_input.at(0): " << raw_global_input.at(0) << std::endl;
  //  std::cout << "raw_global_input.at(1): " << raw_global_input.at(1) << std::endl;

  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input,
                          &global_input_accompany, &dummy_input, &raw_global_input,
                          &raw_global_input_accompany, n]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      // encrypto::motion::SecureFixedPointCircuitCBMC
      //     share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
      //                       : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
      //     share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
      //                       : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
      //                       1);

      std::size_t k = 32;
      std::size_t f = 16;

      std::vector<encrypto::motion::ShareWrapper> share_sequence_vector;
      share_sequence_vector.reserve(n);

      std::vector<encrypto::motion::ShareWrapper> share_sequence_accompany_vector;
      share_sequence_accompany_vector.reserve(n);

      for (std::size_t i = 0; i < n; ++i) {
        encrypto::motion::ShareWrapper share_0 =
            party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(i), 0)
                    : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0);

        encrypto::motion::ShareWrapper share_0_accompany =
            party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input_accompany.at(i), 0)
                    : motion_parties.at(party_id)->In<kBooleanGmw>(global_input_accompany.at(i), 0);

        // share_0.SetFixedPointFormat(k, f);

        EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

        share_sequence_vector.emplace_back(share_0);
        share_sequence_accompany_vector.emplace_back(share_0_accompany);
      }

      // std::cout << "000" << std::endl;

      std::vector<encrypto::motion::ShareWrapper> share_result_accompany_vector =
          share_sequence_vector[0].BitonicSortExtension(share_sequence_vector,
                                                        share_sequence_accompany_vector, 0, n, 1);

      // // only for debugging
      //       std::vector<encrypto::motion::ShareWrapper> share_result_vector =
      //           share_sequence_vector[0].BitonicSort(share_sequence_vector, 0, n, 1);

      // std::cout << "001" << std::endl;

      std::vector<encrypto::motion::SecureFixedPointCircuitCBMC> share_output_vector;
      share_output_vector.reserve(n);

      std::vector<encrypto::motion::SecureFixedPointCircuitCBMC> share_output_accompany_vector;
      share_output_accompany_vector.reserve(n);

      for (std::size_t i = 0; i < n; i++) {
        share_output_vector.emplace_back(
            encrypto::motion::SecureFixedPointCircuitCBMC(share_sequence_vector[i]).Out());

        share_output_accompany_vector.emplace_back(
            encrypto::motion::SecureFixedPointCircuitCBMC(share_result_accompany_vector[i]).Out());
      }

      // std::size_t k = share_0.k_;
      // std::size_t f = share_0.f_;

      // std::cout << "k: " << k << std::endl;
      // std::cout << "f: " << f << std::endl;

      std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      // const bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) ==
      //                            FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);
      // std::cout << "raw_global_input.at(0): " << T_int(raw_global_input.at(0)) << std::endl;
      // std::cout << "raw_global_input.at(1): " << T_int(raw_global_input.at(1)) << std::endl;
      // std::cout << "raw_global_input.at(0)_double: "
      //           << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
      // std::cout << "raw_global_input.at(1)_double: "
      //           << FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f) << std::endl;

      if (party_id == 0) {
        std::vector<double> global_input_fixed_point_vector;
        global_input_fixed_point_vector.reserve(n);

        std::vector<double> global_input_fixed_point_accompany_vector;
        global_input_fixed_point_accompany_vector.reserve(n);

        std::cout << "raw_global_input: " << std::endl;
        for (std::size_t i = 0; i < n; ++i) {
          double global_input_fixed_point =
              FixedPointToDouble<T, T_int>(raw_global_input.at(i), k, f);
          std::cout << global_input_fixed_point << ", ";
          global_input_fixed_point_vector.emplace_back(global_input_fixed_point);
        }
        std::cout << std::endl;

        std::cout << "raw_global_input_accompany: " << std::endl;
        for (std::size_t i = 0; i < n; ++i) {
          double global_accompany_input_fixed_point =
              FixedPointToDouble<T, T_int>(raw_global_input_accompany.at(i), k, f);
          std::cout << global_accompany_input_fixed_point << ", ";
          global_input_fixed_point_accompany_vector.emplace_back(
              global_accompany_input_fixed_point);
        }

        std::cout << std::endl;
        std::cout << std::endl;

        std::cout << "raw_global_input after sorting: " << std::endl;
        BitonicSortExtension<double>(global_input_fixed_point_vector,
                                     global_input_fixed_point_accompany_vector, 0, n, 1);
        for (std::size_t i = 0; i < n; ++i) {
          std::cout << global_input_fixed_point_vector[i] << ", ";
        }
        std::cout << std::endl;

        std::cout << "raw_global_input_accompany after sorting: " << std::endl;
        for (std::size_t i = 0; i < n; ++i) {
          std::cout << global_input_fixed_point_accompany_vector[i] << ", ";
        }
        std::cout << std::endl;
        std::cout << std::endl;

        std::cout << "output_sequence after sorting: " << std::endl;
        for (std::size_t i = 0; i < n; ++i) {
          double result_T = share_output_vector[i].AsFixedPoint<T, T_int>();
          std::cout << result_T << ", ";

          EXPECT_EQ(result_T, global_input_fixed_point_vector[i]);
        }
        std::cout << std::endl;

        std::cout << "output_accompany_sequence after sorting: " << std::endl;
        for (std::size_t i = 0; i < n; ++i) {
          double result_T = share_output_accompany_vector[i].AsFixedPoint<T, T_int>();
          std::cout << result_T << ", ";

          EXPECT_EQ(result_T, global_input_fixed_point_accompany_vector[i]);
        }
        std::cout << std::endl;
      }

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

}  // namespace
