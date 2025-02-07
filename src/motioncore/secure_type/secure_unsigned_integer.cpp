// MIT License
//
// Copyright (c) 2021-2022 Oleksandr Tkachenko, Arianne Roselina Prananto, Liang Zhao
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

#include "secure_unsigned_integer.h"

#include <fmt/format.h>
#include <iterator>

#include "algorithm/algorithm_description.h"
#include "algorithm/boolean_algorithms.h"
#include "base/backend.h"
#include "base/register.h"
// #include "protocols/constant/constant_share_wrapper.h"
#include "protocols/data_management/unsimdify_gate.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace encrypto::motion {

SecureUnsignedInteger::SecureUnsignedInteger(const SharePointer& other)
    : share_(std::make_unique<ShareWrapper>(other)),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

SecureUnsignedInteger::SecureUnsignedInteger(SharePointer&& other)
    : share_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

SecureUnsignedInteger SecureUnsignedInteger::operator+(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    // use primitive operation in arithmetic GMW
    return *share_ + *other.share_;
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> addition_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kAdd, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kAdd, bitlength, "_depth");

    if ((addition_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer addition circuit with file path {}", path));
      }
    } else {
      addition_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(addition_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer addition circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureUnsignedInteger(share_input.Evaluate(addition_algorithm));
  }
}

SecureUnsignedInteger SecureUnsignedInteger::operator-(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    // use primitive operation in arithmetic GMW
    return *share_ - *other.share_;
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> subtraction_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kSub, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kSub, bitlength, "_depth");

    if ((subtraction_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean integer subtraction circuit with file path {}", path));
      }
    } else {
      subtraction_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(subtraction_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean integer subtraction circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureUnsignedInteger(share_input.Evaluate(subtraction_algorithm));
  }
}

SecureUnsignedInteger SecureUnsignedInteger::operator*(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    // use primitive operation in arithmetic GMW
    return *share_ * *other.share_;
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> multiplication_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kMul, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kMul, bitlength, "_depth");

    if ((multiplication_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean integer multiplication circuit with file path {}", path));
      }
    } else {
      multiplication_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(multiplication_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean integer multiplication circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureUnsignedInteger(share_input.Evaluate(multiplication_algorithm));
  }
}

// ! depth and size of the generated circuits are the same, i.e., the depth circuits is not highly
// optimized
SecureUnsignedInteger SecureUnsignedInteger::operator/(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer division is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> division_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kDiv, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kDiv, bitlength, "_depth");

    if ((division_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer division circuit with file path {}", path));
      }
    } else {
      division_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(division_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer division circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureUnsignedInteger(share_input.Evaluate(division_algorithm));
  }
}

ShareWrapper SecureUnsignedInteger::operator<(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    if (share_->Get()->GetProtocol() == MpcProtocol::kArithmeticGmw) {
      return *other.share_ > *share_;
    }
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer comparison is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> greater_than_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGt, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGt, bitlength, "_depth");

    if ((greater_than_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean integer greater than circuit with file path {}", path));
      }
    } else {
      greater_than_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(greater_than_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean integer greater than circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*other.share_, *share_})};
    return share_input.Evaluate(greater_than_algorithm).Split().at(0);
  }
}

ShareWrapper SecureUnsignedInteger::operator>(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    if (share_->Get()->GetProtocol() == MpcProtocol::kArithmeticGmw) {
      return *share_ > *other.share_;
    }
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer comparison is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> greater_than_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGt, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGt, bitlength, "_depth");

    if ((greater_than_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer addition circuit with file path {}", path));
      }
    } else {
      greater_than_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(greater_than_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer addition circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return share_input.Evaluate(greater_than_algorithm).Split().at(0);
  }
}

ShareWrapper SecureUnsignedInteger::operator==(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer equality check is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    if constexpr (kDebug) {
      if (other->GetProtocol() == MpcProtocol::kBmr) {
        logger_->LogDebug("Creating a Boolean equality circuit in BMR");
      } else if (share_->Get()->GetProtocol() == MpcProtocol::kGarbledCircuit) {
        logger_->LogDebug("Creating a Boolean equality circuit in YAO");
      } else if (share_->Get()->GetProtocol() == MpcProtocol::kBooleanGmw) {
        logger_->LogDebug("Creating a Boolean equality circuit in GMW");
      }
    }
    return this->Get() == other.Get();
  }
}

template <typename T, typename>
SecureUnsignedInteger SecureUnsignedInteger::operator+(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput(constant_value);

  return *this + unsigned_integer_constant;
}

template SecureUnsignedInteger SecureUnsignedInteger::operator+
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator+
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator+
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator+
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator+
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
SecureUnsignedInteger SecureUnsignedInteger::operator-(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput<T>(constant_value);

  return *this - unsigned_integer_constant;
}

template SecureUnsignedInteger SecureUnsignedInteger::operator-
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator-
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator-
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator-
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator-
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
SecureUnsignedInteger SecureUnsignedInteger::operator*(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput<T>(constant_value);

  return *this * unsigned_integer_constant;
}

template SecureUnsignedInteger SecureUnsignedInteger::operator*
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator*
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator*
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator*
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator*
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
SecureUnsignedInteger SecureUnsignedInteger::operator/(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput<T>(constant_value);

  return *this / unsigned_integer_constant;
}

template SecureUnsignedInteger SecureUnsignedInteger::operator/
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator/
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator/
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator/
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator/
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
ShareWrapper SecureUnsignedInteger::operator<(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput<T>(constant_value);

  return *this < unsigned_integer_constant;
}

template ShareWrapper SecureUnsignedInteger::operator< <std::uint8_t>(
    const std::uint8_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator< <std::uint16_t>(
    const std::uint16_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator< <std::uint32_t>(
    const std::uint32_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator< <std::uint64_t>(
    const std::uint64_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator< <__uint128_t>(
    const __uint128_t& constant_value) const;

template <typename T, typename>
ShareWrapper SecureUnsignedInteger::operator>(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput<T>(constant_value);

  return *this > unsigned_integer_constant;
}
template ShareWrapper SecureUnsignedInteger::operator>
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator>
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator>
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator>
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator>
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
ShareWrapper SecureUnsignedInteger::operator==(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput<T>(constant_value);

  return *this == unsigned_integer_constant;
}
template ShareWrapper SecureUnsignedInteger::operator==
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator==
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator==
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator==
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator==
    <__uint128_t>(const __uint128_t& constant_value) const;

// TODO: test
SecureUnsignedInteger SecureUnsignedInteger::MulBooleanBit(
    const ShareWrapper& boolean_gmw_bmr_gc_bit_share_other) const {
  assert(boolean_gmw_bmr_gc_bit_share_other->GetProtocol() == MpcProtocol::kBooleanGmw ||
         boolean_gmw_bmr_gc_bit_share_other->GetProtocol() == MpcProtocol::kBmr ||
         boolean_gmw_bmr_gc_bit_share_other->GetProtocol() == MpcProtocol::kGarbledCircuit);
  assert(boolean_gmw_bmr_gc_bit_share_other->GetWires().size() == 1);

  SecureUnsignedInteger result = boolean_gmw_bmr_gc_bit_share_other.XCOTMul(*share_);
  return result;
}

ShareWrapper SecureUnsignedInteger::IsZero() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer is_zero check is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> is_zero_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kIsZero, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kIsZero, bitlength, "_depth");

    if ((is_zero_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer is_zero circuit with file path {}", path));
      }
    } else {
      is_zero_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(is_zero_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer is_zero circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    return share_input.Evaluate(is_zero_algorithm).Split().at(0);
  }
}

// ! depth and size of the circuits are the same, i.e., the depth circuits is not optimized
SecureUnsignedInteger SecureUnsignedInteger::Mod(
    const SecureUnsignedInteger& secure_unsigned_integer_m) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer modular reduction is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> mod_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kMod, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kMod, bitlength, "_depth");

    if ((mod_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean integer modular reduction circuit with file path {}", path));
      }
    } else {
      mod_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(mod_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean integer modular reduction circuit from file {}", path));
      }
    }
    const auto share_input{
        ShareWrapper::Concatenate(std::vector{*share_, *secure_unsigned_integer_m.share_})};
    return share_input.Evaluate(mod_algorithm);
  }
}

template <typename T>
SecureUnsignedInteger SecureUnsignedInteger::Mod(const T& integer_m) const {
  SecureUnsignedInteger unsigned_integer_constant_m =
      share_->CreateConstantAsBooleanGmwBmrGCInput<T>(integer_m);

  return (*this).Mod(unsigned_integer_constant_m);
}

template SecureUnsignedInteger SecureUnsignedInteger::Mod<std::uint8_t>(
    const std::uint8_t& integer_m) const;
template SecureUnsignedInteger SecureUnsignedInteger::Mod<std::uint16_t>(
    const std::uint16_t& integer_m) const;
template SecureUnsignedInteger SecureUnsignedInteger::Mod<std::uint32_t>(
    const std::uint32_t& integer_m) const;
template SecureUnsignedInteger SecureUnsignedInteger::Mod<std::uint64_t>(
    const std::uint64_t& integer_m) const;
template SecureUnsignedInteger SecureUnsignedInteger::Mod<__uint128_t>(
    const __uint128_t& integer_m) const;

SecureUnsignedInteger SecureUnsignedInteger::Neg(
    const ShareWrapper& boolean_gmw_bmr_gc_share_sign) const {
  std::vector<ShareWrapper> boolean_gmw_bmr_gc_share_this_vector = share_->Split();
  std::vector<ShareWrapper> boolean_gmw_bmr_gc_share_this_invert_vector;
  boolean_gmw_bmr_gc_share_this_invert_vector.reserve(boolean_gmw_bmr_gc_share_this_vector.size());
  for (ShareWrapper boolean_gmw_bmr_gc_share_this_wire : boolean_gmw_bmr_gc_share_this_vector) {
    boolean_gmw_bmr_gc_share_this_invert_vector.emplace_back(~boolean_gmw_bmr_gc_share_this_wire);
    // std::cout << "boolean_gmw_bmr_gc_share_this_wire->GetBitLength(): "
    //           << boolean_gmw_bmr_gc_share_this_wire->GetBitLength() << std::endl;
  }

  // std::cout << "boolean_gmw_bmr_gc_share_sign->GetBitLength(): " <<
  // boolean_gmw_bmr_gc_share_sign->GetBitLength()
  //           << std::endl;

  // std::cout << "AdderChain" << std::endl;
  ShareWrapper unsigned_integer_twos_complement_with_overflow_bit =
      encrypto::motion::algorithm::AdderChain(boolean_gmw_bmr_gc_share_this_invert_vector,
                                              boolean_gmw_bmr_gc_share_sign);

  std::vector<ShareWrapper> unsigned_integer_twos_complement_with_overflow_bit_vector =
      unsigned_integer_twos_complement_with_overflow_bit.Split();

  std::vector<ShareWrapper> unsigned_integer_twos_complement_vector(
      unsigned_integer_twos_complement_with_overflow_bit_vector.begin(),
      unsigned_integer_twos_complement_with_overflow_bit_vector.end() - 1);

  // return (boolean_gmw_bmr_gc_share_sign.XCOTMul(
  //            ShareWrapper::Concatenate(unsigned_integer_twos_complement_vector))) ^
  //        ((~boolean_gmw_bmr_gc_share_sign).XCOTMul(this->Get()));

  return boolean_gmw_bmr_gc_share_sign.Mux(
      ShareWrapper::Concatenate(unsigned_integer_twos_complement_vector), this->Get());
}

SecureUnsignedInteger SecureUnsignedInteger::Neg() const {
  std::size_t number_of_simd = (*share_)->GetNumberOfSimdValues();

  std::vector<ShareWrapper> boolean_gmw_bmr_gc_share_this_vector = share_->Split();
  std::vector<ShareWrapper> boolean_gmw_bmr_gc_share_this_invert_vector;
  boolean_gmw_bmr_gc_share_this_invert_vector.reserve(boolean_gmw_bmr_gc_share_this_vector.size());
  for (ShareWrapper boolean_gmw_bmr_gc_share_this_wire : boolean_gmw_bmr_gc_share_this_vector) {
    boolean_gmw_bmr_gc_share_this_invert_vector.emplace_back(~boolean_gmw_bmr_gc_share_this_wire);
    // std::cout << "boolean_gmw_bmr_gc_share_this_wire->GetBitLength(): "
    //           << boolean_gmw_bmr_gc_share_this_wire->GetBitLength() << std::endl;
  }

  // ShareWrapper constant_boolean_gmw_bmr_gc_share_one =
  //     boolean_gmw_bmr_gc_share_this_vector[0] ^ (~boolean_gmw_bmr_gc_share_this_vector[0]);
  ShareWrapper constant_boolean_gmw_bmr_gc_share_one =
      share_->CreateConstantAsBooleanGmwBmrGCInput(true, number_of_simd);

  // std::cout << "boolean_gmw_bmr_gc_share_sign->GetBitLength(): " <<
  // boolean_gmw_bmr_gc_share_sign->GetBitLength()
  //           << std::endl;

  // std::cout << "AdderChain" << std::endl;
  ShareWrapper unsigned_integer_twos_complement_with_overflow_bit =
      encrypto::motion::algorithm::AdderChain(boolean_gmw_bmr_gc_share_this_invert_vector,
                                              constant_boolean_gmw_bmr_gc_share_one);

  std::vector<ShareWrapper> unsigned_integer_twos_complement_with_overflow_bit_vector =
      unsigned_integer_twos_complement_with_overflow_bit.Split();

  std::vector<ShareWrapper> unsigned_integer_twos_complement_vector(
      unsigned_integer_twos_complement_with_overflow_bit_vector.begin(),
      unsigned_integer_twos_complement_with_overflow_bit_vector.end() - 1);

  return (ShareWrapper::Concatenate(unsigned_integer_twos_complement_vector));

  // // only for debugging
  // return ((*this));
}

ShareWrapper SecureUnsignedInteger::GE(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error(
        "Integer greater than or equal to is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> ge_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGE, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGE, bitlength, "_depth");

    if ((ge_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean integer greater than or equal to circuit with file path {}",
            path));
      }
    } else {
      ge_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(ge_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Read Boolean integer greater than or equal to circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return share_input.Evaluate(ge_algorithm).Split().at(0);
  }
}
ShareWrapper SecureUnsignedInteger::LE(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error(
        "Integer greater than or equal to is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> ge_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGE, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGE, bitlength, "_depth");

    if ((ge_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean integer greater than or equal to circuit with file path {}",
            path));
      }
    } else {
      ge_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(ge_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Read Boolean integer greater than or equal to circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*other.share_, *share_})};
    return share_input.Evaluate(ge_algorithm).Split().at(0);
  }
}

// TODO: generate special circuit for unsigned integer
// use circuit for signed integer for now
SecureFloatingPointCircuitABY SecureUnsignedInteger::Int2FL(
    std::size_t floating_point_bit_length) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();

    std::shared_ptr<AlgorithmDescription> integer_to_floating_point_algorithm;
    std::string path;
    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kInt2FL, bitlength, "_size",
                           floating_point_bit_length);
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kInt2FL, bitlength, "_depth",
                           floating_point_bit_length);
    if ((integer_to_floating_point_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean integer to floating-point circuit with file path {}", path));
      }
    } else {
      integer_to_floating_point_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(integer_to_floating_point_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean integer to floating circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    const auto evaluation_result = share_input.Evaluate(integer_to_floating_point_algorithm);

    return evaluation_result;
  }
}

SecureFixedPointCircuitCBMC SecureUnsignedInteger::Int2Fx(std::size_t fraction_bit_size) const {
  std::size_t number_of_simd = (*share_)->GetNumberOfSimdValues();
  const auto bitlength = share_->Get()->GetBitLength();
  std::vector<ShareWrapper> boolean_gmw_bmr_gc_share_vector = share_->Split();

  // ShareWrapper fixed_point_boolean_gmw_bmr_gc_share = *(share_.get()) ^ *(share_.get());

  // ShareWrapper constant_boolean_gmw_bmr_gc_share_zero =
  //     boolean_gmw_bmr_gc_share_vector[0] ^ boolean_gmw_bmr_gc_share_vector[0];
  ShareWrapper constant_boolean_gmw_bmr_gc_share_zero =
      share_->CreateConstantAsBooleanGmwBmrGCInput(false, number_of_simd);

  std::vector<ShareWrapper> fixed_point_boolean_gmw_bmr_gc_share_vector(bitlength);
  for (std::size_t i = 0; i < bitlength; i++) {
    fixed_point_boolean_gmw_bmr_gc_share_vector[i] = constant_boolean_gmw_bmr_gc_share_zero;
  }

  for (std::size_t i = 0; i + fraction_bit_size < bitlength; i++) {
    fixed_point_boolean_gmw_bmr_gc_share_vector[i + fraction_bit_size] =
        boolean_gmw_bmr_gc_share_vector[i];
  }
  ShareWrapper fixed_point_boolean_gmw_bmr_gc_share =
      share_->Concatenate(fixed_point_boolean_gmw_bmr_gc_share_vector);

  return fixed_point_boolean_gmw_bmr_gc_share;
}

std::string SecureUnsignedInteger::ConstructPath(
    const UnsignedIntegerOperationType type, const std::size_t bitlength, std::string suffix,
    const std::size_t floating_point_bit_length) const {
  std::string operation_type_string;

  switch (type) {
    case UnsignedIntegerOperationType::kAdd: {
      operation_type_string = "add";
      break;
    }
    case UnsignedIntegerOperationType::kSub: {
      operation_type_string = "sub";
      break;
    }
    case UnsignedIntegerOperationType::kMul: {
      operation_type_string = "mul";
      break;
    }
    case UnsignedIntegerOperationType::kDiv: {
      operation_type_string = "div";
      break;
    }
    case UnsignedIntegerOperationType::kGt: {
      operation_type_string = "gt";
      break;
    }
    case UnsignedIntegerOperationType::kEq: {
      operation_type_string = "eq";
      break;
    }
    case UnsignedIntegerOperationType::kIsZero: {
      operation_type_string = "is_zero";
      break;
    }
    case UnsignedIntegerOperationType::kGE: {
      operation_type_string = "ge";
      break;
    }
    case UnsignedIntegerOperationType::kMod: {
      operation_type_string = "mod";
      break;
    }
    case UnsignedIntegerOperationType::kInt2FL: {
      operation_type_string = "to_float" + std::to_string(floating_point_bit_length);
      break;
    }

    default:
      throw std::runtime_error(
          fmt::format("Invalid integer operation required: {}", to_string(type)));
  }
  return fmt::format("{}/circuits/unsigned_integer/uint{}_{}{}.bristol", kRootDir, bitlength,
                     operation_type_string, suffix);
}

SecureUnsignedInteger SecureUnsignedInteger::Simdify(std::span<SecureUnsignedInteger> input) {
  std::vector<SharePointer> input_as_shares;
  input_as_shares.reserve(input.size());
  std::transform(input.begin(), input.end(), std::back_inserter(input_as_shares),
                 [&](SecureUnsignedInteger& i) -> SharePointer { return i.Get().Get(); });
  return SecureUnsignedInteger(ShareWrapper::Simdify(input_as_shares));
}

SecureUnsignedInteger SecureUnsignedInteger::Simdify(std::vector<SecureUnsignedInteger>&& input) {
  return Simdify(input);
}

SecureUnsignedInteger SecureUnsignedInteger::Subset(std::span<const size_t> positions) {
  ShareWrapper unwrap{this->Get()};
  return SecureUnsignedInteger(unwrap.Subset(positions));
}

SecureUnsignedInteger SecureUnsignedInteger::Subset(std::vector<size_t>&& positions) {
  return Subset(std::span<const std::size_t>(positions));
}

// added by Liang Zhao
ShareWrapper SecureUnsignedInteger::TruncateToHalfSize() {
  std::size_t bitlength = share_->Get()->GetBitLength();
  ShareWrapper unwrap{this->Get()};

  std::vector<ShareWrapper> truncated_unsigned_integer_vector;
  truncated_unsigned_integer_vector.reserve(bitlength / 2);

  std::vector<ShareWrapper> unsigned_integer_vector = unwrap.Split();

  for (std::size_t i = 0; i < bitlength / 2; i++) {
    // truncated_unsigned_integer_vector.emplace_back(unsigned_integer_vector[bitlength-i-1]);
    truncated_unsigned_integer_vector.emplace_back(unsigned_integer_vector[i]);
  }

  return (ShareWrapper::Concatenate(truncated_unsigned_integer_vector));
}

std::vector<SecureUnsignedInteger> SecureUnsignedInteger::Unsimdify() const {
  auto unsimdify_gate = share_->Get()->GetRegister()->EmplaceGate<UnsimdifyGate>(share_->Get());
  std::vector<SharePointer> shares{unsimdify_gate->GetOutputAsVectorOfShares()};
  std::vector<SecureUnsignedInteger> result(shares.size());
  std::transform(shares.begin(), shares.end(), result.begin(),
                 [](SharePointer share) { return SecureUnsignedInteger(share); });
  return result;
}

SecureUnsignedInteger SecureUnsignedInteger::Out(std::size_t output_owner) const {
  return SecureUnsignedInteger(share_->Out(output_owner));
}

template <typename Test, template <typename...> class Ref>
struct is_specialization : std::false_type {};

template <template <typename...> class Ref, typename... Args>
struct is_specialization<Ref<Args...>, Ref> : std::true_type {};

template <typename T>
T SecureUnsignedInteger::As() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic)
    return share_->As<T>();
  else if (share_->Get()->GetCircuitType() == CircuitType::kBoolean) {
    auto share_out = share_->As<std::vector<encrypto::motion::BitVector<>>>();
    if constexpr (std::is_unsigned<T>() || std::is_same<T, __uint128_t>()) {
      return encrypto::motion::ToOutput<T>(share_out);
    } else if constexpr (is_specialization<T, std::vector>::value &&
                         std::is_unsigned<typename T::value_type>()) {
      return encrypto::motion::ToVectorOutput<typename T::value_type>(share_out);
    } else {
      throw std::invalid_argument(
          fmt::format("Unsupported output type in SecureUnsignedInteger::As<{}>() for {} Protocol",
                      typeid(T).name(), to_string(share_->Get()->GetProtocol())));
    }
  } else {
    throw std::invalid_argument("Unsupported protocol for SecureUnsignedInteger::As()");
  }
}

template std::uint8_t SecureUnsignedInteger::As() const;
template std::uint16_t SecureUnsignedInteger::As() const;
template std::uint32_t SecureUnsignedInteger::As() const;
template std::uint64_t SecureUnsignedInteger::As() const;
template __uint128_t SecureUnsignedInteger::As() const;

template std::vector<std::uint8_t> SecureUnsignedInteger::As() const;
template std::vector<std::uint16_t> SecureUnsignedInteger::As() const;
template std::vector<std::uint32_t> SecureUnsignedInteger::As() const;
template std::vector<std::uint64_t> SecureUnsignedInteger::As() const;
template std::vector<__uint128_t> SecureUnsignedInteger::As() const;

template <typename T, typename A>
std::vector<T, A> SecureUnsignedInteger::AsVector() const {
  auto share_out = share_->As<std::vector<encrypto::motion::BitVector<>>>();
  std::vector<T> as_unsigned_output_vector = encrypto::motion::ToVectorOutput<T>(share_out);

  return as_unsigned_output_vector;
}

template std::vector<std::uint8_t> SecureUnsignedInteger::AsVector() const;
template std::vector<std::uint16_t> SecureUnsignedInteger::AsVector() const;
template std::vector<std::uint32_t> SecureUnsignedInteger::AsVector() const;
template std::vector<std::uint64_t> SecureUnsignedInteger::AsVector() const;
template std::vector<__uint128_t> SecureUnsignedInteger::AsVector() const;

}  // namespace encrypto::motion
