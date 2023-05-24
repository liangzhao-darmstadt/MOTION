// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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

#pragma once

#include <cstddef>
#include <string_view>

// added by Liang Zhao
#include <cstdint>

namespace encrypto::motion {

// kDebug flag is set true when compiler in Debug mode, i.e., CMAKE_BUILD_TYPE=Debug.
// If this flag equals true, MOTION will log information about the actions that happened, e.g., gate
// allocation and evaluation, OT extension, etc.
// clang-format off
constexpr bool kDebug{false};

// increase if something is changed fundamentally in MOTION and/or breaks the API,
// eg the backend class got replaced
constexpr std::uint16_t kMotionVersionMajor{0};
// increase on mainly externally visible changes implementing a feature, e.g., a new protocol
constexpr std::uint16_t kMotionVersionMinor{1};
// increase on bug fixes and small improvements
constexpr std::uint16_t kMotionVersionPatch{1};
constexpr std::string_view kRootDir{"/media/liangzhao/d5c709c3-5e6f-4fa2-b422-007a6f243cda/test_MOTION_DP_WAN/MOTION"};

// alignment for data buffers
constexpr std::size_t kAlignment{16};
// clang-format on

}  // namespace encrypto::motion
