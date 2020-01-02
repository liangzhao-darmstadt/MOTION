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

#include <cmath>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>

#include <fmt/format.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>

#include "base/party.h"
#include "common/benchmark_providers.h"
#include "statistics/analysis.h"
#include "utility/typedefs.h"

namespace po = boost::program_options;

bool CheckPartyArgumentSyntax(const std::string& p);

std::tuple<po::variables_map, bool, bool> ParseProgramOptions(int ac, char* av[]);

MOTION::PartyPtr CreateParty(const po::variables_map& vm);

int main(int ac, char* av[]) {
  auto [vm, help_flag, ots_flag] = ParseProgramOptions(ac, av);
  // if help flag is set - print allowed command line arguments and exit
  if (help_flag) EXIT_SUCCESS;
  const auto num_repetitions{vm["repetitions"].as<std::size_t>()};
  const auto batch_size{vm["batch-size"].as<std::size_t>()};

  struct Combination {
    Combination(Provider p, std::size_t bit_size, std::size_t batch_size)
        : p_(p), bit_size_(bit_size), batch_size_(batch_size) {}
    Provider p_;
    std::size_t bit_size_;
    std::size_t batch_size_;
  };

  // clang-format off
  std::vector<Combination> combs = {{AMT, 8, batch_size},
                                    {AMT, 16, batch_size},
                                    {AMT, 32, batch_size},
                                    {AMT, 64, batch_size},
                                    {BMT, 1, batch_size},
                                    {SB, 8, batch_size},
                                    {SB, 16, batch_size},
                                    {SB, 32, batch_size},
                                    {SB, 64, batch_size},
                                    {SP, 8, batch_size},
                                    {SP, 16, batch_size},
                                    {SP, 32, batch_size},
                                    {SP, 64, batch_size}};

  std::vector<Combination> combs_ots = {{GOT, 1, batch_size},
                                       {GOT, 128, batch_size},
                                       {XCOT, 1, batch_size},
                                       {XCOT, 128, batch_size},
                                       {ACOT, 8, batch_size},
                                       {ACOT, 16, batch_size},
                                       {ACOT, 32, batch_size},
                                       {ACOT, 64, batch_size},
                                       {ACOT, 128, batch_size},
                                       {ROT, 128, batch_size}};
  // clang-format on

  auto chosen_combs = ots_flag ? combs_ots : combs;
  for (const auto comb : chosen_combs) {
    MOTION::Statistics::AccumulatedRunTimeStats accumulated_stats;
    for (std::size_t i = 0; i < num_repetitions; ++i) {
      MOTION::PartyPtr party{CreateParty(vm)};
      // establish communication channels with other parties
      party->Connect();
      auto stats = BenchmarkProvider(party, comb.batch_size_, comb.p_, comb.bit_size_);
      accumulated_stats.add(stats);
    }
    std::cout << fmt::format("Provider {} bit size {} batch size {}\n", ToString(comb.p_),
                             comb.bit_size_, comb.batch_size_);
    std::cout << accumulated_stats.print_human_readable() << std::endl;
  }
  return EXIT_SUCCESS;
}

const std::regex party_argument_re("(\\d+),(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}),(\\d{1,5})");

bool CheckPartyArgumentSyntax(const std::string& p) {
  // other party's id, IP address, and port
  return std::regex_match(p, party_argument_re);
}

std::tuple<std::size_t, std::string, std::uint16_t> ParsePartyArgument(const std::string& p) {
  std::smatch match;
  std::regex_match(p, match, party_argument_re);
  auto id = boost::lexical_cast<std::size_t>(match[1]);
  auto host = match[2];
  auto port = boost::lexical_cast<std::uint16_t>(match[3]);
  return {id, host, port};
}

// <variables map, help flag>
std::tuple<po::variables_map, bool, bool> ParseProgramOptions(int ac, char* av[]) {
  using namespace std::string_view_literals;
  constexpr std::string_view config_file_msg =
      "config file, other arguments will overwrite the parameters read from the config file"sv;
  bool print, help, ots;
  boost::program_options::options_description desc("Allowed options");
  // clang-format off
  desc.add_options()
      ("help,h", po::bool_switch(&help)->default_value(false),"produce help message")
      ("disable-logging,l","disable logging to file")
      ("print-config,p", po::bool_switch(&print)->default_value(false), "print config")
      ("config-file,f", po::value<std::string>(), config_file_msg.data())
      ("my-id", po::value<std::size_t>(), "my party id")
      ("batch-size", po::value<std::size_t>()->default_value(1000000), "number of elements in the batch")
      ("other-parties", po::value<std::vector<std::string>>()->multitoken(), "(other party id, IP, port, my role), e.g., --other-parties 1,127.0.0.1,7777")
      ("online-after-setup", po::value<bool>()->default_value(true), "compute the online phase of the gate evaluations after the setup phase for all of them is completed (true/1 or false/0)")
      ("repetitions", po::value<std::size_t>()->default_value(1), "number of repetitions")
      ("ots,o", po::bool_switch(&ots)->default_value(false),"test OTs, otherwise all other providers");
  // clang-format on

  po::variables_map vm;

  po::store(po::parse_command_line(ac, av, desc), vm);
  po::notify(vm);

  // argument help or no arguments (at least a config file is expected)
  if (help) {
    std::cout << desc << "\n";
    return std::make_tuple<po::variables_map, bool, bool>({}, true, false);
  }

  // read config file
  if (vm.count("config-file")) {
    std::ifstream ifs(vm["config-file"].as<std::string>().c_str());
    po::variables_map vm_config_file;
    po::store(po::parse_config_file(ifs, desc), vm);
    po::notify(vm);
  }

  // print parsed parameters
  if (vm.count("my-id")) {
    if (print) std::cout << "My id " << vm["my-id"].as<std::size_t>() << std::endl;
  } else
    throw std::runtime_error("My id is not set but required");

  if (vm.count("other-parties")) {
    const std::vector<std::string> other_parties{
        vm["other-parties"].as<std::vector<std::string>>()};
    std::string parties("Other parties: ");
    for (auto& p : other_parties) {
      if (CheckPartyArgumentSyntax(p)) {
        if (print) parties.append(" " + p);
      } else {
        throw std::runtime_error("Incorrect party argument syntax " + p);
      }
    }
    if (print) std::cout << parties << std::endl;
  } else
    throw std::runtime_error("Other parties' information is not set but required");

  if (print) {
    std::cout << "Number of SIMD AES evaluations: " << vm["num-simd"].as<std::size_t>()
              << std::endl;

    std::cout << "MPC Protocol: " << vm["protocol"].as<std::string>() << std::endl;
  }
  return std::make_tuple(vm, help, ots);
}

MOTION::PartyPtr CreateParty(const po::variables_map& vm) {
  const auto parties_str{vm["other-parties"].as<const std::vector<std::string>>()};
  const auto num_parties{parties_str.size() + 1};
  const auto my_id{vm["my-id"].as<std::size_t>()};
  if (my_id >= num_parties) {
    throw std::runtime_error(fmt::format(
        "My id needs to be in the range [0, #parties - 1], current my id is {} and #parties is {}",
        my_id, num_parties));
  }

  // create communication contexts for other parties
  std::vector<MOTION::Communication::ContextPtr> contexts;
  for (const auto& party_str : parties_str) {
    const auto [other_id, host, port] = ParsePartyArgument(party_str);
    if (other_id >= num_parties) {
      throw std::runtime_error(
          fmt::format("Other party's id needs to be in the range [0, #parties - 1], current id "
                      "is {} and #parties is {}",
                      other_id, num_parties));
    }
    const auto role{other_id < my_id ? MOTION::Role::Client : MOTION::Role::Server};
    contexts.emplace_back(
        std::make_shared<MOTION::Communication::Context>(host, port, role, other_id));
  }
  // create config for my party
  auto config{std::make_shared<MOTION::Configuration>(std::move(contexts), my_id)};
  // disable logging if the corresponding flag was set
  const auto logging{!vm.count("disable-logging")};
  config->SetLoggingEnabled(logging);
  config->SetOnlineAfterSetup(vm["online-after-setup"].as<bool>());
  // create party object using the given config
  return std::make_unique<MOTION::Party>(config);
}
