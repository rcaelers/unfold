// Copyright (C) 2025 Rob Caelers <rob.caelers@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifndef MERKLE_TREE_VALIDATOR_HH
#define MERKLE_TREE_VALIDATOR_HH

#include <string>
#include <memory>
#include <cstdint>
#include <spdlog/logger.h>
#include <boost/outcome/std_result.hpp>

#include "RFC6962Hasher.hh"
#include "utils/Logging.hh"

#include <google/protobuf/repeated_ptr_field.h>

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  class MerkleTreeValidator
  {
  public:
    MerkleTreeValidator();
    ~MerkleTreeValidator() = default;

    MerkleTreeValidator(const MerkleTreeValidator &) = delete;
    MerkleTreeValidator &operator=(const MerkleTreeValidator &) = delete;
    MerkleTreeValidator(MerkleTreeValidator &&) = delete;
    MerkleTreeValidator &operator=(MerkleTreeValidator &&) = delete;

    outcome::std_result<bool> verify_inclusion_proof(const ::google::protobuf::RepeatedPtrField<std::string> &proof,
                                                     int64_t leaf_index,
                                                     int64_t tree_size,
                                                     const std::string &leaf_hash,
                                                     const std::string &root_hash);

  private:
    outcome::std_result<std::string> compute_merkle_root(const ::google::protobuf::RepeatedPtrField<std::string> &proof,
                                                         int64_t leaf_index,
                                                         int64_t tree_size,
                                                         const std::string &leaf_hash);
    std::pair<int, int> split_inclusion_proof(std::uint64_t index, std::uint64_t size);

  private:
    RFC6962Hasher hasher_;
    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:merkletree")};
  };

} // namespace unfold::sigstore

#endif // MERKLE_TREE_VALIDATOR_HH
