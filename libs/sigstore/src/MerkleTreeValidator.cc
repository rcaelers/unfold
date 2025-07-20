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

#include "MerkleTreeValidator.hh"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <bit>

#include "sigstore/SigstoreErrors.hh"
#include "utils/Base64.hh"

namespace unfold::sigstore
{
  constexpr size_t DEFAULT_HASH_PREVIEW_BYTES = 32;

  std::string binary_to_hex_preview(const std::string &binary_data, size_t max_bytes = DEFAULT_HASH_PREVIEW_BYTES)
  {
    std::stringstream ss;
    size_t bytes_to_show = std::min(max_bytes, binary_data.size());
    for (size_t i = 0; i < bytes_to_show; ++i)
      {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<unsigned int>(static_cast<unsigned char>(binary_data[i]));
      }
    if (binary_data.size() > bytes_to_show)
      {
        ss << "...";
      }
    return ss.str();
  }

  MerkleTreeValidator::MerkleTreeValidator() = default;

  outcome::std_result<bool> MerkleTreeValidator::verify_inclusion_proof(const std::vector<std::string> &proof,
                                                                        int64_t leaf_index,
                                                                        int64_t tree_size,
                                                                        const std::string &leaf_hash,
                                                                        const std::string &root_hash)
  {
    try
      {
        logger_->debug("Verifying inclusion proof for leaf hash: {}", binary_to_hex_preview(leaf_hash));

        auto computed_root = compute_merkle_root(proof, leaf_index, tree_size, leaf_hash);
        if (!computed_root)
          {
            logger_->error("Failed to compute Merkle root hash: {}", computed_root.error().message());
            return computed_root.error();
          }
        std::string expected_root = unfold::utils::Base64::decode(root_hash);

        logger_->debug("Merkle tree computation:");
        logger_->debug("  Using proof log index: {}", leaf_index);
        logger_->debug("  Tree size: {}", tree_size);
        logger_->debug("  Computed root hash: {}", binary_to_hex_preview(computed_root.value()));
        logger_->debug("  Expected root hash: {}", binary_to_hex_preview(expected_root));

        bool is_valid = (computed_root.value() == expected_root);

        if (is_valid)
          {
            logger_->debug("Inclusion proof verification successful");
          }
        else
          {
            logger_->warn("Inclusion proof verification failed: computed root doesn't match expected root");
          }

        return is_valid;
      }
    catch (const std::exception &e)
      {
        logger_->error("Error during inclusion proof verification: {}", e.what());
        return SigstoreError::TransparencyLogInvalid;
      }
  }

  outcome::std_result<std::string> MerkleTreeValidator::compute_merkle_root(const std::vector<std::string> &proof,
                                                                            int64_t leaf_index,
                                                                            int64_t tree_size,
                                                                            const std::string &leaf_hash)
  {
    if (tree_size == 0 || leaf_index >= tree_size)
      {
        logger_->error("Leaf index {} is >= tree size {}", leaf_index, tree_size);
        return SigstoreError::TransparencyLogInvalid;
      }

    auto [inner, border] = split_inclusion_proof(leaf_index, tree_size);

    if (inner + border != static_cast<int>(proof.size()))
      {
        logger_->error("Inclusion proof size mismatch: expected {} hashes, got {}", inner + border, proof.size());
        return SigstoreError::TransparencyLogInvalid;
      }

    logger_->debug("Starting merkle computation with leaf_index={}, tree_size={}, leaf_hash={} inner={}, border={}",
                   leaf_index,
                   tree_size,
                   binary_to_hex_preview(leaf_hash),
                   inner,
                   border);

    std::string current_hash = leaf_hash;
    for (size_t i = 0; i < proof.size(); ++i)
      {
        std::string sibling_hash = unfold::utils::Base64::decode(proof[i]);
        logger_->debug("Step {}: leaf_index={}, sibling_hash={}", i, leaf_index, binary_to_hex_preview(sibling_hash));

        if (leaf_index % 2 == 0 && i < inner)
          {
            current_hash = hasher_.hash_children(current_hash, sibling_hash);
            logger_->debug("  Left child: hash_children(current || sibling) = {}", binary_to_hex_preview(current_hash));
          }
        else
          {
            current_hash = hasher_.hash_children(sibling_hash, current_hash);
            logger_->debug("  Right child: hash_children(sibling || current) = {}", binary_to_hex_preview(current_hash));
          }

        leaf_index = leaf_index / 2;
      }

    logger_->debug("Final computed root: {}", binary_to_hex_preview(current_hash));
    return current_hash;
  }

  std::pair<int, int> MerkleTreeValidator::split_inclusion_proof(std::uint64_t index, std::uint64_t size)
  {
    const std::uint64_t diff = index ^ (size - 1);
    const int inner = diff == 0 ? 0 : std::bit_width(diff);
    const int border = std::popcount(index >> static_cast<unsigned int>(inner));
    return {inner, border};
  }

} // namespace unfold::sigstore
