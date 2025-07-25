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

#include "TransparencyLogLoader.hh"

#include <fstream>
#include <google/protobuf/util/json_util.h>

#include "sigstore/SigstoreErrors.hh"

namespace unfold::sigstore
{

  outcome::std_result<std::unique_ptr<dev::sigstore::rekor::v1::TransparencyLogEntry>> TransparencyLogLoader::load_from_file(
    const std::filesystem::path &file_path)
  {
    if (!std::filesystem::exists(file_path))
      {
        logger_->error("File does not exist: {}", file_path.string());
        return SigstoreError::InvalidTransparencyLog;
      }

    try
      {
        std::ifstream file(file_path, std::ios::in | std::ios::binary);
        if (!file.is_open())
          {
            logger_->error("Failed to open file: {}", file_path.string());
            return SigstoreError::InvalidTransparencyLog;
          }

        std::string json_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        return load_from_json(json_content);
      }
    catch (const std::exception &e)
      {
        logger_->error("Exception while reading file {}: {}", file_path.string(), e.what());
        return SigstoreError::InvalidTransparencyLog;
      }
  }

  outcome::std_result<std::unique_ptr<dev::sigstore::rekor::v1::TransparencyLogEntry>> TransparencyLogLoader::load_from_json(
    const std::string &json_content)
  {
    auto entry = std::make_unique<dev::sigstore::rekor::v1::TransparencyLogEntry>();

    google::protobuf::util::JsonParseOptions options;
    options.ignore_unknown_fields = false;
    options.case_insensitive_enum_parsing = true;

    auto status = google::protobuf::util::JsonStringToMessage(json_content, entry.get(), options);

    if (!status.ok())
      {
        logger_->error("Failed to parse JSON transparency log: {}", std::string(status.message()));
        return SigstoreError::InvalidTransparencyLog;
      }

    return std::move(entry);
  }

} // namespace unfold::sigstore
