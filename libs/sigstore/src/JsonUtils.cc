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

#include "JsonUtils.hh"

namespace unfold::sigstore
{
  std::string JsonUtils::extract_string(const boost::json::value &json_val, const std::string &key)
  {
    try
      {
        if (json_val.is_object())
          {
            const auto &obj = json_val.as_object();
            if (obj.contains(key) && obj.at(key).is_string())
              {
                std::string value = std::string(obj.at(key).as_string());
                return value;
              }
          }
      }
    catch (const std::exception &e)
      {
        logger_->error("Exception while extracting JSON string for key '{}': {}", key, e.what());
      }
    return "";
  }

  boost::json::value JsonUtils::extract_object(const boost::json::value &json_val, const std::string &key)
  {
    try
      {
        if (json_val.is_object())
          {
            const auto &obj = json_val.as_object();
            if (obj.contains(key))
              {
                return obj.at(key);
              }
          }
      }
    catch (const std::exception &e)
      {
        logger_->error("Exception while extracting JSON object for key '{}': {}", key, e.what());
      }
    return boost::json::value{};
  }

  boost::json::value JsonUtils::extract_array_element(const boost::json::value &json_val, const std::string &key, size_t index)
  {
    try
      {
        if (json_val.is_object())
          {
            const auto &obj = json_val.as_object();
            if (obj.contains(key) && obj.at(key).is_array())
              {
                const auto &arr = obj.at(key).as_array();
                if (index < arr.size())
                  {
                    return arr.at(index);
                  }
              }
          }
      }
    catch (const std::exception &e)
      {
        logger_->error("Exception while extracting JSON array element for key '{}': {}", key, e.what());
      }
    return boost::json::value{};
  }

} // namespace unfold::sigstore
