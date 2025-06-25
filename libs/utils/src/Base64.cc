// Copyright (C) 2022 Rob Caelers <rob.caelers@gmail.com>
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

#include "utils/Base64.hh"

#include <algorithm>
#include <string>
#include <cctype>

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

using namespace unfold::utils;

namespace
{
  bool is_valid_base64_char(char c)
  {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '+' || c == '/' || c == '=';
  }

  void validate_base64_input(const std::string &input)
  {
    if (input.empty())
      {
        throw Base64Exception("Base64 input cannot be empty");
      }

    auto invalid_char = std::ranges::find_if(input, [](char c) { return !is_valid_base64_char(c); });
    if (invalid_char != input.end())
      {
        throw Base64Exception("Invalid character in Base64 input: '" + std::string(1, *invalid_char) + "'");
      }

    size_t padding_pos = input.find('=');
    if (padding_pos != std::string::npos)
      {
        // After first '=', there can be at most 1 more character and it must be '='
        size_t padding_count = input.length() - padding_pos;
        if (padding_count > 2)
          {
            throw Base64Exception("Too many padding characters in Base64 input");
          }

        // If there's a second character after first '=', it must also be '='
        if (padding_count == 2 && input[padding_pos + 1] != '=')
          {
            throw Base64Exception("Invalid Base64 padding");
          }
      }
  }
} // anonymous namespace

std::string
Base64::decode(const std::string &val)
{
  if (val.empty())
    {
      return "";
    }

  try
    {
      // Pad with '=' if input is not a multiple of 4
      std::string input = val;
      size_t padding_needed = (4 - input.size() % 4) % 4;
      input.append(padding_needed, '=');

      // Validate the final input (characters, padding, and length)
      validate_base64_input(input);

      // Ensure final length is multiple of 4 (should always be true after padding)
      if (input.length() % 4 != 0)
        {
          throw Base64Exception("Invalid Base64 input length (must be multiple of 4)");
        }

      constexpr int output_bits = 8;
      constexpr int input_bits = 6;
      using namespace boost::archive::iterators;
      using It = transform_width<binary_from_base64<std::string::const_iterator>, output_bits, input_bits>;

      size_t num_padding_chars = std::count(input.begin(), input.end(), '=');
      std::ranges::replace(input, '=', 'A');

      std::string output(It(input.begin()), It(input.end()));
      output.erase(output.end() - static_cast<std::string::difference_type>(num_padding_chars), output.end());
      return output;
    }
  catch (const std::exception &e)
    {
      throw Base64Exception("Base64 decode failed: " + std::string(e.what()));
    }
}

std::string
Base64::encode(const std::string &val)
{
  if (val.empty())
    {
      return "";
    }

  try
    {
      constexpr int output_bits = 6;
      constexpr int input_bits = 8;
      using namespace boost::archive::iterators;
      using It = base64_from_binary<transform_width<std::string::const_iterator, output_bits, input_bits>>;

      std::string tmp(It(std::begin(val)), It(std::end(val)));
      size_t padding_needed = (3 - val.size() % 3) % 3;
      return tmp.append(padding_needed, '=');
    }
  catch (const std::exception &e)
    {
      throw Base64Exception("Base64 encode failed: " + std::string(e.what()));
    }
}
