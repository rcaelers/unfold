// Copyright (C) 2022 Rob Caelers <rob.caelers@gmail.com>
// All rights reserved.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#ifndef UNFOLD_HOOKS_HH
#define UNFOLD_HOOKS_HH

#include <memory>
#include <functional>

namespace unfold
{
  class UnfoldHooks
  {
  public:
    using Ptr = std::shared_ptr<UnfoldHooks>;

    virtual ~UnfoldHooks() = default;

    virtual std::function<bool()> &hook_terminate() = 0;
  };
} // namespace unfold

#endif // UNFOLD_HOOKS_HH
