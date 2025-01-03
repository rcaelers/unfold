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

#ifndef UPDATE_DIALOG_HH
#define UPDATE_DIALOG_HH

#include <optional>
#include <qdialog.h>
#include <string>
#include <memory>

#include <QtGui>
#include <QtWidgets>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include "unfold/Unfold.hh"

class AutoUpdateDialog : public QDialog
{
  Q_OBJECT

public:
  enum class UpdateChoice
  {
    Skip,
    Later,
    Now
  };
  using update_choice_callback_t = std::function<void(UpdateChoice)>;

  AutoUpdateDialog(std::shared_ptr<unfold::UpdateInfo> info, update_choice_callback_t callback);
  ~AutoUpdateDialog() override = default;

  void set_progress_visible(bool visible);
  void set_stage(unfold::UpdateStage stage, double progress);
  void set_status(const std::string &status);
  void start_install();

private:
  update_choice_callback_t callback;
  QTextEdit *text_view{nullptr};
  QScrollArea *scrolled_window{nullptr};
  QFrame *progress_bar_frame{nullptr};
  QProgressBar *progress_bar{nullptr};
  QLabel *status_label{nullptr};
  QHBoxLayout *left_button_box{nullptr};
  QHBoxLayout *right_button_box{nullptr};
  QHBoxLayout *close_button_box{nullptr};
  QPushButton *install_button{nullptr};
  QPushButton *close_button{nullptr};
  QPushButton *skip_button{nullptr};
  QPushButton *remind_button{nullptr};

  std::optional<unfold::UpdateStage> current_stage;
  QTextBrowser *web{nullptr};
};

#endif // UPDATE_DIALOG_HH
