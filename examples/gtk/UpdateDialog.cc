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

#include "UpdateDialog.hh"

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include <gtkmm.h>

#include "nls.h"

#if defined(_WIN32)
#  include "cmark.h"
#  include "Edge.hh"

static constexpr const char *doc =
  R"(<!DOCTYPE html>
<html ang="en">
<head>
  <meta charset="utf-8">
</head>
<body>
  <div>
    {}
  </div>
</body>
</html>)";
#endif

UpdateDialog::UpdateDialog(std::shared_ptr<unfold::UpdateInfo> info)
  : Gtk::Dialog(_("Software Update"), true)
{
  set_default_size(800, 600);
  set_border_width(6);

  auto *hbox = Gtk::manage(new Gtk::Box());
  hbox->set_border_width(6);
  hbox->set_spacing(6);

  get_content_area()->pack_start(*hbox, true, true, 0);

  auto *logobox = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_VERTICAL));
  logobox->set_border_width(6);
  logobox->set_spacing(6);
  hbox->pack_start(*logobox, false, false, 0);

  try
    {
      auto pix = Gdk::Pixbuf::create_from_resource("/workrave/workrave.png");
      Gtk::Image *logo = Gtk::manage(new Gtk::Image(pix));
      logobox->pack_start(*logo, false, false, 0);
    }
  catch (const Glib::Exception &e)
    {
      spdlog::info("error loading image {}", e.what());
    }

  auto *vbox = Gtk::manage(new Gtk::Box(Gtk::ORIENTATION_VERTICAL));
  vbox->set_border_width(6);
  vbox->set_spacing(10);
  hbox->pack_start(*vbox, true, true, 0);

  std::string bold = "<span weight=\"bold\">";
  std::string end = "</span>";

  auto *title_label = Gtk::manage(
    new Gtk::Label(bold + fmt::format(_("A new version of {} is available"), info->title) + end, Gtk::ALIGN_START));
  title_label->set_use_markup();
  vbox->pack_start(*title_label, false, false, 0);

  auto *info_hbox = Gtk::manage(new Gtk::HBox());
  vbox->pack_start(*info_hbox, false, false, 0);

  auto *info_label = Gtk::manage(
    new Gtk::Label(fmt::format(_("{} {} is now available -- you have {}. Would you like to download it now?"),
                               info->title,
                               info->version,
                               info->current_version),
                   Gtk::ALIGN_START));
  info_label->set_line_wrap();
  info_label->set_xalign(0);
  info_hbox->pack_start(*info_label, false, false, 0);

  auto *notes_label = Gtk::manage(new Gtk::Label(bold + _("Release notes") + end, Gtk::ALIGN_START));
  notes_label->set_use_markup();
  vbox->pack_start(*notes_label, false, false, 0);

  auto *notes_frame = Gtk::manage(new Gtk::Frame);
  notes_frame->set_shadow_type(Gtk::SHADOW_IN);
  vbox->pack_start(*notes_frame, true, true, 0);

#if defined(_WIN32)
  if (Edge::is_supported())
    {
      web = Gtk::manage(new Edge);

      std::string body;
      for (auto note: info->release_notes)
        {
          body += fmt::format(_("<h3>Version {}</h3>\n"), note.version);
          auto html = cmark_markdown_to_html(note.markdown.c_str(), note.markdown.length(), CMARK_OPT_DEFAULT);
          ;
          if (html != nullptr)
            {
              body += html;
              free(html);
            }
        }
      web->set_content(fmt::format(doc, body));
      notes_frame->add(*web);
    }
  else
#endif
    {
      text_buffer = Gtk::TextBuffer::create();
      text_view = Gtk::manage(new Gtk::TextView(text_buffer));
      text_view->set_cursor_visible(false);
      text_view->set_editable(false);

      scrolled_window.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);
      scrolled_window.add(*text_view);

      Gtk::HBox *scrolled_box = Gtk::manage(new Gtk::HBox(false, 6));
      scrolled_box->pack_start(scrolled_window, true, true, 0);

      notes_frame->add(*scrolled_box);
      Gtk::TextIter iter = text_buffer->end();

      for (auto note: info->release_notes)
        {
          auto line = fmt::format(_("Version {}\n"), note.version);

          iter = text_buffer->insert(iter, line);
          iter = text_buffer->insert(iter, note.markdown + "\n\n");
        }
    }

  add_button(Gtk::Stock::CLOSE, Gtk::RESPONSE_CLOSE);

  show_all();
}
