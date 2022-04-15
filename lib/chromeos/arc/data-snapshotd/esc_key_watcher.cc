// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/data-snapshotd/esc_key_watcher.h"

#include <utility>

#include <fcntl.h>
#include <sys/epoll.h>

#include <base/files/file_enumerator.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>

namespace arc {
namespace data_snapshotd {

namespace {

constexpr char kDevInputEvent[] = "/dev/input";
constexpr char kEventDevName[] = "*event*";

// Determines if the given |bit| is set in the |bitmask| array.
bool TestBit(const int bit, const uint8_t* bitmask) {
  return (bitmask[bit / 8] >> (bit % 8)) & 1;
}

// Check if ESC key is supported by |fd|.
bool IsEscKeySupported(const int fd) {
  uint8_t key_bitmask[KEY_MAX / 8 + 1];
  if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(key_bitmask)), key_bitmask) == -1) {
    PLOG(ERROR) << "Failed to ioctl to determine supported key events";
    return false;
  }

  return TestBit(KEY_ESC, key_bitmask);
}

}  // namespace

EscKeyWatcher::EscKeyWatcher(Delegate* delegate) : delegate_(delegate) {
  DCHECK(delegate_);
}

EscKeyWatcher::~EscKeyWatcher() = default;

bool EscKeyWatcher::Init() {
  if (!GetValidFds()) {
    LOG(ERROR) << "No valid input devices found.";
    return false;
  }
  if (!EpollCreate(&epfd_)) {
    PLOG(ERROR) << " EpollCreate failed, cannot watch epfd.";
    return false;
  }
  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      epfd_.get(),
      base::BindRepeating(&EscKeyWatcher::OnKeyEvent, base::Unretained(this)));
  if (!watcher_) {
    LOG(ERROR) << "Failed to watch epoll fd.";
    return false;
  }
  return true;
}

bool EscKeyWatcher::EpollCreate(base::ScopedFD* epfd) {
  *epfd = base::ScopedFD(epoll_create1(EPOLL_CLOEXEC));
  if (epfd->get() < 0) {
    PLOG(ERROR) << "Epoll_create failed";
    return false;
  }

  for (int i = 0; i < fds_.size(); ++i) {
    struct epoll_event ep_event {
      .events = EPOLLIN, .data.u32 = static_cast<uint32_t>(i),
    };
    if (epoll_ctl(epfd->get(), EPOLL_CTL_ADD, fds_[i].get(), &ep_event) < 0) {
      PLOG(ERROR) << "Epoll_ctl failed";
      return false;
    }
  }
  return true;
}

bool EscKeyWatcher::GetValidFds() {
  fds_.clear();
  base::FileEnumerator file_enumerator(base::FilePath(kDevInputEvent), true,
                                       base::FileEnumerator::FILES,
                                       kEventDevName);

  for (base::FilePath dir_path = file_enumerator.Next(); !dir_path.empty();
       dir_path = file_enumerator.Next()) {
    base::ScopedFD fd(open(dir_path.value().c_str(), O_RDONLY | O_CLOEXEC));
    if (!fd.is_valid()) {
      continue;
    }

    if (IsEscKeySupported(fd.get()))
      fds_.push_back(std::move(fd));
  }
  return !fds_.empty();
}

bool EscKeyWatcher::GetEpEvent(int epfd, struct input_event* ev, int* index) {
  struct epoll_event ep_event;
  if (epoll_wait(epfd, &ep_event, 1, -1) <= 0) {
    PLOG(ERROR) << "epoll_wait failed";
    return false;
  }
  *index = ep_event.data.u32;
  if (read(fds_[*index].get(), ev, sizeof(*ev)) != sizeof(*ev)) {
    PLOG(ERROR) << "Could not read event";
    return false;
  }
  return true;
}

void EscKeyWatcher::OnKeyEvent() {
  struct input_event ev;
  int index = 0;
  if (!GetEpEvent(epfd_.get(), &ev, &index)) {
    PLOG(ERROR) << "Could not get event";
    return;
  }

  // Notify only if the valid key is pressed.
  if (ev.type != EV_KEY || ev.code > KEY_MAX)
    return;

  // Notify only about ESC key.
  if (ev.code != KEY_ESC)
    return;

  delegate_->SendCancelSignal();
}

}  // namespace data_snapshotd
}  // namespace arc
