// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "vm_tools/concierge/balloon_policy.h"

#include <algorithm>
#include <assert.h>
#include <inttypes.h>
#include <optional>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/process/process_metrics.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/process/process.h>

namespace vm_tools {
namespace concierge {

// LMKD's minfree level for killing the lowest priority apps. See
// mOomMinFreeHigh in Android's
// frameworks/base/services/core/java/com/android/server/am/ProcessList.java
// NB: 64-bit systems multiply the last entry by 1.75, and the second last by
// 1.5.
constexpr int64_t MAX_OOM_MIN_FREE = 322560 * KIB;

BalanceAvailableBalloonPolicy::BalanceAvailableBalloonPolicy(
    int64_t critical_host_available,
    int64_t guest_available_bias,
    const std::string& vm)
    : critical_host_available_(critical_host_available),
      guest_available_bias_(guest_available_bias),
      max_balloon_actual_(0),
      critical_guest_available_(400 * MIB) {
  LOG(INFO) << "BalloonInit: { "
            << "\"type\": \"BalanceAvailableBalloonPolicy\","
            << "\"vm\": \"" << vm << "\","
            << "\"critical_margin\": " << critical_host_available << ","
            << "\"bias\": " << guest_available_bias << " }";
}

int64_t BalanceAvailableBalloonPolicy::ComputeBalloonDelta(
    const BalloonStats& stats,
    uint64_t host_available,
    bool game_mode,
    const std::string& vm) {
  // returns delta size of balloon
  constexpr int64_t MAX_CRITICAL_DELTA = 10 * MIB;

  const int64_t balloon_actual = stats.balloon_actual;
  const int64_t guest_free = stats.free_memory;
  const int64_t guest_cached = stats.disk_caches;
  const int64_t guest_total = stats.total_memory;

  // NB: max_balloon_actual_ should start at a resonably high value, but we
  // don't know how much memory the guest has until we get some BalloonStats, so
  // update it here instead of the constructor.
  if (max_balloon_actual_ == 0) {
    max_balloon_actual_ = (guest_total * 3) / 4;
  }
  max_balloon_actual_ = std::max(max_balloon_actual_, balloon_actual);

  const int64_t guest_available = guest_free + guest_cached;
  const int64_t balloon_full_percent =
      max_balloon_actual_ > 0 ? balloon_actual * 100 / max_balloon_actual_ : 0;

  if (guest_available < critical_guest_available_ &&
      balloon_full_percent < 95) {
    if (prev_guest_available_ < critical_guest_available_ &&
        prev_balloon_full_percent_ < 95) {
      critical_guest_available_ = prev_guest_available_;
    }
  }

  const int64_t bias = guest_available_bias_ * balloon_full_percent / 100;
  const int64_t guest_above_critical =
      guest_available - critical_guest_available_ - bias;
  const int64_t host_above_critical = host_available - critical_host_available_;

  // Find the midpoint to account for the fact that inflating/deflating the
  // balloon will decrease/increase the host available memory.
  const int64_t balloon_delta =
      (guest_above_critical - host_above_critical) / 2;

  // To avoid killing apps accidentally, cap the delta here by leaving the space
  // MAX_CRITICAL_DELTA;
  // We can remove this if clause
  // TODO(hikalium): Consider changing 2nd argument of clamp to
  // guest_above_critical + MAX_CRITICAL_DELTA
  const int64_t balloon_delta_capped = std::clamp(
      balloon_delta, -(host_above_critical + MAX_CRITICAL_DELTA),
      guest_available - critical_guest_available_ + MAX_CRITICAL_DELTA);

  prev_guest_available_ = guest_available;
  prev_balloon_full_percent_ = balloon_full_percent;

  const int64_t balloon_delta_abs =
      std::abs(balloon_delta);  // should be balloon_delta_capped???
  // Only return a value if target would change available above critical
  // by more than 1%, or we are within 1 MB of critical in host or guest.
  // Division by guest_above_critical and host_above_critical here are
  // safe since they will not be evaluated on that condition.
  if (guest_above_critical < 1 * MIB || host_above_critical < 1 * MIB ||
      balloon_delta_abs * 100 / guest_above_critical > 1 ||
      balloon_delta_abs * 100 / host_above_critical > 1) {
    // Finally, make sure the balloon delta won't cause a negative size.
    const int64_t delta = std::max(balloon_delta_capped, -balloon_actual);
    LOG(INFO) << "BalloonTrace: { "
              << "\"vm\": \"" << vm << "\", "
              << "\"game_mode\": " << (game_mode ? "true" : "false") << ", "
              << "\"balloon\": " << balloon_actual << ", "
              << "\"guest_cached\": " << guest_cached << ", "
              << "\"guest_free\": " << guest_free << ", "
              << "\"host_available\": " << host_available << ", "
              << "\"delta\": " << delta << " }";
    return delta;
  }

  return 0;
}

LimitCacheBalloonPolicy::LimitCacheBalloonPolicy(const MemoryMargins& margins,
                                                 int64_t host_lwm,
                                                 ZoneInfoStats guest_zoneinfo,
                                                 const Params& params,
                                                 const std::string& vm)
    : margins_(margins),
      host_lwm_(host_lwm),
      guest_zoneinfo_(guest_zoneinfo),
      params_(params) {
  LOG(INFO) << "BalloonInit: { "
            << "\"type\": \"LimitCacheBalloonPolicy\","
            << "\"vm\": \"" << vm << "\","
            << "\"moderate_margin\": " << margins.moderate << ","
            << "\"critical_margin\": " << margins.critical << ","
            << "\"host_lwm\": " << host_lwm << ","
            << "\"guest_lwm\": " << guest_zoneinfo.sum_low << ","
            << "\"guest_totalreserve\": " << guest_zoneinfo.totalreserve << ","
            << "\"reclaim_target_cache\": " << params.reclaim_target_cache
            << ","
            << "\"critical_target_cache\": " << params.critical_target_cache
            << ","
            << "\"moderate_target_cache\": " << params.moderate_target_cache
            << " }";
}

int64_t LimitCacheBalloonPolicy::ComputeBalloonDelta(const BalloonStats& stats,
                                                     uint64_t uhost_available,
                                                     bool game_mode,
                                                     const std::string& vm) {
  base::SystemMemoryInfoKB meminfo;
  if (!base::GetSystemMemoryInfo(&meminfo)) {
    LOG(ERROR) << "Failed to get system memory info";
    return 0;
  }
  const int64_t host_free = static_cast<int64_t>(meminfo.free) * KIB;
  return ComputeBalloonDeltaImpl(host_free, stats, uhost_available, game_mode,
                                 vm);
}

int64_t LimitCacheBalloonPolicy::ComputeBalloonDeltaImpl(
    int64_t host_free,
    const BalloonStats& stats,
    int64_t host_available,
    bool game_mode,
    const std::string& vm) {
  const int64_t max_free = MaxFree();
  const int64_t min_free = MinFree();
  const int64_t guest_free = stats.free_memory;
  const int64_t guest_unreclaimable =
      stats.shared_memory + stats.unevictable_memory;
  const int64_t guest_cache = std::max(stats.disk_caches - guest_unreclaimable,
                                       static_cast<int64_t>(0));
  const int64_t guest_lwm = guest_zoneinfo_.sum_low;
  const int64_t critical_margin = margins_.critical;
  const int64_t moderate_margin = margins_.moderate;
  int64_t target_free = max_free;
  int64_t target_cache = guest_cache;

  // Look for a reason to give the guest less than max_free memory.

  if (params_.reclaim_target_cache > 0) {
    const int64_t reclaim_target_free =
        std::max(guest_lwm + host_free - host_lwm_, min_free);
    if (reclaim_target_free < max_free &&
        guest_cache > params_.reclaim_target_cache) {
      // We are close enough to reclaiming in the host that we should restrict
      // guest memory AND the guest has enough cache that it's safe to force it
      // to reclaim.
      target_free = std::min(target_free, reclaim_target_free);
      target_cache = std::min(target_cache, params_.reclaim_target_cache);
    }
  }
  if (params_.critical_target_cache > 0) {
    const int64_t critical_target_free =
        std::max(guest_lwm + host_available - critical_margin, min_free);
    if (critical_target_free < max_free &&
        guest_cache > params_.critical_target_cache) {
      // We are close enough to discarding tabs in Chrome that we should
      // restrict guest memory AND the guest has enough cache that it's safe to
      // force it to reclaim.
      target_free = std::min(target_free, critical_target_free);
      target_cache = std::min(target_cache, params_.critical_target_cache);
    }
  }
  if (params_.moderate_target_cache > 0) {
    const int64_t moderate_target_free =
        std::max(guest_lwm + host_available - moderate_margin, min_free);
    if (moderate_target_free < max_free &&
        guest_cache > params_.moderate_target_cache) {
      // We are close enough to per-process reclaim in Chrome that we should
      // restrict guest memory AND the guest has enough cache that it's safe to
      // force it to reclaim.
      target_free = std::min(target_free, moderate_target_free);
      target_cache = std::min(target_cache, params_.moderate_target_cache);
    }
  }

  int64_t delta = guest_free - target_free;
  // In addition, don't let the balloon inflate more than the amount of cache
  // we want to reclaim. To avoid overshooting.
  if (target_free != max_free) {
    // NB: guest_cache > target_cache, because if it were less, we would have
    // left target_free == max_free.
    delta = std::min(delta, guest_cache - target_cache);
  }

  // Reduce how often we change the balloon size.
  const bool target_not_low = target_free == max_free;
  const bool guest_not_low = guest_free >= max_free;
  const bool delta_not_big =
      (guest_free / min_free) == ((guest_free + delta) / min_free);
  if (target_not_low && guest_not_low && delta_not_big) {
    return 0;
  }

  LOG(INFO) << "BalloonTrace: { "
            << "\"vm\": \"" << vm << "\", "
            << "\"game_mode\": " << (game_mode ? "true" : "false") << ", "
            << "\"balloon\": " << stats.balloon_actual << ", "
            << "\"guest_cached\": " << guest_cache << ", "
            << "\"guest_unreclaimable\": " << guest_unreclaimable << ", "
            << "\"guest_free\": " << guest_free << ", "
            << "\"host_available\": " << host_available << ", "
            << "\"host_free\": " << host_free << ", "
            << "\"delta\": " << delta << " }";

  return delta;
}

int64_t LimitCacheBalloonPolicy::MaxFree() {
  return guest_zoneinfo_.totalreserve + MAX_OOM_MIN_FREE;
}

std::optional<uint64_t> HostZoneLowSum(bool log_on_error) {
  constexpr char kProcZoneinfo[] = "/proc/zoneinfo";
  const base::FilePath zoneinfo_path(kProcZoneinfo);
  std::string zoneinfo;
  if (!base::ReadFileToString(zoneinfo_path, &zoneinfo)) {
    if (log_on_error) {
      LOG(ERROR) << "Failed to read /proc/zoneinfo";
    }
    return std::nullopt;
  }
  auto stats = ParseZoneInfoStats(zoneinfo);
  if (!stats) {
    return std::nullopt;
  }
  return std::optional<uint64_t>(stats->sum_low);
}

std::optional<ZoneInfoStats> ParseZoneInfoStats(const std::string& zoneinfo) {
  auto lines = base::SplitStringPiece(zoneinfo, "\n", base::TRIM_WHITESPACE,
                                      base::SPLIT_WANT_NONEMPTY);
  ZoneInfoStats stats = {0, 0};
  int64_t high = -1;
  for (auto line : lines) {
    if (base::StartsWith(line, "low ")) {
      auto cols = base::SplitStringPiece(line, " ", base::TRIM_WHITESPACE,
                                         base::SPLIT_WANT_NONEMPTY);
      int64_t low;
      if (cols.size() != 2 || !base::StringToInt64(cols[1], &low)) {
        LOG(ERROR) << "Failed to parse low watermark line \"" << line << "\"";
        return std::nullopt;
      }
      stats.sum_low += low * PAGE_BYTES;
    } else if (base::StartsWith(line, "high ")) {
      if (high != -1) {
        LOG(ERROR) << "Found zone protection before any high watermark line";
        return std::nullopt;
      }
      auto cols = base::SplitStringPiece(line, " ", base::TRIM_WHITESPACE,
                                         base::SPLIT_WANT_NONEMPTY);
      if (cols.size() != 2 || !base::StringToInt64(cols[1], &high)) {
        LOG(ERROR) << "Failed to parse high watermark line \"" << line << "\"";
        return std::nullopt;
      }
      // High is saved until we see a "protection" line.
    } else if (base::StartsWith(line, "protection: (")) {
      if (high == -1) {
        LOG(ERROR) << "Found zone protection before any high watermark line";
        return std::nullopt;
      }
      // NB: we only care about page counts, so to simplify indexing into
      // columns, add all the letters of "protection" to the delimiters.
      auto cols =
          base::SplitStringPiece(line, "protecin: (,)", base::TRIM_WHITESPACE,
                                 base::SPLIT_WANT_NONEMPTY);
      int64_t max_protection = 0;
      for (auto col : cols) {
        int64_t protection;
        if (!base::StringToInt64(col, &protection)) {
          LOG(ERROR) << "Failed to parse protection \"" << col
                     << "\" in line \"" << line << "\"";
          return std::nullopt;
        }
        if (max_protection < protection) {
          max_protection = protection;
        }
      }
      // Zone watermarks can be boosted by up to 50%, so to be conservative,
      // totalreserve should use the maximum zone size.
      high = high + (high >> 1);
      stats.totalreserve += (max_protection + high) * PAGE_BYTES;
      high = -1;
    }
  }
  if (high != -1) {
    LOG(ERROR) << "Zone high watermark without a following protection line";
    return std::nullopt;
  }
  if (stats.sum_low == 0) {
    LOG(ERROR) << "Failed to find any non-zero zone low watermarks";
    return std::nullopt;
  }
  if (stats.totalreserve == 0) {
    LOG(ERROR) << "Failed to find any non-zero zone high watermarks";
    return std::nullopt;
  }
  return std::optional<ZoneInfoStats>(stats);
}

}  // namespace concierge
}  // namespace vm_tools
