#pragma once

#include <darkhook.h>

#include <algorithm>
#include <cassert>
#include <vector>

namespace darkhook {

enum hook_information { hook_original, hook_target, hook_original_ptr };

struct hook_t {
  void* original{nullptr};
  void* target{nullptr};
  void* old_original{nullptr};
};

namespace hooks {

inline std::vector<hook_t> hooks{};

[[nodiscard]] inline dh_status hook_function(void* original, void* target) {
  hook_t new_hook{original, target, nullptr};
  const auto status =
      dh_create_hook(original, target, &new_hook.old_original);

  if (status != DH_OK) {
#ifdef _DEBUG
    MessageBoxA(nullptr, "Failed to hook function", nullptr, 0);
    assert(false && "Invalid hook");
#endif
    return status;
  }

  hooks.emplace_back(new_hook);
  return status;
}

template <typename T>
[[nodiscard]] inline T find_original(T fn) noexcept {
  const auto found_hook =
      std::find_if(hooks.begin(), hooks.end(),
                   [fn](const hook_t& hk) { return hk.target == fn; });

  if (found_hook != hooks.end() && found_hook->old_original) {
    return reinterpret_cast<T>(found_hook->old_original);
  }

  return nullptr;
}

inline void clear_hooks() noexcept { hooks.clear(); }

}  // namespace hooks
}  // namespace darkhook
