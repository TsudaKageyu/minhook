# SPDX-License-Identifier: BSD-2-Clause
add_executable(minhook_safe_freeze_faults failure_injection.c)
set_target_properties(minhook_safe_freeze_faults PROPERTIES C_STANDARD 17)
target_compile_definitions(minhook_safe_freeze_faults PRIVATE MH_SAFE_FREEZE=1)
target_include_directories(minhook_safe_freeze_faults PRIVATE
  "${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/include")
# The fault fixture includes hook.c to inject OS failures. Compile its actual
# buffer/decoder dependencies directly, including when minhook is a DLL whose
# private helpers are intentionally not exported.
target_sources(minhook_safe_freeze_faults PRIVATE
  "${PROJECT_SOURCE_DIR}/src/buffer.c" "${PROJECT_SOURCE_DIR}/src/trampoline.c")
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  target_sources(minhook_safe_freeze_faults PRIVATE "${PROJECT_SOURCE_DIR}/src/hde/hde64.c")
else()
  target_sources(minhook_safe_freeze_faults PRIVATE "${PROJECT_SOURCE_DIR}/src/hde/hde32.c")
endif()
add_test(NAME minhook_safe_freeze_faults COMMAND minhook_safe_freeze_faults)
set_tests_properties(minhook_safe_freeze_faults PROPERTIES TIMEOUT 30)
add_executable(minhook_safe_freeze_real_peer real_peer.cpp)
set_target_properties(minhook_safe_freeze_real_peer PROPERTIES CXX_STANDARD 17)
target_compile_definitions(minhook_safe_freeze_real_peer PRIVATE NOMINMAX)
target_link_libraries(minhook_safe_freeze_real_peer PRIVATE minhook)
if(BUILD_SHARED_LIBS)
  add_custom_command(TARGET minhook_safe_freeze_real_peer POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "$<TARGET_FILE:minhook>" "$<TARGET_FILE_DIR:minhook_safe_freeze_real_peer>")
endif()
add_test(NAME minhook_safe_freeze_real_peer COMMAND minhook_safe_freeze_real_peer)
set_tests_properties(minhook_safe_freeze_real_peer PROPERTIES TIMEOUT 45)
add_executable(minhook_safe_freeze_live_calls live_calls.c)
set_target_properties(minhook_safe_freeze_live_calls PROPERTIES C_STANDARD 17)
target_link_libraries(minhook_safe_freeze_live_calls PRIVATE minhook)
if(BUILD_SHARED_LIBS)
  add_custom_command(TARGET minhook_safe_freeze_live_calls POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "$<TARGET_FILE:minhook>" "$<TARGET_FILE_DIR:minhook_safe_freeze_live_calls>")
endif()
add_test(NAME minhook_safe_freeze_live_calls COMMAND minhook_safe_freeze_live_calls)
set_tests_properties(minhook_safe_freeze_live_calls PROPERTIES TIMEOUT 45)

add_executable(minhook_safe_freeze_completion completion.c
  "${PROJECT_SOURCE_DIR}/src/trampoline.c")
set_target_properties(minhook_safe_freeze_completion PROPERTIES C_STANDARD 17)
target_compile_definitions(minhook_safe_freeze_completion PRIVATE MH_SAFE_FREEZE=1)
target_include_directories(minhook_safe_freeze_completion PRIVATE
  "${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/include")
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  target_sources(minhook_safe_freeze_completion PRIVATE "${PROJECT_SOURCE_DIR}/src/hde/hde64.c")
else()
  target_sources(minhook_safe_freeze_completion PRIVATE "${PROJECT_SOURCE_DIR}/src/hde/hde32.c")
endif()
add_test(NAME minhook_safe_freeze_completion COMMAND minhook_safe_freeze_completion)
set_tests_properties(minhook_safe_freeze_completion PROPERTIES TIMEOUT 30)

add_executable(minhook_safe_freeze_retirement retirement_peer.cpp)
set_target_properties(minhook_safe_freeze_retirement PROPERTIES CXX_STANDARD 17)
target_compile_definitions(minhook_safe_freeze_retirement PRIVATE NOMINMAX)
target_link_libraries(minhook_safe_freeze_retirement PRIVATE minhook)
if(BUILD_SHARED_LIBS)
  add_custom_command(TARGET minhook_safe_freeze_retirement POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "$<TARGET_FILE:minhook>" "$<TARGET_FILE_DIR:minhook_safe_freeze_retirement>")
endif()
add_test(NAME minhook_safe_freeze_retirement COMMAND minhook_safe_freeze_retirement)
set_tests_properties(minhook_safe_freeze_retirement PROPERTIES TIMEOUT 45)
