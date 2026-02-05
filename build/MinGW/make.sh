x86_64-w64-mingw32-windres -i ../../dll_resources/darkhook.rc -o DarkHook_rc.o &&
\
x86_64-w64-mingw32-dllwrap -o DarkHook.dll -masm=intel --def ../../dll_resources/darkhook.def \
  -Wl,-enable-stdcall-fixup -Wall DarkHook_rc.o ../../src/*.cpp ../../src/hde/*.cpp \
  -I../../include -I../../src -Werror -std=c++23 -s -static-libgcc -static-libstdc++
