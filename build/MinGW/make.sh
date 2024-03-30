x86_64-w64-mingw32-windres -i ../../dll_resources/MinHook.rc -o MinHook_rc.o &&
x86_64-w64-mingw32-dllwrap -o MinHook.dll -masm=intel --def ../../dll_resources/MinHook.def -Wl,-enable-stdcall-fixup -Wall MinHook_rc.o ../../src/*.c ../../src/hde/*.c -I../../include -I../../src -Werror -s -static-libgcc -static-libstdc++
