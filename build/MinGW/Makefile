WINDRES:=$(CROSS_PREFIX)windres
DLLTOOL:=$(CROSS_PREFIX)dlltool
AR:=$(CROSS_PREFIX)ar
CC:=$(CROSS_PREFIX)g++
CCLD:=$(CC)
SRCS:=$(wildcard src/*.cpp src/hde/*.cpp)
OBJS:=$(SRCS:%.cpp=%.o)
DEPS:=$(SRCS:%.cpp=%.d)
INCS:=-Isrc -Iinclude
CFLAGS:=-masm=intel -Wall -Werror -std=c++23
LDFLAGS:=-Wl,-enable-stdcall-fixup -s -static-libgcc

all: DarkHook.dll libDarkHook.dll.a libDarkHook.a

-include $(DEPS)

libDarkHook.a: $(OBJS)
	$(AR) r $@ $^
libDarkHook.dll.a: DarkHook.dll dll_resources/darkhook.def
	$(DLLTOOL) --dllname DarkHook.dll --input-def dll_resources/darkhook.def --output-lib $@
DarkHook.dll: $(OBJS) dll_resources/darkhook.res dll_resources/darkhook.def
	$(CCLD) -o $@ -shared $(LDFLAGS) $^

.rc.res:
	$(WINDRES) -o $@ --input-format=rc --output-format=coff $<
.cpp.o:
	$(CC) -o $@ -c -MMD -MP $(INCS) $(CFLAGS) $<

clean:
	rm -f $(OBJS) $(DEPS) DarkHook.dll libDarkHook.dll.a libDarkHook.a dll_resources/darkhook.res

.PHONY: clean
.SUFFIXES: .rc .res
