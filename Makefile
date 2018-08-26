# tested with MSYS2

CC=gcc
CFLAGS=-Wall -std=c11 -O3
AR=ar

SRC=cd src &&

.PHONY: build_dir

all: build_dir build_static

build_dir:
	mkdir -p build_tmp

build_static: build_tmp/buffer.o build_tmp/hook.o build_tmp/trampoline.o build_tmp/hde32.o build_tmp/hde64.o
	cd build_tmp && ${AR} rcs libminhook.a *.o
	mv build_tmp/libminhook.a .

build_tmp/buffer.o: src/buffer.c
	${SRC} ${CC} -o ../build_tmp/buffer.o -c buffer.c ${CFLAGS}

build_tmp/hook.o: src/hook.c
	${SRC} ${CC} -o ../build_tmp/hook.o -c hook.c ${CFLAGS}

build_tmp/trampoline.o: src/trampoline.c
	${SRC} ${CC} -o ../build_tmp/trampoline.o -c trampoline.c ${CFLAGS}

build_tmp/hde32.o: src/hde/hde32.c
	${SRC} ${CC} -o ../build_tmp/hde32.o -c hde/hde32.c ${CFLAGS}

build_tmp/hde64.o: src/hde/hde64.c
	${SRC} ${CC} -o ../build_tmp/hde64.o -c hde/hde64.c ${CFLAGS}

clean:
	rm -rf build_tmp
