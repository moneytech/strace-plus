# build a split-debug version of hello32
all:
				gcc -g -m32 hello.c -o hello32
				objcopy --only-keep-debug hello32 hello32.debug
				objcopy --strip-debug hello32
				objcopy --add-gnu-debuglink=hello32.debug hello32
