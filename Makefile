CC=g++
OT=ot
TEST=test
MIRACL=miracl
LIBRARIES=-lpthread ENCRYPTO_utils/miracl_lib/miracl.a -lssl -lcrypto -lgmp -lgmpxx
MIRACL_PATH= -I./ENCRYPTO_utils/miracl_lib
SOURCES_UTIL=ENCRYPTO_utils/*.cpp
OBJECTS_UTIL=ENCRYPTO_utils/*.o
SOURCES_OTMAIN=mains/otmain.cpp
OBJECTS_OTMAIN=mains/otmain.o
SOURCES_TEST=mains/test.cpp
OBJECTS_TEST=mains/test.o
SOURCES_CRYPTO=ENCRYPTO_utils/crypto/*.cpp
OBJECTS_CRYPTO=ENCRYPTO_utils/crypto/*.o
SOURCES_OT=ot/*.cpp
OBJECTS_OT=ot/*.o
COMPILER_OPTIONS=-std=c++14 -O2# -mavx -maes  -mpclmul -DRDTSC -DTEST=AES128
DEBUG_OPTIONS=#-g3 -ggdb
BATCH=
INCLUDE=-I..

ARCHITECTURE = $(shell uname -m)
ifeq (${ARCHITECTURE},x86_64)
MIRACL_MAKE:=linux64_cpp
else
MIRACL_MAKE:=linux
endif


# directory for the Miracl submodule and library
MIRACL_LIB_DIR=ENCRYPTO_utils/miracl_lib
SOURCES_MIRACL=ENCRYPTO_utils/Miracl/*
OBJECTS_MIRACL=${MIRACL_LIB_DIR}/*.o

all: ${MIRACL} ${OT} ${TEST}

ot: ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_OTMAIN}
	${CC} -o ot.exe ${CFLAGS} ${OBJECTS_OTMAIN} ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_MIRACL} ${MIRACL_PATH} ${LIBRARIES} ${COMPILER_OPTIONS} ${DEBUG_OPTIONS}

test: ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_TEST}
	${CC} -o test.exe ${CFLAGS} ${OBJECTS_TEST} ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_MIRACL} ${MIRACL_PATH} ${LIBRARIES} ${COMPILER_OPTIONS} ${DEBUG_OPTIONS}

# this will create a copy of the files in src/ENCRYPTO_utils/Miracl and its sub-directories and put them into src/ENCRYPTO_utils/miracl_lib without sub-directories, then compile it
miracl:	${MIRACL_LIB_DIR}/miracl.a

# copy Miracl files to a new directory (/ENCRYPTO_utils/miracl_lib/), call the build script and delete everything except the archive, header and object files.
${MIRACL_LIB_DIR}/miracl.a: ${SOURCES_MIRACL}
	@find ENCRYPTO_utils/Miracl/ -type f -exec cp '{}' ENCRYPTO_utils/miracl_lib \;
	@cd ENCRYPTO_utils/miracl_lib/; bash ${MIRACL_MAKE}; find . -type f -not -name '*.a' -not -name '*.h' -not -name '*.o' -not -name '.git*'| xargs rm

${OBJECTS_OTMAIN}: ${SOURCES_OTMAIN}
	@cd mains; ${CC} -c ${INCLUDE} ${CFLAGS} ${COMPILER_OPTIONS} ${DEBUG_OPTIONS} otmain.cpp

${OBJECTS_UTIL}: ${SOURCES_UTIL}
	@cd ENCRYPTO_utils; ${CC} -c ${INCLUDE} ${CFLAGS} ${BATCH} ${COMPILER_OPTIONS} ${DEBUG_OPTIONS} *.cpp

${OBJECTS_OT}: ${SOURCES_OT}
	@cd ot; ${CC} -c ${INCLUDE} ${CFLAGS} ${BATCH} ${COMPILER_OPTIONS} ${DEBUG_OPTIONS} *.cpp

${OBJECTS_CRYPTO}: ${SOURCES_CRYPTO}
	@cd ENCRYPTO_utils/crypto; ${CC} -c ${INCLUDE} ${CFLAGS} ${BATCH} ${COMPILER_OPTIONS} ${DEBUG_OPTIONS} *.cpp

%.o:%.cpp %.h
	${CC} $< ${COMPILER_OPTIONS} ${DEBUG_OPTIONS} -c ${INCLUDE} ${CFLAGS} ${BATCH} -o $@

%.o:%.cpp
	${CC} $< ${COMPILER_OPTIONS} ${DEBUG_OPTIONS} -c ${INCLUDE} ${CFLAGS} ${BATCH} -o $@

clean:
	rm -rf ot.exe test.exe ${OBJECTS_UTIL} ${OBJECTS_OTMAIN} ${OBJECTS_OT} ${OBJECTS_CRYPTO} ${OBJECTS_TEST}

# this will clean everything: example objects, test object and binaries and the Miracl library
cleanall: clean
	rm -f ${OBJECTS_MIRACL} ${MIRACL_LIB_DIR}/*.a
