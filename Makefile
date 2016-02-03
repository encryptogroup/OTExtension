CC=g++
OT=ot
TEST=test
MIRACL=miracl
LIBRARIES=-lpthread util/Miracl/miracl.a -lssl -lcrypto -lgmp -lgmpxx 
MIRACL_PATH= -I./util/Miracl
SOURCES_UTIL=util/*.cpp
OBJECTS_UTIL=util/*.o
SOURCES_OTMAIN=mains/otmain.cpp
OBJECTS_OTMAIN=mains/otmain.o
SOURCES_TEST=mains/test.cpp
OBJECTS_TEST=mains/test.o
SOURCES_CRYPTO=util/crypto/*.cpp
OBJECTS_CRYPTO=util/crypto/*.o
SOURCES_OT=ot/*.cpp
OBJECTS_OT=ot/*.o
COMPILER_OPTIONS=-O2# -mavx -maes  -mpclmul -DRDTSC -DTEST=AES128
DEBUG_OPTIONS=-g3 -ggdb 
BATCH=
INCLUDE=-I..

ARCHITECTURE = $(shell uname -m)
ifeq (${ARCHITECTURE},x86_64)
MIRACL_MAKE:=linux64
GNU_LIB_PATH:=x86_64
else
MIRACL_MAKE:=linux
GNU_LIB_PATH:=i386
endif


# directory for the Miracl submodule and library
MIRACL_LIB_DIR=/util/miracl_lib
SOURCES_MIRACL=/util/Miracl/*
OBJECTS_MIRACL=${MIRACL_LIB_DIR}/*.o

all: ${OT} ${TEST} ${MIRACL}

ot: ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_MIRACL} ${OBJECTS_OT} ${OBJECTS_OTMAIN}
	${CC} -o ot.exe ${CFLAGS} ${OBJECTS_OTMAIN} ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_MIRACL} ${MIRACL_PATH} ${LIBRARIES} ${COMPILER_OPTIONS} ${DEBUG_OPTIONS}
	
test: ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_MIRACL} ${OBJECTS_OT} ${OBJECTS_TEST}
	${CC} -o test.exe ${CFLAGS} ${OBJECTS_TEST} ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_MIRACL} ${MIRACL_PATH} ${LIBRARIES} ${COMPILER_OPTIONS} ${DEBUG_OPTIONS}
	
# this will create a copy of the files in src/util/Miracl and its sub-directories and put them into src/util/miracl_lib without sub-directories, then compile it
miracl:	${MIRACL_LIB_DIR}/miracl.a

# copy Miracl files to a new directory (${CORE}/util/miracl_lib/), call the build script and delete everything except the archive, header and object files.
${MIRACL_LIB_DIR}/miracl.a: ${SOURCES_MIRACL}
	@find ${CORE}/util/Miracl/ -type f -exec cp '{}' ${CORE}/util/miracl_lib \;
	@cd ${CORE}/util/miracl_lib/; bash ${MIRACL_MAKE}; find . -type f -not -name '*.a' -not -name '*.h' -not -name '*.o' -not -name '.git*'| xargs rm
		
${OBJECTS_OTMAIN}: ${SOURCES_OTMAIN}$
	@cd mains; ${CC} -c ${INCLUDE} ${CFLAGS} ${COMPILER_OPTIONS} ${DEBUG_OPTIONS} otmain.cpp 

${OBJECTS_UTIL}: ${SOURCES_UTIL}$  
	@cd util; ${CC} -c ${INCLUDE} ${CFLAGS} ${BATCH} ${COMPILER_OPTIONS} ${DEBUG_OPTIONS} *.cpp

${OBJECTS_OT}: ${SOURCES_OT}$
	@cd ot; ${CC} -c ${INCLUDE} ${CFLAGS} ${BATCH} ${COMPILER_OPTIONS} ${DEBUG_OPTIONS} *.cpp 

${OBJECTS_CRYPTO}: ${SOURCES_CRYPTO}$
	@cd util/crypto; ${CC} -c ${INCLUDE} ${CFLAGS} ${BATCH} ${COMPILER_OPTIONS} ${DEBUG_OPTIONS} *.cpp 

clean:
	rm -rf ot.exe test.exe ${OBJECTS_UTIL} ${OBJECTS_OTMAIN} ${OBJECTS_OT} ${OBJECTS_CRYPTO} ${OBJECTS_TEST}
	
# this will clean everything: example objects, test object and binaries and the Miracl library
cleanall: clean
	rm -f ${OBJECTS_MIRACL} ${MIRACL_LIB_DIR}/*.a
