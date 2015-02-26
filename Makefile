CC=g++
OT=ot
LIBRARIES=-lpthread util/Miracl/miracl.a -lssl -lcrypto -lgmp -lgmpxx 
MIRACL_PATH= -I./util/Miracl
SOURCES_UTIL=util/*.cpp
OBJECTS_UTIL=util/*.o
SOURCES_OTMAIN=mains/otmain.cpp
OBJECTS_OTMAIN=mains/otmain.o
SOURCES_CRYPTO=util/crypto/*.cpp
OBJECTS_CRYPTO=util/crypto/*.o
SOURCES_OT=ot/*.cpp
OBJECTS_OT=ot/*.o
OBJECTS_MIRACL= util/Miracl/*.o
COMPILER_OPTIONS=-O3
BATCH=
INCLUDE=-I..

all: ${OT}

ot: ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_MIRACL} ${OBJECTS_OT} ${OBJECTS_OTMAIN}
	${CC} -o ot.exe ${CFLAGS} ${OBJECTS_OTMAIN} ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_MIRACL} ${MIRACL_PATH} ${LIBRARIES} ${COMPILER_OPTIONS}
	
${OBJECTS_OTMAIN}: ${SOURCES_OTMAIN}$
	@cd mains; ${CC} -c ${INCLUDE} ${CFLAGS} otmain.cpp 

${OBJECTS_UTIL}: ${SOURCES_UTIL}$  
	@cd util; ${CC} -c ${INCLUDE} ${CFLAGS} ${BATCH} *.cpp

${OBJECTS_OT}: ${SOURCES_OT}$
	@cd ot; ${CC} -c ${INCLUDE} ${CFLAGS} ${BATCH} *.cpp 

${OBJECTS_CRYPTO}: ${SOURCES_CRYPTO}$
	@cd util/crypto; ${CC} -c ${INCLUDE} ${CFLAGS} ${BATCH} *.cpp 

clean:
	rm -rf ot.exe ${OBJECTS_UTIL} ${OBJECTS_OTMAIN} ${OBJECTS_OT} ${OBJECTS_CRYPTO}

