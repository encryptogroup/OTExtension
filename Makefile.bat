mingw32-g++ -O3 -c -o util/cbitvector.o util/cbitvector.cpp

mingw32-g++ -O3 -c -o ot/brick.o ot/brick.cpp
mingw32-g++ -O3 -c -o ot/double-exp.o ot/double-exp.cpp
mingw32-g++ -O3 -c -o ot/baseOT.o ot/baseOT.cpp 
mingw32-g++ -O3 -c -o ot/naor-pinkas.o ot/naor-pinkas.cpp
mingw32-g++ -O3 -c -o ot/naor-pinkas_noro.o ot/naor-pinkas_noro.cpp 
mingw32-g++ -O3 -c -o ot/asharov-lindell.o ot/asharov-lindell.cpp
mingw32-g++ -O3 -c -o ot/ot-extension.o ot/ot-extension.cpp

mingw32-g++ -O3 -o ot.exe util/Miracl/crt.o util/Miracl/flash.o util/Miracl/poly.o util/Miracl/polymod.o util/Miracl/zzn.o util/Miracl/ecn.o util/Miracl/big.o util/Miracl/ec2.o ot\baseOT.o ot\naor-pinkas.o ot\ot-extension.o util/cbitvector.o util/sha1.o util/aes_core.o mains/otmain.cpp -I.util/Miracl util/Miracl/miracl.a -lws2_32 -lssl -lcrypto
