set MSYSINCLUDEPATH=-I c:/mingw/msys/1.0/include/
set MSYSLIBPATH=-L c:/mingw/msys/1.0/lib
set LIBRARIES=-lssl -lcrypto

mingw32-g++ -O3 -c -o util/cbitvector.o util/cbitvector.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o util/crypto.o util/crypto.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o util/gmp-pk-crypto.o util/gmp-pk-crypto.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o util/ecc-pk-crypto.o util/ecc-pk-crypto.cpp %MSYSINCLUDEPATH% %LIBRARIES%

mingw32-g++ -O3 -c -o ot/baseOT.o ot/baseOT.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o ot/naor-pinkas.o ot/naor-pinkas.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o ot/naor-pinkas_noro.o ot/naor-pinkas_noro.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o ot/asharov-lindell.o ot/asharov-lindell.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o ot/ot-extension.o ot/ot-extension.cpp %MSYSINCLUDEPATH% %LIBRARIES%

mingw32-g++ -O3 -o ot.exe util/Miracl/crt.o util/Miracl/flash.o util/Miracl/poly.o util/Miracl/polymod.o util/Miracl/zzn.o util/Miracl/ecn.o util/Miracl/big.o util/Miracl/ec2.o ot\brick.o ot\double-exp.o ot\baseOT.o ot\naor-pinkas.o ot\ot-extension.o util/cbitvector.o mains/otmain.cpp -I.util/Miracl util/Miracl/miracl.a -lws2_32 %MSYSINCLUDEPATH% %MSYSLIBPATH% %LIBRARIES%

