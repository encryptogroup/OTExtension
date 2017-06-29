set MSYSINCLUDEPATH=-I c:/mingw/msys/1.0/include/
set MSYSLIBPATH=-L c:/mingw/msys/1.0/lib
set LIBRARIES=-lssl -lcrypto

mingw32-g++ -O3 -c -o ENCRYPTO_utils/cbitvector.o ENCRYPTO_utils/cbitvector.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o ENCRYPTO_utils/crypto.o ENCRYPTO_utils/crypto.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o ENCRYPTO_utils/gmp-pk-crypto.o ENCRYPTO_utils/gmp-pk-crypto.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o ENCRYPTO_utils/ecc-pk-crypto.o ENCRYPTO_utils/ecc-pk-crypto.cpp %MSYSINCLUDEPATH% %LIBRARIES%

mingw32-g++ -O3 -c -o ot/baseOT.o ot/baseOT.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o ot/naor-pinkas.o ot/naor-pinkas.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o ot/naor-pinkas_noro.o ot/naor-pinkas_noro.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o ot/asharov-lindell.o ot/asharov-lindell.cpp %MSYSINCLUDEPATH% %LIBRARIES%
mingw32-g++ -O3 -c -o ot/ot-extension.o ot/ot-extension.cpp %MSYSINCLUDEPATH% %LIBRARIES%

mingw32-g++ -O3 -o ot.exe ENCRYPTO_utils/Miracl/crt.o ENCRYPTO_utils/Miracl/flash.o ENCRYPTO_utils/Miracl/poly.o ENCRYPTO_utils/Miracl/polymod.o ENCRYPTO_utils/Miracl/zzn.o ENCRYPTO_utils/Miracl/ecn.o ENCRYPTO_utils/Miracl/big.o ENCRYPTO_utils/Miracl/ec2.o ot\brick.o ot\double-exp.o ot\baseOT.o ot\naor-pinkas.o ot\ot-extension.o ENCRYPTO_utils/cbitvector.o mains/otmain.cpp -I.ENCRYPTO_utils/Miracl ENCRYPTO_utils/Miracl/miracl.a -lws2_32 %MSYSINCLUDEPATH% %MSYSLIBPATH% %LIBRARIES%

