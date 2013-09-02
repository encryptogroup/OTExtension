--- DESCRIPTION ---
OT extension implementation of the paper [1]. Implements the general OT (G_OT), correlated OT (C_OT), and random OT (R_OT) as well as the base-OT by Noar-Pinkas with and without random oracle and the base-OT in [1] (Asharov-Lindell). The code is based on the OT extension implementation of [2] and uses the MIRACL libary [3] for elliptic curve arithmetic. 

--- COMPILE ---
Linux: 
Required compiler: g++
1) Compile Miracl in util/Miracl either using "bash linux" or "bash linux64" (see util/Miracl/first.txt for more information)
2) Compile OT extension by executing make

Windows:
Required compiler: mingw32
1) Compile Miracl in util/Miracl using windows32.bat
2) Compile OT extension by invoking Makefile.bat


--- USE ---
To start OT extension, open two terminals on the same PC and call "ot.exe 0" in one terminal to start OT extension as sender and call "ot.exe 1" in the second terminal to start OT extension as receiver. 


--- NOTES ---
The use of the gnu-multiprecision library is currently disabled and only elliptic curve cryptography is used. To enable GMP under 64-bit Linux, uncomment "#define OTEXT_USE_GMP" in util/typedefs.h and uncomment "-lgmpxx -lgmp" in the Makefile. Additionally, under Linux the AES and SHA implementation of OpenSSL can be used if "#define OTEXT_USE_OPENSSL" uncommented in util/typedefs.h and "-L /usr/lib  -lssl -lcrypto" is uncommented in the Makefile. 

An example implementation of OT extension can be found in mains/otmain.cpp.

OT related source code is found in ot/. 

The number of threads can be set in util/typedefs.h (OT_NUM_THREADS).



[1] G. Asharov, Y. Lindell, T. Schneider and M. Zohner: More Efficient Oblivious Transfer and Extensions for Faster Secure Computation (CCS'13). 
[2] S.G. Choi, K.W. Hwang, J.Katz, T. Malkin, D. Rubenstein: Secure multi-party computation of Boolean circuits with applications to privacy in on-line market-places. In: Cryptographers’ Track at the RSA Conference (CT-RSA’12). LNCS, vol. 7178, pp. 416–432. Springer (2012)
[3] CertiVox, Multiprecision Integer and Rational Arithmetic Cryptographic Library (MIRACL) https://github.com/CertiVox/MIRACL
