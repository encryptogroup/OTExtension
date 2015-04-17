###DESCRIPTION
Passive and active secure OT extension implementation of the papers [1] and [2]. Implements the general OT (G_OT), correlated OT (C_OT), global correlated OT (GC_OT), sender random OT (SR_OT), and receiver random OT (RR_OT) (Definitions of the functionalities will follow). Implements the base-OTs by Naor-Pinkas [3], Peikert-Vaikuntanathan-Waters [4], and Chou-Orlandi [5]. The code is based on the OT extension implementation of [6] and uses the MIRACL libary [7] for elliptic curve arithmetic. 

###COMPILE
####Linux: 
Required compiler: g++

Required libraries: OpenSSL (e.g., on Ubuntu run `sudo apt-get install libssl-dev`)

1. Compile Miracl in util/Miracl either using "bash linux" or "bash linux64" (see `util/Miracl/first.txt` for more information)
2. Compile OT extension by executing make

####Windows:
ATTENTION: CURRENTLY NOT TESTED. 

Required compiler: mingw32

Required libraries: OpenSSL (the OpenSSL library is part of msys in mingw, can be installed using `mingw-get`, and the Windows `$PATH` variable has to be set to `[PATH_TO_MINGW]\msys\1.0\bin\`.) 

1. Compile Miracl in util/Miracl using `windows32.bat`
2. Set the Paths to your MSYS directory in `Makefile.bat`
3. Compile OT extension by invoking `Makefile.bat`


###USE
To start OT extension, open two terminals on the same PC and call `ot.exe 0` in one terminal to start OT extension as sender and call `ot.exe 1` in the second terminal to start OT extension as receiver. 


###NOTES
An example implementation of OT extension can be found in `mains/otmain.cpp`.

OT related source code is found in `ot/`. 

Different compilation flags can be set in `util/constants.h`.

###TBD
The current version is in a prototypical state. Next steps: 
1. Implementation of the NNOB OT extension protocol in [8]. 
2. Better documentation. Clean interfaces and source code.
3. Integration into the ABY framework [9] and Miracl [7] as external GIT project.
4. Test and enable support under Windows. 


###REFERENCES
* [1] G. Asharov, Y. Lindell, T. Schneider, M. Zohner: More Efficient Oblivious Transfer and Extensions for Faster Secure Computation (CCS'13). 
* [2] G. Asharov, Y. Lindell, T. Schneider, M. Zohner: More Efficient Oblivious Transfer Extensions with Security for Malicious Adversaries. EUROCRYPT (1) 2015: 673-701.
* [3] M. Naor, B. Pinkas: Efficient oblivious transfer protocols. SODA 2001: 448-457. 
* [4] C. Peikert, V. Vaikuntanathan, B. Waters: A Framework for Efficient and Composable Oblivious Transfer. CRYPTO 2008: 554-571.
* [5] T. Chou, C. Orlandi: The Simplest Protocol for Oblivious Transfer. Online at: http://eprint.iacr.org/2015/267. 
* [6] S.G. Choi, K.W. Hwang, J.Katz, T. Malkin, D. Rubenstein: Secure multi-party computation of Boolean circuits with applications to privacy in on-line market-places. In CT-RSA’12. LNCS, vol. 7178, pp. 416–432. 
* [7] CertiVox, Multiprecision Integer and Rational Arithmetic Cryptographic Library (MIRACL) https://github.com/CertiVox/MIRACL
* [8] J. B. Nielsen, P. S. Nordholt, C. Orlandi, S. S. Burra: A New Approach to Practical Active-Secure Two-Party Computation. CRYPTO 2012: 681-700.
* [9] D. Demmler, T. Schneider, M. Zohner: ABY - A Framework for Efficient Mixed-Protocol Secure Two-Party Computation. NDSS 2015.
