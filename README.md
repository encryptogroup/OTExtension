# OTExtension  [![Build Status](https://travis-ci.org/encryptogroup/OTExtension.svg?branch=master)](https://travis-ci.org/encryptogroup/OTExtension)

## DESCRIPTION
Implementation of the passive secure OT extension protocol of [1] and the active secure OT extension protocols of [2] and [3]. Implements the general OT (G_OT), correlated OT (C_OT), global correlated OT (GC_OT), sender random OT (SR_OT), and receiver random OT (RR_OT) (Definitions of the functionalities will follow). Implements the base-OTs by Naor-Pinkas [4], Peikert-Vaikuntanathan-Waters [5], and Chou-Orlandi [6]. The code is based on the OT extension implementation of [7] and uses the MIRACL libary [8] for elliptic curve arithmetic.

Update: Implemented 1-out-of-2 OT from the 1-out-of-N OT extension of [10].

## REQUIREMENTS

* A **Linux distribution** of your choice (the OT extension code was developed under [Ubuntu](http://www.ubuntu.com/)).
* **Required packages:**
  * [`g++`](https://packages.debian.org/testing/g++)
  * [`make`](https://packages.debian.org/testing/make)
  * [`libgmp-dev`](https://packages.debian.org/testing/libgmp-dev)
  * [`libssl-dev`](https://packages.debian.org/testing/libssl-dev)
  * [`libboost-all-dev`](https://packages.debian.org/testing/libboost-all-dev) (version >= 1.66)
  
  Install these packages with your favorite package manager, e.g, `sudo apt-get install <package-name>`.


## COMPILING

1. Clone a copy of the OTExtension git repository:
	```
	git clone https://github.com/encryptogroup/OTExtension.git
	```

2. Enter the Framework directory: `cd OTExtension/`

3. Create and enter a build directory: `mkdir build && cd build`

4. Use CMake to create build files. Use

	```
    cmake ..
	```

	The following options are available:

	* `-DCMAKE_INSTALL_PREFIX=/path/to/installation`
	* `-DOTEXTENSION_BUILD_EXE=On` to build executables (they are written to `mains/` in the build directory)

In case [ENCRYPTO_utils](https://github.com/encryptogroup/ENCRYPTO_utils)
cannot be found on your system, it will automatically be compiled.  If it is
installed in a non-standard location, the path can be provided via
`-DCMAKE_PREFIX_PATH=/some/path`.

5. Call `make` in the build directory to compile.


## USE
To start OT extension, open two terminals on the same PC and call `otmain -r 0` in one terminal to start OT extension as sender and call `otmain -r 1` in the second terminal to start OT extension as receiver. This will invoke the passive secure IKNP 1-out-of-2 OT extension protocol for 1 million OTs on 8-bit strings. The result of the OT will be checked for correctness and the times (in ms) for the base-OTs, for the OT extensions, the number of bytes sent and the number of bytes received will be printed on the terminals.
A list of all available options can be obtained via `otmain -h`.

## NOTES
An example implementation of OT extension can be found in `mains/otmain.cpp`.

OT related source code is found in `ot/`.

Some compilation flags can be set in `ot/OTconstants.h`.


## REFERENCES
* [1] G. Asharov, Y. Lindell, T. Schneider, M. Zohner: More Efficient Oblivious Transfer and Extensions for Faster Secure Computation (CCS'13).
* [2] G. Asharov, Y. Lindell, T. Schneider, M. Zohner: More Efficient Oblivious Transfer Extensions with Security for Malicious Adversaries. EUROCRYPT (1) 2015: 673-701.
* [3] J. B. Nielsen, P. S. Nordholt, C. Orlandi, S. S. Burra: A New Approach to Practical Active-Secure Two-Party Computation. CRYPTO 2012: 681-700.
* [4] M. Naor, B. Pinkas: Efficient oblivious transfer protocols. SODA 2001: 448-457.
* [5] C. Peikert, V. Vaikuntanathan, B. Waters: A Framework for Efficient and Composable Oblivious Transfer. CRYPTO 2008: 554-571.
* [6] T. Chou, C. Orlandi: The Simplest Protocol for Oblivious Transfer. Online at: http://eprint.iacr.org/2015/267.
* [7] S.G. Choi, K.W. Hwang, J.Katz, T. Malkin, D. Rubenstein: Secure multi-party computation of Boolean circuits with applications to privacy in on-line market-places. In CT-RSA’12. LNCS, vol. 7178, pp. 416–432.
* [8] CertiVox, Multiprecision Integer and Rational Arithmetic Cryptographic Library (MIRACL) https://github.com/CertiVox/MIRACL
* [9] V. Kolesnikov, R. Kumaresan: Improved OT Extension for Transferring Short Secrets. In CRYPTO'13 (2).
* [10] D. Demmler, T. Schneider, M. Zohner: ABY - A Framework for Efficient Mixed-Protocol Secure Two-Party Computation. NDSS 2015. https://github.com/encryptogroup/ABY
