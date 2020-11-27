set(OTExtension_LIBRARY_TYPE "${OTExtension_LIBRARY_TYPE}" CACHE STRING
    [=["[STATIC | SHARED | MODULE] The type of library in which OTExtension will be built."
       "Default: STATIC"]=]
)
set_property(CACHE OTExtension_LIBRARY_TYPE PROPERTY STRINGS STATIC SHARED MODULE)
string(TOUPPER "${OTExtension_LIBRARY_TYPE}" OTExtension_LIBRARY_TYPE)
if("${OTExtension_LIBRARY_TYPE}" STREQUAL "")
    set(OTExtension_LIBRARY_TYPE "STATIC")
elseif(NOT "${OTExtension_LIBRARY_TYPE}" STREQUAL "STATIC" AND
       NOT "${OTExtension_LIBRARY_TYPE}" STREQUAL "SHARED" AND
       NOT "${OTExtension_LIBRARY_TYPE}" STREQUAL "MODULE")
    message(WARNING 
        "Unknown library type: ${OTExtension_LIBRARY_TYPE}. "
        "Setting OTExtension_LIBRARY_TYPE to default value."
    )
    set(OTExtension_LIBRARY_TYPE "SHARED")
endif()

option(OTExtension_BUILD_EXE "Build executables" OFF)

set(DEPENDENCY_DIR "${DEPENDENCY_DIR}" CACHE PATH
    "Path to directory, where dependencies will be downloaded."
)

# Set build type to `Release` if none was specified:
# (cf. https://gitlab.kitware.com/cmake/community/wikis/FAQ#how-can-i-change-the-default-build-mode-and-see-it-reflected-in-the-gui)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release 
        CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
                 "None" "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif(NOT CMAKE_BUILD_TYPE)

include(AndroidCacheVariables)

#Cache Variables related to ENCRYPTO_utils dependency
set(ENCRYPTO_utils_SOURCE 
    CACHE PATH "Path to ENCRYPTO_utils source.")
set(ENCRYPTO_utils_REPOSITORY https://github.com/oliver-schick/ENCRYPTO_utils.git
    CACHE STRING "Git repository of ENCRYPTO_utils project.")
set(ENCRYPTO_utils_TAG origin/master 
    CACHE STRING "Git tag of downloaded ENCRYPTO_utils project.")

#Cache Variables related to Relic dependency
set(Relic_SOURCE
    CACHE PATH "Path to Relic source.")
set(Relic_LIBRARY_TYPE CACHE STRING "[SHARED | STATIC]: Type of Relic library linked to project.")
set_property(CACHE Relic_LIBRARY_TYPE PROPERTY STRINGS STATIC SHARED)
if(ANDROID)
    if(NOT "${Relic_LIBRARY_TYPE}" STREQUAL "" AND NOT "${Relic_LIBRARY_TYPE}" STREQUAL "STATIC")
        message(WARNING "${Relic_LIBRARY_TYPE} build for Relic is disabled on Android, " 
                        "setting Relic_LIBRARY_TYPE to STATIC...")
    endif()
    set(Relic_LIBRARY_TYPE "STATIC")
else()
    if("${Relic_LIBRARY_TYPE}" STREQUAL "")
        set(Relic_LIBRARY_TYPE "${OTExtension_LIBRARY_TYPE}")
    endif()
endif()
set(LABEL "aby" CACHE STRING "Label for relic (empty label not recommended, as this might cause name conflicts at link time)")
set(DEBUG off CACHE BOOL "Build relic with debugging support")
set(PROFL off CACHE BOOL "Build relic with profiling support")
set(CHECK off CACHE BOOL "Build relic with error-checking support")
set(ALIGN "16" CACHE STRING "Relic align")
set(ARITH "curve2251-sse" CACHE STRING "arithmetic utils used in relic")
set(FB_POLYN ${ecclvl} CACHE STRING "security level of the ecc binary curve in relic")
set(FB_METHD "INTEG;INTEG;QUICK;QUICK;QUICK;QUICK;QUICK;SLIDE;QUICK" CACHE STRING "Methods for fb in relic")
set(FB_PRECO on CACHE BOOL "fb preco for relic")
set(FB_SQRTF off CACHE BOOL "sqrtf for relic")
set(EB_METHD "PROJC;LODAH;COMBS;INTER" CACHE STRING "Methods for eb in relic")
set(EC_METHD "CHAR2" CACHE STRING "Methods for ec in relic")
set(TIMER "CYCLE" CACHE STRING "Relic timer")
set(TESTS "0" CACHE STRING "Relic amount of random tests, 0 for disable")
set(BENCH "0" CACHE STRING "Relic amount of benchmarks on random values, 0 for disable")
set(WITH "MD;DV;BN;FB;EB;EC" CACHE STRING "Relic algorithms")
set(COMP "-O3 -funroll-loops -fomit-frame-pointer -march=core2 -msse4.2 -mpclmul" CACHE STRING "Relic compiler options")
set(ARCH "X64" CACHE STRING "Architecture to be used in relic")
set(WSIZE "64" CACHE STRING "Relic word size in bits")
if("${Relic_LIBRARY_TYPE}" STREQUAL "STATIC")
    set(SHLIB off CACHE BOOL "Relic shared library")
    set(STLIB on CACHE BOOL "Relic static library")
elseif("${Relic_LIBRARY_TYPE}" STREQUAL "SHARED")
    set(SHLIB on CACHE BOOL "Relic shared library")
    set(STLIB off CACHE BOOL "Relic static library")
endif()
#Overwrite cache entries to be consistent with target android platform
if(ANDROID AND (ANDROID_ABI STREQUAL "armeabi-v7a" OR ANDROID_ABI STREQUAL "x86" OR ANDROID_ABI STREQUAL "mips"))
    set(WSIZE "32")
else()
    set(WSIZE "64")
endif()
if(ANDROID)
    set(COMP "-O3 -funroll-loops -fomit-frame-pointer")
    set(OPSYS "DROID")
    if(ANDROID_ABI STREQUAL "armeabi-v7a")
        set(ARITH "arm-asm-254")
        set(ARCH "ARM")
    elseif(ANDROID_ABI STREQUAL "arm64-v8a")
        set(ARITH "arm-asm-254")
        set(ARCH "")
    elseif(ANDROID_ABI STREQUAL "x86")
        set(ARITH "fiat")
        set(ARCH "X86")
    elseif(ANDROID_ABI STREQUAL "x86_64")
        set(ARITH "fiat")
        set(ARCH "X64")
    endif()
endif()
