cmake_minimum_required(VERSION 3.13)
list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_LIST_DIR}/cmake/Modules")
include(OTExtensionCacheVariables)
if(ANDROID)
    set(CMAKE_CXX_STANDARD 14)
else()
    set(CMAKE_CXX_STANDARD 17)
endif()
project(OTExtension LANGUAGES C CXX)

if(ANDROID)
     if(ANDROID_ARM_NEON)
         set(OTExtension_INSTALL_PREFIX "platforms/${ANDROID_PLATFORM}/arch-${ANDROID_SYSROOT_ABI}/NEON")
     else(ANDROID_ARM_NEON)
         set(OTExtension_INSTALL_PREFIX "platforms/${ANDROID_PLATFORM}/arch-${ANDROID_SYSROOT_ABI}")
     endif(ANDROID_ARM_NEON)
     set(OTExtension_INSTALL_INCLUDE "${OTExtension_INSTALL_PREFIX}/include")
     set(OTExtension_INSTALL_LIB "${OTExtension_INSTALL_PREFIX}/lib")
     set(OTExtension_INSTALL_ARCHIVE "${OTExtension_INSTALL_PREFIX}/lib")
     set(OTExtension_INSTALL_CONFIG "")
else(ANDROID)
     set(OTExtension_INSTALL_PREFIX "")
     set(OTExtension_INSTALL_INCLUDE "include")
     set(OTExtension_INSTALL_LIB "lib")
     set(OTExtension_INSTALL_ARCHIVE "lib")
     set(OTExtension_INSTALL_CONFIG "")
endif(ANDROID)

if(ANDROID AND CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${ANDROID_NDK}/usr/local" 
        CACHE PATH "Default install directory for android builds." FORCE)
endif()

include(AddRelic)
include(AddENCRYPTO_utils)
find_package(Threads REQUIRED)


add_library(otextension ${OTExtension_LIBRARY_TYPE}
    ot/alsz-ot-ext-rec.cpp
    ot/alsz-ot-ext-snd.cpp
    ot/iknp-ot-ext-rec.cpp
    ot/iknp-ot-ext-snd.cpp
    ot/kk-ot-ext-rec.cpp
    ot/kk-ot-ext-snd.cpp
    ot/naor-pinkas.cpp
    ot/nnob-ot-ext-rec.cpp
    ot/nnob-ot-ext-snd.cpp
    ot/ot-ext.cpp
    ot/ot-ext-rec.cpp
    ot/ot-ext-snd.cpp
    ot/pvwddh.cpp
    ot/simpleot.cpp
)
set_target_properties(otextension PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)

add_library(OTExtension::otextension ALIAS otextension)

target_compile_options(otextension PRIVATE "-Wall" "-Wextra")

target_include_directories(otextension
    PUBLIC
        $<INSTALL_INTERFACE:${OTExtension_INSTALL_INCLUDE}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)


target_link_libraries(otextension
    PUBLIC ENCRYPTO_utils::encrypto_utils
    PUBLIC Relic::relic
    PUBLIC Threads::Threads
)


include(InstallConfig)
install_config(OTExtension_INSTALL_LOCATION "OTExtension" OTExtension::otextension)

install(TARGETS otextension
        EXPORT "${PROJECT_NAME}Targets"
        ARCHIVE DESTINATION "${OTExtension_INSTALL_ARCHIVE}"
        LIBRARY DESTINATION "${OTExtension_INSTALL_LIB}"
        INCLUDES DESTINATION "${OTExtension_INSTALL_INCLUDE}")
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/ot"
        DESTINATION "${OTExtension_INSTALL_INCLUDE}"
        FILES_MATCHING REGEX ".*\\.h(pp|h)?$" REGEX ".*cmake.*" EXCLUDE)
export(TARGETS otextension ${OTExtension_DEPENDENCIES_TO_EXPORT}
       NAMESPACE "${PROJECT_NAME}::"
       FILE "${PROJECT_NAME}Targets.cmake")
install(EXPORT "${PROJECT_NAME}Targets"
        NAMESPACE "${PROJECT_NAME}::"
        DESTINATION "${OTExtension_INSTALL_LOCATION}")

if(OTExtension_BUILD_EXE)
    add_subdirectory(mains)
endif(OTExtension_BUILD_EXE)
