cmake_minimum_required(VERSION 3.12)
project(OTExtension LANGUAGES CXX)

if (CMAKE_COMPILER_IS_GNUCXX AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
    message(FATAL_ERROR "ENCRYPTO_utils require at least g++-8")
endif()

option(OTEXTENSION_BUILD_EXE "Build executables" OFF)

find_package(ENCRYPTO_utils QUIET)
if(ENCRYPTO_utils_FOUND)
    message(STATUS "Found ENCRYPTO_utils")
elseif(NOT ENCRYPTO_utils_FOUND AND NOT TARGET ENCRYPTO_utils::encrypto_utils)
    message("ENCRYPTO_utils was not found: add ENCRYPTO_utils subdirectory")
    if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/ENCRYPTO_utils/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/ENCRYPTO_utils")
        execute_process(COMMAND git submodule update --init extern/ENCRYPTO_utils
                        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif()
    add_subdirectory(extern/ENCRYPTO_utils)
endif()
find_package(Threads REQUIRED)


add_library(otextension
    ot/alsz-ot-ext-rec.cpp
    ot/alsz-ot-ext-snd.cpp
#    ot/asharov-lindell.cpp
    ot/iknp-ot-ext-rec.cpp
    ot/iknp-ot-ext-snd.cpp
    ot/kk-ot-ext-rec.cpp
    ot/kk-ot-ext-snd.cpp
    ot/naor-pinkas.cpp
#    ot/naor-pinkas_noro.cpp
    ot/nnob-ot-ext-rec.cpp
    ot/nnob-ot-ext-snd.cpp
    ot/ot-ext.cpp
    ot/ot-ext-rec.cpp
    ot/ot-ext-snd.cpp
    ot/pvwddh.cpp
    ot/simpleot.cpp
)
add_library(OTExtension::otextension ALIAS otextension)

target_compile_features(otextension PUBLIC cxx_std_17)
target_compile_options(otextension PRIVATE "-Wall" "-Wextra")
#target_compile_options(otextension PUBLIC "-fno-omit-frame-pointer" "-fsanitize=address")
#target_link_options(otextension PUBLIC "-fno-omit-frame-pointer" "-fsanitize=address")

target_include_directories(otextension
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)


target_link_libraries(otextension
    PUBLIC ENCRYPTO_utils::encrypto_utils
    PUBLIC Threads::Threads
)


install(TARGETS otextension
        EXPORT "${PROJECT_NAME}Targets"
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        INCLUDES DESTINATION lib
)
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/ot"
        DESTINATION include
        FILES_MATCHING PATTERN "*.h"
)
export(TARGETS otextension NAMESPACE "${PROJECT_NAME}::" FILE "${PROJECT_NAME}Targets.cmake")
install(EXPORT "${PROJECT_NAME}Targets"
        NAMESPACE "${PROJECT_NAME}::"
        DESTINATION "lib/cmake/${PROJECT_NAME}"
)


include(CMakePackageConfigHelpers)

configure_package_config_file("${CMAKE_CURRENT_LIST_DIR}/cmake/${PROJECT_NAME}Config.cmake.in"
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    INSTALL_DESTINATION "lib/cmake/${PROJECT_NAME}"
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    DESTINATION "lib/cmake/${PROJECT_NAME}"
)

if(OTEXTENSION_BUILD_EXE)
    add_subdirectory(mains)
endif(OTEXTENSION_BUILD_EXE)
