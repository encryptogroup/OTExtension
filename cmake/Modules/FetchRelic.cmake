cmake_minimum_required(VERSION 3.13)

set(Relic_SOURCE
    CACHE PATH
    "Path to Relic source."
)
set(Relic_URL
    https://github.com/relic-toolkit/relic/archive/a13dcefef1b81a51f2661910200aa76ab3599273.zip
    CACHE STRING
    "URL of Relic project."
)
set(Relic_URL_HASH
    SHA256=fb327f7350c563433797b5c9ac4e8d08a6989afec5f8f58dbe5d44d621240d65
    CACHE STRING
    "Hash of Relic archive."
)

include(FetchHelper)
#EXCLUDE_FROM_ALL to prevent some rogue config files to be installed
fetch_helper(Relic patch EXCLUDE_FROM_ALL)

set(Relic_INCLUDE_DIRS "${relic_SOURCE_DIR}/include" "${relic_SOURCE_DIR}/include/low" "${relic_BINARY_DIR}/include")
set(Relic_LIB_DIR "${CMAKE_BINARY_DIR}/lib")
if(Relic_LIBRARY_TYPE STREQUAL "STATIC")
    if(LABEL)
        set(Relic_TARGET "relic_s_${LABEL}")
    else()
        set(Relic_TARGET "relic_s")
    endif()
elseif(${Relic_LIBRARY_TYPE} STREQUAL "SHARED")
    if(LABEL)
        set(Relic_TARGET "relic_${LABEL}")
    else()
        set(Relic_TARGET "relic")
    endif()
endif()
set(Relic_LIB_NAME "${Relic_TARGET}")
#Allow relic target to be installed (but keep install deactivated for config files etc.)
set_target_properties(${Relic_TARGET} PROPERTIES EXCLUDE_FROM_ALL 0)
add_library(Relic::relic ${Relic_LIBRARY_TYPE} IMPORTED GLOBAL)
add_dependencies(Relic::relic ${Relic_TARGET})
target_include_directories(Relic::relic INTERFACE "${Relic_INCLUDE_DIRS}")
set_target_properties(Relic::relic PROPERTIES IMPORTED_LOCATION "${Relic_LIB_DIR}/${CMAKE_${Relic_LIBRARY_TYPE}_LIBRARY_PREFIX}${Relic_TARGET}${CMAKE_${Relic_LIBRARY_TYPE}_LIBRARY_SUFFIX}")
if(ANDROID)
    find_library(ANDROID_LOG_LIB log)
    target_link_libraries(Relic::relic INTERFACE "${ANDROID_LOG_LIB}")
endif()
