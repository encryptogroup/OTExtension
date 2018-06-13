get_filename_component(OTExtension_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)

list(APPEND CMAKE_MODULE_PATH "${OTExtension_CMAKE_DIR}")

include(CMakeFindDependencyMacro)

find_dependency(ENCRYPTO_utils)

if(NOT TARGET OTExtension::otextension)
    include("${OTExtension_CMAKE_DIR}/OTExtensionTargets.cmake")
endif()
