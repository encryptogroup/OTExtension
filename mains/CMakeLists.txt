add_executable(test test.cpp)
target_link_libraries(test OTExtension::otextension)

add_executable(otmain otmain.cpp)
target_link_libraries(otmain OTExtension::otextension)
