# tutorial/CMakeLists.txt
# tutorial1 executable
add_executable(tutorial1 tutorial1.cpp)
if (BUILD_STATIC)
    target_link_libraries(tutorial1
        PUBLIC OPENFHEcore
        PUBLIC OPENFHEpke
        PUBLIC OPENFHEbinfhe
    )
else()
    target_link_libraries(tutorial1
        PUBLIC OPENFHEcore
        PUBLIC OPENFHEpke
        PUBLIC OPENFHEbinfhe
    )
endif()

# tutorial2 executable
add_executable(tutorial2 tutorial2.cpp)
if (BUILD_STATIC)
    target_link_libraries(tutorial2
        PUBLIC OPENFHEcore
        PUBLIC OPENFHEpke
        PUBLIC OPENFHEbinfhe
    )
else()
    target_link_libraries(tutorial2
        PUBLIC OPENFHEcore
        PUBLIC OPENFHEpke
        PUBLIC OPENFHEbinfhe
    )
endif()

# tutorial3 executable
add_executable(tutorial3 tutorial3.cpp)
if (BUILD_STATIC)
    target_link_libraries(tutorial3
        PUBLIC OPENFHEcore
        PUBLIC OPENFHEpke
        PUBLIC OPENFHEbinfhe
    )
else()
    target_link_libraries(tutorial3
        PUBLIC OPENFHEcore
        PUBLIC OPENFHEpke
        PUBLIC OPENFHEbinfhe
    )
endif()