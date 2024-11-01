# test/CMakeLists.txt
include(GoogleTest)

# Include directories for practice headers
include_directories(
    ${CMAKE_SOURCE_DIR}/practice1
    ${CMAKE_SOURCE_DIR}/practice2
    ${CMAKE_SOURCE_DIR}/practice3
)

# Google Test를 사용하는 테스트 실행 파일 생성
add_executable(practice1_test practice1_test.cpp)
add_executable(practice2_test practice2_test.cpp)
add_executable(practice3_test practice3_test.cpp)

# 각 테스트 실행 파일에 대해 OpenFHE와 GTest 라이브러리 링크
foreach(test_target practice1_test practice2_test practice3_test)
    if (BUILD_STATIC)
        target_link_libraries(${test_target}
            PUBLIC practice1
            PUBLIC practice2
            PUBLIC practice3
            PUBLIC OPENFHEcore
            PUBLIC OPENFHEpke
            PUBLIC OPENFHEbinfhe
            GTest::gtest_main
            GTest::gtest
        )
    else()
        target_link_libraries(${test_target}
            PUBLIC practice1
            PUBLIC practice2
            PUBLIC practice3
            PUBLIC OPENFHEcore
            PUBLIC OPENFHEpke
            PUBLIC OPENFHEbinfhe
            GTest::gtest_main
            GTest::gtest
        )
    endif()

    # Google Test와 통합
    gtest_discover_tests(${test_target})
endforeach()