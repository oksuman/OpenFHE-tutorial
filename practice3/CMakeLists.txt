add_library(practice3 SHARED practice3.cpp practice3.h)

if(BUILD_STATIC)
    target_link_libraries(practice3 PRIVATE ${OpenFHE_STATIC_LIBRARIES})
else()
    target_link_libraries(practice3 PRIVATE ${OpenFHE_SHARED_LIBRARIES})
endif()