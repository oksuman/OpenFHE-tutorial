add_library(practice1 SHARED practice1.cpp practice1.h)

if(BUILD_STATIC)
    target_link_libraries(practice1 PRIVATE ${OpenFHE_STATIC_LIBRARIES})
else()
    target_link_libraries(practice1 PRIVATE ${OpenFHE_SHARED_LIBRARIES})
endif()