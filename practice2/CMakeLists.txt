add_library(practice2 SHARED practice2.cpp practice2.h)

if(BUILD_STATIC)
    target_link_libraries(practice2 PRIVATE ${OpenFHE_STATIC_LIBRARIES})
else()
    target_link_libraries(practice2 PRIVATE ${OpenFHE_SHARED_LIBRARIES})
endif()