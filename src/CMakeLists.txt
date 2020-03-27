set(EXECUTABLE_NAME dumpwow)

include_directories(Include ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR})

set(SOURCE_FILES
    main.cpp
)

add_executable(${EXECUTABLE_NAME} ${SOURCE_FILES})
target_link_libraries(${EXECUTABLE_NAME} shlwapi.lib asmjit.lib udis86.lib)

install(TARGETS ${EXECUTABLE_NAME} RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}")
