add_subdirectory(core)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(EXTENSION_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/simple_encryption_extension.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/simple_encryption_state.cpp
        ${EXTENSION_SOURCES}
        PARENT_SCOPE
)