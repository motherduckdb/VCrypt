add_subdirectory(core)
include_directories(src/include)

set(EXTENSION_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/vcrypt_extension.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/vcrypt_state.cpp
        ${EXTENSION_SOURCES}
        PARENT_SCOPE
)