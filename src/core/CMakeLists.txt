add_subdirectory(functions)

set(EXTENSION_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/module.cpp
        ${EXTENSION_SOURCES}
        PARENT_SCOPE
)