add_subdirectory(functions)
add_subdirectory(utils)

set(EXTENSION_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/module.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/types.cpp
        ${EXTENSION_SOURCES}
        PARENT_SCOPE
)