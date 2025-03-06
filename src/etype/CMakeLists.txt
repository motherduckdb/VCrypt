add_subdirectory(core)
include_directories(src/etype)

set(EXTENSION_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/etype_serialization.cpp
        ${EXTENSION_SOURCES}
        PARENT_SCOPE
)