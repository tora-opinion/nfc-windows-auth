cmake_minimum_required(VERSION 3.16)
project(NFCCredentialProvider)

set(CMAKE_CXX_STANDARD 17)

# Add source files
add_library(NFCCredentialProvider SHARED
    src/NFCCredentialProvider.cpp
    src/NFCCredentialProvider.def
)

# Link libraries
target_link_libraries(NFCCredentialProvider
    shlwapi
    credui
    crypt32
    secur32
)

# Set output directory
set_target_properties(NFCCredentialProvider PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
)

# Windows specific
if(WIN32)
    target_compile_definitions(NFCCredentialProvider PRIVATE
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
    )
endif()
