cmake_minimum_required(VERSION 3.21)
project(NfcCredentialProvider LANGUAGES CXX)

if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "NfcCredentialProvider requires MSVC on Windows")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

function(nfc_release_output target)
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}"
    )
endfunction()

function(nfc_harden_target target)
    target_compile_options(${target} PRIVATE /W4 /WX /permissive- /EHsc /utf-8 /guard:cf)
    target_link_options(${target} PRIVATE /GUARD:CF /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA)
endfunction()

add_library(NfcCredentialProvider SHARED
    src/Credential.cpp
    src/Dll.cpp
    src/KerbPack.cpp
    src/PipeClient.cpp
    src/Provider.cpp
    src/SubmitFlow.cpp
    src/NfcAuthCredentialProvider.def
)
target_compile_definitions(NfcCredentialProvider PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
nfc_harden_target(NfcCredentialProvider)
target_link_libraries(NfcCredentialProvider PRIVATE secur32 advapi32 ole32 shlwapi credui uuid)
nfc_release_output(NfcCredentialProvider)
set_target_properties(NfcCredentialProvider PROPERTIES OUTPUT_NAME "NfcCredentialProvider")

add_executable(test_kerb_pack
    tests/test_kerb_pack.cpp
    src/KerbPack.cpp
)
target_compile_definitions(test_kerb_pack PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
nfc_harden_target(test_kerb_pack)
target_link_libraries(test_kerb_pack PRIVATE ole32)
nfc_release_output(test_kerb_pack)

add_executable(test_pipe_client_parse
    tests/test_pipe_client_parse.cpp
    src/PipeClient.cpp
)
target_compile_definitions(test_pipe_client_parse PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_definitions(test_pipe_client_parse PRIVATE NFC_AUTH_TESTING)
nfc_harden_target(test_pipe_client_parse)
target_link_libraries(test_pipe_client_parse PRIVATE advapi32)
nfc_release_output(test_pipe_client_parse)

add_executable(test_submit_flow
    tests/test_submit_flow.cpp
    src/KerbPack.cpp
    src/SubmitFlow.cpp
)
target_compile_definitions(test_submit_flow PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
nfc_harden_target(test_submit_flow)
target_link_libraries(test_submit_flow PRIVATE ole32)
nfc_release_output(test_submit_flow)

enable_testing()
add_test(NAME kerb_pack COMMAND $<TARGET_FILE:test_kerb_pack>)
add_test(NAME pipe_client_parse COMMAND $<TARGET_FILE:test_pipe_client_parse>)
add_test(NAME submit_flow COMMAND $<TARGET_FILE:test_submit_flow>)
