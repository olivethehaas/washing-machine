cmake_minimum_required(VERSION 3.13)
include(pico_sdk_import.cmake)
project(washing-machine C CXX ASM)
set(PICO_BOARD pico_w)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
pico_sdk_init()
add_executable(washing-machine
washing-machine.c
)
target_include_directories(washing-machine PRIVATE ${CMAKE_CURRENT_LIST_DIR})
pico_generate_pio_header(washing-machine ${CMAKE_CURRENT_LIST_DIR}/wm.pio)

pico_add_extra_outputs(washing-machine)
target_link_libraries(washing-machine
     pico_stdlib
     pico_cyw43_arch_lwip_threadsafe_background
     hardware_pio
    )