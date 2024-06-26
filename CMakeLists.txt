cmake_minimum_required(VERSION 3.20)
project(init)
# Set the C compiler
include(su.cmake)
set(CMAKE_C_COMPILER "clang")
# Add compile options
add_compile_options(-D_FORTIFY_SOURCE=3 -Wall -fPIE -flto -Oz)
# Use file(GLOB ...) to get the list of all source files
file(GLOB SRCS "init.c")
# Define the executable with the source files
add_executable(${PROJECT_NAME} ${SRCS})
# Set properties for the target
set_target_properties(${PROJECT_NAME} PROPERTIES
    LINK_FLAGS "-static -fstack-protector-all -z now -z noexecstack -fuse-ld=lld"
)
# Add custom commands for post-build steps
add_custom_command(TARGET init
    POST_BUILD
    COMMAND ${CMAKE_STRIP} $<TARGET_FILE:init>
    COMMAND upx --best --ultra-brute $<TARGET_FILE:init>
)
# Add a clean target to remove compiled binaries
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "*.o")

