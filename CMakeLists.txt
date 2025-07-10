cmake_minimum_required(VERSION 3.15...4.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(HelpMe)
find_package(OpenSSL)
add_executable(main main.c smtp_commands.c tls_setup.c)
target_link_libraries(main cares OpenSSL::SSL)
