cmake_minimum_required(VERSION 3.15...4.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(HelpMe)
add_executable(main main.c)
find_library(careslib cares)
target_link_libraries(main $careslib)
