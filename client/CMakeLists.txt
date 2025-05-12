cmake_minimum_required(VERSION 3.8)

PROJECT(whisper-client)

set(VERSION_NUMBER 1.0.0)

string(TIMESTAMP COMPILE_TIME ${VERSION_NUMBER}_%Y%m%d%H%M%S)
set(build_time ${COMPILE_TIME})
configure_file(
        ${PROJECT_SOURCE_DIR}/include/version_config.h.in
        ${PROJECT_SOURCE_DIR}/include/version_config.h
)

INCLUDE_DIRECTORIES(include)

link_directories(/usr/lib)
link_directories(/usr/lib64)
link_directories(/usr/local/lib)
link_directories(/usr/local/lib64)

AUX_SOURCE_DIRECTORY(src DIR_SRCS)

SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_CXX_FLAGS -g)
SET(CMAKE_BUILD_TYPE "Debug")
SET(SOURCE_FILES ${DIR_SRCS})

add_compile_options(-fpermissive)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_link_libraries(${PROJECT_NAME}
        -llog4cpp
        -lconfig++
        -ljsoncpp
        -luv
        -lip4tc
        -lxtables
        )