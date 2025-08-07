cmake_minimum_required(VERSION 3.12)

project(ArgusScan VERSION 1.0 LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Capstone REQUIRED)

file(GLOB SOURCES "*.cpp")

add_executable(${PROJECT_NAME} WIN32 ${SOURCES})

target_link_libraries(${PROJECT_NAME} PRIVATE
    # Windows Kütüphaneleri
    comctl32
    psapi
    Dbghelp
    Shlwapi

    Capstone::Capstone
)