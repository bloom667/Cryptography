# CMake 最低版本号要求
cmake_minimum_required (VERSION 3.13)
project (cryptography)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 14)

include_directories(include)

# 指定生成目标
add_executable(cryptography
            src/main.cpp
            src/Cry.cpp
            )

