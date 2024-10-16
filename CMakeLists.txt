# CMake 最低版本号要求
cmake_minimum_required (VERSION 2.8)

# 项目信息
project (cryptography)

include_directories(include/)

# 指定生成目标
add_executable(cryptography
            src/main.cpp
            )

