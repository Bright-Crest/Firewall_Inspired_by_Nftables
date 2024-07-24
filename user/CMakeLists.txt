cmake_minimum_required(VERSION 3.10)
project(NftFirewallUser)

## Use c++14
## set(CMAKE_CXX_STANDARD 14)
## Use c++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

## By adding -Wall and -Werror, the compiler does not ignore warnings anymore,
## enforcing cleaner code.
# add_definitions(-Wall -Werror)

set(CMAKE_BUILD_TYPE Debug)

# set(INCLUDE_DIR ../include ../../share/include)
# set(INCLUDE_LIST ../include/api.h ../include/call.h ../../share/include/share.h ../../share/include/comm_protocol.h)
# set(SRC_LIST ../src/kernel.c ../src/myfw.cpp ../src/operate.c ../src/utils.cpp)

# path relative to CMakeLists.txt
set(INCLUDE_DIR ./include ./../share/include)
set(INCLUDE_LIST ./include/api.h ./include/call.h ./../share/include/share.h ./../share/include/comm_protocol.h)
set(SRC_LIST ./src/kernel.c ./src/myfw.cpp ./src/operate.c ./src/utils.c)

add_executable(${PROJECT_NAME} ${SRC_LIST} ${INCLUDE_LIST})
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIR}) 
