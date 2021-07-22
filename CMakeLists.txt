set(CMAKE_CXX_STANDARD 14)

cmake_minimum_required(VERSION 3.0)

project(firod CXX)

add_definitions(-DENABLE_CLIENTAPI=1)
add_definitions(-DENABLE_WALLET=1)
add_definitions(-DENABLE_ELYSIUM=1)

set(ENABLE_CLIENTAPI ON)
set(ENABLE_WALLET ON)
set(ENABLE_ELYSIUM ON)
set(INCLUDE_DIRS src src/univalue/include src/client-api src/zmq src/zmqserver src/wallet src/qt src/qt/forms src/hdmint src/elysium src/crypto src/leveldb/include src/secp256k1/include)
include_directories(${INCLUDE_DIRS})

file(GLOB_RECURSE SRC_FILES *.h *.cpp *.ui)
add_executable(firod ${SRC_FILES})

find_package(Boost 1.45.0 COMPONENTS)
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(firod ${Boost_LIBRARIES})
endif()

# Qt's path must be added to the CMAKE_PREFIX_PATH envvar for this to work. e.g. CMAKE_PREFIX_PATH=/usr/local/Cellar/qt/5.15.2/lib/cmake/
foreach(module Core Widgets Gui)
    find_package(Qt5${module} REQUIRED)
    target_link_libraries(firod Qt5::${module})
endforeach()

