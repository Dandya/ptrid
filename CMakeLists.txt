cmake_minimum_required (VERSION 3.12)
project (ptrid CXX)

set(CMAKE_CXX_STANDARD 20)
set(Boost_USE_STATIC_LIBS OFF) 
set(Boost_USE_MULTITHREADED ON)  
set(Boost_USE_STATIC_RUNTIME OFF) 
find_package(Boost COMPONENTS program_options serialization system REQUIRED)

add_executable (
  ptrid
  src/ptrid.cc
)

add_executable (
  ptrid_new
  src/ptrid_new.cc
)

add_library(
  ptrid_lib
  STATIC
  src/ptrid_lib/math_func.cc
  src/ptrid_lib/markov_chain.cc
  src/ptrid_lib/probabilistic_scheme.cc
  src/ptrid_lib/readers.cc
  src/ptrid_lib/sniffer.cc
)

target_link_libraries(
  ptrid
  ptrid_lib
  Boost::serialization
)

target_link_libraries(
  ptrid_new
  ptrid_lib
  pcap
  Boost::program_options 
  Boost::serialization
  Boost::system
)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(
  test_ptrid
  test/test.cc
)

target_link_libraries(
  test_ptrid
  ptrid_lib
  GTest::gtest_main
  Boost::program_options 
  Boost::serialization
)

include(GoogleTest)
gtest_discover_tests(test_ptrid)