cmake_minimum_required(VERSION 3.0.2)
project(sca)

# Keep aside for potential later use
# set(COMPILATION_WARNINGS "-W -Wall -Wextra -Werror -ansi -pedantic -Wuninitialized -Wcast-align -Wpointer-arith -Wmissing-braces -Wunused-result -Wl,-z,relro -Wl,-z,now -Wformat -Wformat-security -Wstrict-aliasing -Wunused-parameter")
# set(LINKER_LIBRARIES "-lrt -pthread -lm")
# set(CMAKE_C_FLAGS " ${COMPILATION_WARNINGS} ${LINKER_LIBRARIES} -fstack-protector -pie -fPIC  -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -O3 -std=c89 ")
# -D_XOPEN_SOURCE=700

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        src/launch_attacks.c
        src/read_csv.c
        src/xpa_attacks.c
        src/xpa_new.c)
        #src/pearson.c)

include_directories(include/ src/)

add_executable(xpa_attack ${SOURCE_FILES})