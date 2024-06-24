# the name of the target operating system
set(CMAKE_SYSTEM_NAME Windows)

# which compilers to use for C 
set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc-win32)

# where is the target environment located
set(CMAKE_FIND_ROOT_PATH  /usr/lib/gcc/x86_64-w64-mingw32/10-win32)

# adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# search headers and libraries in the target environment
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)