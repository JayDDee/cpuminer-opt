// This file exists to force the use of g++ as the linker which in turn
// links the math library with the inclusion of math.h. gcc will not 
// automatically link math. Without this file linking will fail for m7m.c.
// Linking math manually, allowing gcc to do the linking work on Linux
// but on Windows it segfaults. Until that is solved this file must continue
// to exist.
