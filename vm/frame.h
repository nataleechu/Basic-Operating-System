#include "threads/loader.h"

typedef int pid_t;

typedef struct frame {
    pid_t process_inside;
    void* physical_addr;
    void* virtual_addr; // Wonder why this is here. Maybe used to access process' page table to check dirty bits, clock, etc.
} frame_t, frame;

extern frame_t* frame_table; // Where do we get this from?

void frame_init();

// frame_t[] == frame_t*