#include "vm/frame.h"
#include "string.h"
#include "threads/palloc.h"

frame_t* frame_table; // Where do we get this from?

void frame_init() {
    memset(frame_table, 0, init_ram_pages * sizeof(frame_t));
    for (int i = 0; i < init_ram_pages; i++) {
        frame_table[i].physical_addr = palloc_get_page(PAL_USER | PAL_ZERO);
    }
}