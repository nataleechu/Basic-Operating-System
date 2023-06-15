#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/pagedir.h"
#include "process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include <string.h>


#define NOT_IMPLEMENTED -1
#define STDIN 0
#define STDOUT 1
#define MAX_FD 127

static void syscall_handler (struct intr_frame *);
bool addressValid(void* ptr);

bool addressValid(void* ptr) {
  struct thread* t = thread_current();
  return is_user_vaddr(ptr) && pagedir_get_page(t->pagedir, ptr) != NULL;
}

// Student: declare filesystem_lock
extern struct lock filesystem_lock;

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// The system call handler
static void syscall_handler (struct intr_frame *f UNUSED)
{
  // We need to check if the stack pointer is in valid memory, as well as the
  // stack pointer + offset. An object is in valid memory if it is in userspace
  // and in an allocated page.
  // Nate driving
  struct thread* t = thread_current();
  if (f->esp == NULL) {
    thread_exit();
  }
  
  if (!is_user_vaddr(f->esp) || pagedir_get_page(t->pagedir, f->esp) == NULL) {
    thread_exit();
  }

  if (!is_user_vaddr((char*)f->esp + 3) || 
    pagedir_get_page(t->pagedir, (char*)f->esp + 3) == NULL) {
    thread_exit();
  }

  switch (*(uint32_t*)(f->esp)) {
    case(SYS_HALT): {
      halt();
      break;
    }
    case(SYS_EXIT): {      
      if (!is_user_vaddr((char*)f->esp+7) || 
          pagedir_get_page(t->pagedir, (char*)f->esp+7) == NULL) {
        thread_exit();
      }
      int *exit_status = (int*)((char*)f->esp+4);
      exit(*exit_status);
      break;
    }
    // Ben driving
    case(SYS_EXEC): {
      if (!is_user_vaddr((char*)f->esp+7) || 
          pagedir_get_page(t->pagedir, (char*)f->esp+7) == NULL) {
        thread_exit();
      }
      const char** file = (const char**)((char*)f->esp+4);
      f->eax = exec(*file);
      break;
    }
    case(SYS_WAIT): {
      if (!is_user_vaddr((char*)f->esp+7) || 
          pagedir_get_page(t->pagedir, (char*)f->esp+7) == NULL) {
        thread_exit();
      }
      pid_t* pid = (pid_t*) ((char*)f->esp+4);
      f->eax = wait(*pid);
      break;
    }
    case (SYS_CREATE): {
      if (!is_user_vaddr((char*)f->esp+11) || 
          pagedir_get_page(t->pagedir, (char*)f->esp+11) == NULL) {
        thread_exit();
      }
      char** file = (char**)((char*)f->esp+4);
      int *initial_size = (int*)((char*)f->esp+8);
      f->eax = create(*file, *initial_size);
      break;
    }
    // Natalee driving
    case (SYS_REMOVE): {
      if (!is_user_vaddr((char*)f->esp+7) || 
          pagedir_get_page(t->pagedir, (char*)f->esp+7) == NULL) {
        thread_exit();
      }
      char** file = (char**)((char*)f->esp+4);
      f->eax = remove(*file);
      break;
    }
    case(SYS_OPEN): {
      if (!is_user_vaddr((char*)f->esp+7) || 
          pagedir_get_page(t->pagedir, (char*)f->esp+7) == NULL) {
        thread_exit();
      }
      const char** file = ((char*)f->esp+4);
      f->eax = open(*file);
      break;
    }
    case (SYS_FILESIZE): {
      if (!is_user_vaddr((char*)f->esp+7) || 
          pagedir_get_page(t->pagedir, (char*)f->esp+7) == NULL) {
        thread_exit();
      }
      int *fd = (int*)((char*)f->esp+4);
      f->eax = filesize(*fd);
      break;
    }
    case(SYS_READ): {
      if (!is_user_vaddr((char*)f->esp+15) || 
          pagedir_get_page(t->pagedir, (char*)f->esp+15) == NULL) {
        thread_exit();
      }
      int *fd = (int*) ((char*)f->esp+4);
      void **buffer = (void**) ((char*)f->esp+8);
      unsigned *length = (unsigned*) ((char*)f->esp+12);
      f->eax = read(*fd, *buffer, *length);
      break;
    }
    case(SYS_WRITE): {
     if (!is_user_vaddr((char*)f->esp+15) || 
        pagedir_get_page(t->pagedir, (char*)f->esp+15) == NULL) {
        thread_exit();
      }
      int *fd = (int*) ((char*)f->esp+4);
      void **buffer = (void**) ((char*)f->esp+8);
      unsigned *size = (unsigned*) ((char*)f->esp+12);
      f->eax = write(*fd, *buffer, *size);
      break;
    }
    // Sai driving
    case (SYS_SEEK): {
      if (!is_user_vaddr((char*)f->esp+11) || 
          pagedir_get_page(t->pagedir, (char*)f->esp+11) == NULL) {
        thread_exit();
      }
      int *fd = (int*) ((char*)f->esp+4);
      int *position = (int*) ((char*)f->esp+8);
      seek(*fd, *position);
      break;
    }
    case (SYS_TELL): {
      if (!is_user_vaddr((char*)f->esp+7) || 
          pagedir_get_page(t->pagedir, (char*)f->esp+7) == NULL) {
        thread_exit();
      }
      int *fd = (int*) ((char*)f->esp+4);
      f->eax = tell(*fd);
      break;
    }
    case (SYS_CLOSE): {
      if (!is_user_vaddr((char*)f->esp+7) || 
          pagedir_get_page(t->pagedir, (char*)f->esp+7) == NULL) {
        thread_exit();
      }
      int *fd = (int*) ((char*)f->esp+4);
      close(*fd);
      break;
    }
  }

}

void halt(void) {
  shutdown_power_off();
}

void exit(int status) {
  thread* cur = thread_current();
  cur->return_status = status;
  thread_exit();
}


// Nate driving
// Runs the executable whose name is given. 
pid_t exec (const char *file) {

  if (file == NULL || !addressValid(file)) {
    thread_exit();
  }
  char* copy = file;
  while(true) {
    if (*copy == NULL) {
      break;
    }
    copy++;
    if (!addressValid(copy))
      thread_exit();
  }

  thread* cur = thread_current();
  ASSERT(cur->is_process);
  pid_t pid = process_execute (file);
  struct thread* child = thread_get(pid);
  sema_down(&child->wait_on_exec);
  if (child->load_failed) {
    return -1;
  }

  return pid;
}

// Waits for a child process to exit. Returns -1 if is not a child.
int wait (pid_t pid) {
  return process_wait(pid);
}

// Creates a new file called file initially initial_size bytes in size.
// Returns true if successful, false otherwise.
bool create (const char *file, unsigned initial_size) {
  if (file == NULL || !addressValid(file)) {
    thread_exit();
  } 
  // Check if each character in the string is in a valid address
  unsigned string_len = 0;
  const char* copy = file;
  while(true) {
    if (*copy == NULL) {
      break;
    }
    copy++;
    if (!addressValid(copy))
      thread_exit();
  }

  if (strlen(file) == 0 || strlen(file) > 14) {
    return 0; 
  }
  
  lock_acquire(&filesystem_lock);
  bool result = filesys_create(file, initial_size);
  lock_release(&filesystem_lock);
  return result;
}

bool remove (const char *file) {
  if (file == NULL || !addressValid(file)) {
    thread_exit();
  } 
  // Check if each character in the string is in a valid address
  unsigned string_len = 0;
  const char* copy = file;
  while(true) {
    if (*copy == NULL) {
      break;
    }
    copy++;
    if (!addressValid(copy))
      thread_exit();
  }

  if (strlen(file) == 0 || strlen(file) > 14) {
    return 0; 
  }

  lock_acquire(&filesystem_lock);
  bool result = filesys_remove(file);
  lock_release(&filesystem_lock);
  return result;
}

/* Opens the file called file. Returns the file descriptor or -1 if the file 
could not be opened.
Sai driving
*/
int open (const char *file) {
  if (file == NULL) {
    return STDIN; // this is 0
  } 
  // Check if each character in the string is in a valid address
  unsigned string_len = 0;
  const char* copy = file;
  while(true) {
    if (!addressValid(copy)) {
      thread_exit();
    }
    if (*copy == NULL) {
      break;
    }
    copy++;
  }

  if (strlen(file) == 0 || strlen(file) > 14) {
    return -1; 
  }
  
  struct thread *t = thread_current();
  lock_acquire(&filesystem_lock);
  struct file *result = filesys_open(file);
  if(result == NULL) {
    return -1;
  }
  int i = 2;
  
  while(t->files[i] != NULL) {
    i++;
    if (i > MAX_FD) {
      lock_release(&filesystem_lock);
      thread_exit();
    }
  }
  
  t->files[i] = result;
  lock_release(&filesystem_lock);
  return i;
}

int filesize (int fd) {
  if(fd < 2 || fd > MAX_FD) {
    return -1;
  }
  struct thread *t = thread_current();
  struct file *cur_file = t->files[fd];
  return file_length(cur_file);
}

/* Reads size bytes from the file open as fd into buffer. Return the number of
    bytes read.
    Natalee driving */
int read (int fd, void *buffer, unsigned length) {
  // Error checking.
  if(fd < 0 || fd == STDOUT || fd > MAX_FD) {
    return -1;
  }
  if (!addressValid(buffer)) {
    thread_exit();
  }
  // I don't think the below check is needed
  if (!addressValid((char*)buffer + length)) { 
    return -1;
  }

  // Perform easy actions based on the file descriptor
  if (fd == STDIN) {
    ((char*) buffer)[0] = input_getc(); 
    return 1;
  }

  // More error checking and the beginning of syncrhonization
  struct thread* t = thread_current();
  struct file* file = t->files[fd]; // This is shared filesystem info
  if (file == NULL) { 
    return -1;
  }

  // Read from a file and ensure filesystem synchronization while reading
  unsigned bytes_read = 0;
  lock_acquire(&filesystem_lock);
  bytes_read += file_read(file, buffer, length);
  lock_release(&filesystem_lock);
  return bytes_read;
}

// Writes size bytes from buffer to the open file fd. 
// Returns the number of bytes written.
int write (int fd, const void *buffer, unsigned length) {
  // Error checking and synchronization
  if (fd < 0 || fd > MAX_FD) {
    return -1;
  }
  if (!addressValid(buffer) || !addressValid((char*)buffer + length)) {
    thread_exit();
  }
  
  // Writing to STDOUT does not touch the filesystem
  if (fd == STDOUT) {
    putbuf((char*)buffer, length);
    return length;
  } 

  // More error checking and beginning of concurrency checking
  
  struct thread* t = thread_current();
  struct file* file = t->files[fd]; // This is shared filesystem info
  if (file == NULL) {
    return -1;
  }

  // Actually do work
  unsigned bytes_written = 0; 
  lock_acquire(&filesystem_lock);
  bytes_written += file_write(file, (char*)buffer, length);
  lock_release(&filesystem_lock);
  return bytes_written;
}

// Ben driving
void seek (int fd, unsigned position) {
  if (fd < 0 || fd > MAX_FD) {
    return;
  }
  struct thread* t = thread_current();
  struct file* file = t->files[fd];
  if (file == NULL || ((int) position) < 0) 
    return;
  lock_acquire(&filesystem_lock);
  file_seek(file, position);
  lock_release(&filesystem_lock);
}

// Returns the position of the next file to be read or written in the open file
unsigned tell (int fd) {
  if (fd < 0 || fd > MAX_FD) {
    return;
  }
  struct thread* t = thread_current();
  struct file* file = t->files[fd];
  if (file == NULL) 
    return -1;
  lock_acquire(&filesystem_lock);
  unsigned res = file_tell(file);
  lock_release(&filesystem_lock);
  return res;
}

// Close a file
void close (int fd) {
  if (fd < 0 || fd > MAX_FD) {
    return;
  }
  struct thread* t = thread_current();
  t->files[fd] = NULL;
}
