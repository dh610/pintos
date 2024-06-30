#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"
#include <string.h>

struct lock filesys_lock;
void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

static void halt (void) NO_RETURN;
static void exit (int status) NO_RETURN;
static tid_t sys_fork (const char *thread_name, struct intr_frame *f);
static int exec (const char *cmd_line);
static int wait (tid_t tid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned length);
static int write (int fd, const void *buffer, unsigned length);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch (f->R.rax) {
		case SYS_HALT:
			halt();
			break;

		case SYS_EXIT:
			exit(f->R.rdi);
			break;

		case SYS_FORK:
			f->R.rax = sys_fork((char *) f->R.rdi, f);
			break;

		case SYS_EXEC:
			f->R.rax = exec((char *) f->R.rdi);
			break;

		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;

		case SYS_CREATE:
			f->R.rax = create((char *) f->R.rdi, f->R.rsi);
			break;

		case SYS_REMOVE:
			f->R.rax = remove((char *) f->R.rdi);
			break;

		case SYS_OPEN:
			f->R.rax = open((char *) f->R.rdi);
			break;

		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;

		case SYS_READ:
			f->R.rax = read(f->R.rdi, (void *) f->R.rsi, f->R.rdx);
			break;

		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, (void *) f->R.rsi, f->R.rdx);
			break;
			
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;

		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;

		case SYS_CLOSE:
			close(f->R.rdi);
			break;
	}
}

#define ADDR_VAL(va) if (!va || is_kernel_vaddr(va) || !pml4_get_page(thread_current()->pml4, va)) exit(-1);

static void
halt (void) {
	power_off();
}

static void
exit (int status) {
	thread_current()->exit_status = status;
	for (unsigned i = 0; thread_name()[i] != ' ' && i < strlen(thread_name()); i++)
		printf("%c", thread_name()[i]);
	printf(": exit(%d)\n",  status);
	thread_exit();
}

static tid_t 
sys_fork (const char *thread_name, struct intr_frame *f) {
	return process_fork(thread_name, f);
}

static int 
exec (const char *cmd_line) {
	ADDR_VAL(cmd_line)
	return process_exec((void *) cmd_line);
}

static int
wait (tid_t tid) {
	return process_wait(tid);
}

static bool
create (const char *file, unsigned initial_size) {
	ADDR_VAL(file)

	lock_acquire(&filesys_lock);
	bool ret = filesys_create(file, initial_size);
	lock_release(&filesys_lock);

	return ret;
}

static bool
remove (const char *file) {
	ADDR_VAL(file)

	lock_acquire(&filesys_lock);
	bool ret = filesys_remove(file);
	lock_release(&filesys_lock);

	return ret;
}

static int
open (char *file) {
	ADDR_VAL(file)
	struct thread *curr = thread_current();
	if (curr->fd_end >= 128) return -1;
	
	lock_acquire(&filesys_lock);
	struct file *fp = filesys_open(file);
	lock_release(&filesys_lock);

	if (!fp) return -1;

	int fd;

	/*
	if (strcmp(thread_name(), file) == 0)
		file_deny_write(fp);
	*/

	for (fd = 2; fd < curr->fd_end; fd++)
		if (!curr->fd_table[fd]) break;

	if (fd == curr->fd_end) curr->fd_end++;

	curr->fd_table[fd] = fp;

	return fd;
}

static int
filesize (int fd) {
	if (fd < 2) return -1;

	lock_acquire(&filesys_lock);
	int ret = file_length(thread_current()->fd_table[fd]);
	lock_release(&filesys_lock);

	return ret;
}

static int
read (int fd, void *buffer, unsigned size) {
	ADDR_VAL(buffer)
	
	if (fd == 0)
	{
		unsigned i;
		for (i = 0; i < size; i++)
			*(char *)(buffer + i) = input_getc();
		return (int) i;
	} else if (fd == 1) return -1;

	struct file *fp = thread_current()->fd_table[fd];

	if (!fp) return -1;

	lock_acquire(&filesys_lock);
	int ret = file_read(fp, buffer, size);
	lock_release(&filesys_lock);

	return ret;
}

static int
write (int fd, const void *buffer, unsigned size) {
	ADDR_VAL(buffer)

	if (fd == 1)
	{
		putbuf(buffer, size);
		return size;
	} else if (fd == 0) return -1;

	struct file *fp = thread_current()->fd_table[fd];

	if (!fp) return -1;
	
	lock_acquire(&filesys_lock);
	int ret = file_write(fp, buffer, size);
	lock_release(&filesys_lock);

	return ret;
}

static void
seek (int fd, unsigned position) {
	if (fd < 2) return;

	struct file *fp = thread_current()->fd_table[fd];

	if (!fp) return;

	lock_acquire(&filesys_lock);
	file_seek(fp, position);
	lock_release(&filesys_lock);
}

static unsigned
tell (int fd) {
	if (fd < 2) return -1;

	struct file *fp = thread_current()->fd_table[fd];

	if (!fp) return -1;

	lock_acquire(&filesys_lock);
	unsigned ret = file_tell(fp);
	lock_release(&filesys_lock);

	return ret;
}

static void
close (int fd) {
	if (fd < 2) return;

	struct thread *curr = thread_current();
	struct file *fp = curr->fd_table[fd];

	if (!fp) return;

	curr->fd_table[fd] = NULL;

	if(curr->fd_end == fd) curr->fd_end--;

	lock_acquire(&filesys_lock);
	file_close(fp);
	lock_release(&filesys_lock);
}
