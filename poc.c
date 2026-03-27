#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __aarch64__
#include <sys/uio.h>
#endif

#define DEBUG 1

extern unsigned long module_address(pid_t pid, int prot, const char *name);

unsigned long ptrace_checked(enum __ptrace_request request, pid_t pid, void *addr,
		void *data)
{
	unsigned long ret = ptrace(request, pid, addr, data);
#if DEBUG == 1
	printf("ptrace called with request: %d, pid: %d, addr: %p, data: %p resulted: %lx\n",
			request, pid, addr, data, ret);
#endif
	return ret;
}

/*
 * Architecture-specific register access abstractions.
 *
 * x86-64: uses PTRACE_GETREGS/PTRACE_SETREGS with struct user_regs_struct.
 * AArch64: uses PTRACE_GETREGSET/PTRACE_SETREGSET (NT_PRSTATUS) with
 *          struct user_pt_regs, as PTRACE_GETREGS is not available on AArch64.
 */
#ifdef __aarch64__

typedef struct user_pt_regs arch_regs_t;

#define ARCH_GETREGS(pid, regs) do { \
	struct iovec _iov = { .iov_base = &(regs), .iov_len = sizeof(regs) }; \
	ptrace_checked(PTRACE_GETREGSET, (pid), (void *)NT_PRSTATUS, &_iov); \
} while (0)

#define ARCH_SETREGS(pid, regs) do { \
	struct iovec _iov = { .iov_base = &(regs), .iov_len = sizeof(regs) }; \
	ptrace_checked(PTRACE_SETREGSET, (pid), (void *)NT_PRSTATUS, &_iov); \
} while (0)

/* AArch64 C calling convention: arguments in x0-x7, return value in x0. */
#define ARCH_REG_ARG0(r)  (r).regs[0]
#define ARCH_REG_ARG1(r)  (r).regs[1]
#define ARCH_REG_ARG2(r)  (r).regs[2]
#define ARCH_REG_ARG3(r)  (r).regs[3]
#define ARCH_REG_ARG4(r)  (r).regs[4]
#define ARCH_REG_ARG5(r)  (r).regs[5]
#define ARCH_REG_PC(r)    (r).pc
#define ARCH_REG_SP(r)    (r).sp
#define ARCH_REG_RET(r)   (r).regs[0]

/*
 * AArch64 BRK #0 instruction (0xD4200000).
 * When executed under ptrace it delivers SIGTRAP to the tracee.
 */
#define ARCH_BREAKPOINT  0xD4200000UL

/*
 * On AArch64, the return address is held in the link register x30 (regs[30]).
 * Setting it to 0x0 causes a SIGSEGV when the callee returns via `RET`.
 */
#define ARCH_SET_RETURN_TRAP(child, regs) ((regs).regs[30] = 0x0)

#else /* x86-64 */

typedef struct user_regs_struct arch_regs_t;

#define ARCH_GETREGS(pid, regs) \
	ptrace_checked(PTRACE_GETREGS, (pid), NULL, &(regs))

#define ARCH_SETREGS(pid, regs) \
	ptrace_checked(PTRACE_SETREGS, (pid), NULL, &(regs))

/* x86-64 System V AMD64 ABI: arguments in rdi, rsi, rdx, rcx, r8, r9. */
#define ARCH_REG_ARG0(r)  (r).rdi
#define ARCH_REG_ARG1(r)  (r).rsi
#define ARCH_REG_ARG2(r)  (r).rdx
#define ARCH_REG_ARG3(r)  (r).rcx
#define ARCH_REG_ARG4(r)  (r).r8
#define ARCH_REG_ARG5(r)  (r).r9
#define ARCH_REG_PC(r)    (r).rip
#define ARCH_REG_SP(r)    (r).rsp
#define ARCH_REG_RET(r)   (r).rax

/* x86-64 single-byte INT 3 software breakpoint. */
#define ARCH_BREAKPOINT  0xCCUL

/*
 * On x86-64, the return address is pushed onto the stack.
 * Setting it to 0x0 causes a SIGSEGV when the callee executes `ret`.
 */
#define ARCH_SET_RETURN_TRAP(child, regs) do { \
	(regs).rsp -= sizeof(long); \
	ptrace_checked(PTRACE_POKEDATA, (child), (void *)(regs).rsp, (void *)0x0); \
} while (0)

#endif /* __aarch64__ */

int main(int argc, char *argv[])
{
	pid_t child;
	unsigned long entry_point;

	{
		ElfW(Ehdr) *ehdr;
		FILE *f;
		unsigned char buff[255] = {0};

		if (argc < 3) {
			fprintf(stderr, "%s [target] [.so]\n", argv[0]);
			return -1;
		}

		/* Read target binary. */
		f = fopen(argv[1], "r");
		if (f == NULL) {
			fprintf(stderr, "%s is not a file\n", argv[1]);
			return -1;
		}

		/* We check if the binary is an ELF file. */
		fread(buff, sizeof(buff), 1, f);
		if (memcmp(buff, ELFMAG, SELFMAG)) {
			fprintf(stderr, "%s is not an ELF\n", argv[1]);
			return -1;
		}
		fclose(f);

		/* We now have the executable header of the target ELF. */
		ehdr = (void *)buff;

		/* 
		 * `.text` section starts at 0x1000 (page aligned) but we need the actual offset
		 * of  the entry point from the start of `.text` section. Refer to `objdump`.
		 */
		entry_point = ehdr->e_entry - 0x1000;
	}

	if ((child = fork()) != 0) {
		int status;
		unsigned long word;

		/* Wait for SIGSTOP in child. */
		wait(&status);

		{
			printf("child with pid %d stopped...\n", child);

			/* Trace `execve()` syscall. */
			ptrace_checked(PTRACE_SETOPTIONS, child, NULL, (void *)PTRACE_O_TRACEEXEC);
			/* Let us continue. */
			ptrace_checked(PTRACE_CONT, child, NULL, NULL);
		}

		/* Wait before `execve()` returns, we are in the target process image now. */
		wait(&status);

		{
			/* Get the target's entry point within its own memory space. */
			entry_point += module_address(child, PROT_READ | PROT_EXEC, argv[1]);

			printf("entry point address `_start()` of target is: 0x%lx\n", entry_point);

			/* Backup a word of data from target's entry point. */
			word = ptrace_checked(PTRACE_PEEKTEXT, child, (void *)entry_point, NULL);
			/* Install a software breakpoint at the entry point. */
			ptrace_checked(PTRACE_POKETEXT, child, (void *)entry_point,
					(void *)ARCH_BREAKPOINT);
			/* Continue; the child will stop when it executes the breakpoint instruction. */
			ptrace_checked(PTRACE_CONT, child, NULL, NULL);
		}

		/* Wait for the breakpoint. */
		wait(&status);

		unsigned long local_libc, remote_libc, allocmem;

		{
			unsigned long remote_mmap;
			{
				/* Get the remote address of `mmap()` */
				local_libc = module_address(-1, PROT_READ | PROT_EXEC, "libc.so");
				remote_libc = module_address(child, PROT_READ | PROT_EXEC, "libc.so");
				unsigned long local_mmap = (unsigned long)mmap;
				/* 
				 * Why? So we avoid getting the offset directly from libc.so every time there's an update
				 * or if you're a madlad and you compile it constantly. 
				 */
				remote_mmap = remote_libc + (local_mmap - local_libc);
				printf("remote `mmap()` function address is: %p\n", (void *)remote_mmap);
			}

			arch_regs_t regs;

			/* Get the current value of the general-purpose registers. */
			ARCH_GETREGS(child, regs);

			/*
			 * Modify registers to remote call `mmap()`.
			 * Arguments follow the platform's C calling convention.
			 */
			ARCH_REG_ARG0(regs) = 0;                               // addr
			ARCH_REG_ARG1(regs) = 0x1000;                         // length
			ARCH_REG_ARG2(regs) = PROT_READ | PROT_WRITE | PROT_EXEC; // prot
			ARCH_REG_ARG3(regs) = MAP_ANONYMOUS | MAP_PRIVATE;    // flags
			ARCH_REG_ARG4(regs) = 0;                              // fd
			ARCH_REG_ARG5(regs) = 0;                              // offset
			ARCH_REG_PC(regs) = remote_mmap;

			/*
			 * Set the return address to 0x0 so that when the subroutine returns it
			 * will raise a signal that we can catch.
			 */
			ARCH_SET_RETURN_TRAP(child, regs);

			/* Send our modified registers. */
			ARCH_SETREGS(child, regs);
			/* Let us continue. */
			ptrace_checked(PTRACE_CONT, child, NULL, NULL);

			/* Wait for the SIGSEGV caused by the 0x0 return address. */
			wait(&status);

			/* Get the current value of the general-purpose registers. */
			ARCH_GETREGS(child, regs);

			/*
			 * The return value of the subroutine is in the first return register.
			 */
			allocmem = ARCH_REG_RET(regs);
			printf("remote `mmap()` returned: %p\n", (void *)allocmem);

			/* +1 to consider the \0 character of every C string. */
			unsigned long path_size = strlen(argv[2]) + 1;
			unsigned long chunks = path_size / sizeof(long);
			unsigned long remaining = path_size % sizeof(long);

			for (int i = 0; i < chunks; i++) {
				unsigned long buffer = 0;
				unsigned long offset = i * sizeof(long);

				memcpy(&buffer, argv[2] + offset, sizeof(buffer));

				ptrace_checked(PTRACE_POKEDATA, child, (void* )(allocmem + offset),
						(void *)buffer);
			}

			if (remaining != 0) {
				unsigned long offset = chunks * sizeof(long);
				unsigned long buffer = ptrace_checked(PTRACE_PEEKDATA, child, (void *)(allocmem + offset),
						NULL);

				memcpy(&buffer, argv[2] + offset, remaining);
				ptrace_checked(PTRACE_POKEDATA, child, (void* )(allocmem + offset),
						(void *)buffer);
			}
		}

		{
			unsigned long remote_dlopen;
			{
				/* Get the remote address of `dlopen()` */
				unsigned long local_dlopen = (unsigned long)dlopen;
				/* Why? Already explained it. */
				remote_dlopen = remote_libc + (local_dlopen - local_libc);
				printf("remote `dlopen()` function address is: %p\n", (void *)remote_dlopen);
			}

			arch_regs_t regs;

			/* Get the current value of the general-purpose registers. */
			ARCH_GETREGS(child, regs);

			/* Modify registers to remote call `dlopen()` */
			ARCH_REG_ARG0(regs) = allocmem;                // filename
			/* 
			 * We need our library to be loaded completely and globally for subsequent dynamic
			 * dependencies.
			 */
			ARCH_REG_ARG1(regs) = RTLD_NOW | RTLD_GLOBAL; // flags
			ARCH_REG_PC(regs) = remote_dlopen;

			/*
			 * Set the return address to 0x0 so that when the subroutine returns it
			 * will raise a signal that we can catch.
			 */
			ARCH_SET_RETURN_TRAP(child, regs);

			/* Send our modified registers. */
			ARCH_SETREGS(child, regs);
			/* Let us continue. */
			ptrace_checked(PTRACE_CONT, child, NULL, NULL);

			/* Wait for the SIGSEGV caused by the 0x0 return address. */
			wait(&status);

			/* Get the current value of the general-purpose registers. */
			ARCH_GETREGS(child, regs);

			unsigned long lib_handle = ARCH_REG_RET(regs);
			printf("remote `dlopen()` returned: %p\n", (void *)lib_handle);
		}

		{
			/* Restore the instructions we modified for the entry point. */
			ptrace_checked(PTRACE_POKETEXT, child, (void *)entry_point, (void *)word);

			/* Get the current value of the general-purpose registers. */
			arch_regs_t regs;
			ARCH_GETREGS(child, regs);

			/*
			 * Set Program Counter to entry point to execute the target program as if
			 * nothing happened.
			 */
			ARCH_REG_PC(regs) = entry_point;

			/* Restore the original state of the target program. */
			ARCH_SETREGS(child, regs);
		}

		/* Wait for keyboard input. */
		getchar();

		ptrace_checked(PTRACE_DETACH, child, NULL, NULL);
	} else {
		char *const newargv[] = { argv[1], NULL };
		char *const newenvp[] = { NULL };

		ptrace_checked(PTRACE_TRACEME, 0, NULL, NULL);

		/* PTRACE_TRACEME doesn't send a stop signal. */
		raise(SIGSTOP);
		
		/* Execute target. */
		execve(argv[1], newargv, newenvp);

		/* Child is now replaced with the target's process image by `execve()`. */
	}

	return 0;
}
