#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern unsigned long module_address(pid_t pid, int prot, const char *name);
extern unsigned long symbol_vaddr(const char *path, const char *sym_name);

void *page_floor(void *address)
{
	return (void *)((unsigned long)address & -getpagesize());
}

void inline_hook(void *orig_func, void *hook_func)
{
#ifdef __aarch64__
	/*
	 * AArch64 trampoline:
	 *   ldr x16, #8   — load the 64-bit target address from PC+8 into x16
	 *   br  x16       — branch to x16
	 *   <8 bytes>     — 64-bit target address
	 *
	 * ldr x16, #8 = 0x58000050  (little-endian: 0x50, 0x00, 0x00, 0x58)
	 * br  x16     = 0xD61F0200  (little-endian: 0x00, 0x02, 0x1F, 0xD6)
	 */
	char jmp_bytes[] = {
		0x50, 0x00, 0x00, 0x58,                         /* ldr x16, #8 */
		0x00, 0x02, 0x1F, 0xD6,                         /* br  x16     */
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC  /* address placeholder */
	};

	/* Copy hook address into the placeholder at offset 8 (after the two 4-byte instructions). */
	memcpy(jmp_bytes + 8, &hook_func, sizeof(unsigned long));
#else
	char jmp_bytes[] = {
		/* mov rax, 0xCCCCCCCCCCCCCCCC */
		0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		/* jmp rax */
		0xFF, 0xE0
	};

	memcpy(jmp_bytes + 2, &hook_func, sizeof(unsigned long));
#endif
	int page_size = getpagesize();

	mprotect(page_floor(orig_func), page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
	memcpy(orig_func, jmp_bytes, sizeof(jmp_bytes));
	mprotect(page_floor(orig_func), page_size, PROT_READ | PROT_EXEC);
}

void my_hook_function()
{
	printf("Hello from hooked function!\n");
}

__attribute__((constructor)) void on_load()
{
	printf("Hello from library\n");

	void *text_segment = (void *)module_address(-1, PROT_READ | PROT_EXEC, "hello");

	/*
	 * Resolve `my_function` from the ELF symbol table of the target binary.
	 * symbol_vaddr() returns the in-file VMA (st_value); subtracting 0x1000
	 * gives the offset within the R|E segment returned by module_address().
	 */
	unsigned long fn_vaddr = symbol_vaddr("/proc/self/exe", "my_function");
	void *my_function = text_segment + fn_vaddr - 0x1000;

	inline_hook(my_function, my_hook_function);
}

__attribute__((destructor)) void on_unload()
{
	printf("Bye from library\n");
}
