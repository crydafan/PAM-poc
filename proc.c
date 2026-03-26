#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>

unsigned long module_address(pid_t pid, int prot, const char *name)
{
	FILE *f;
	char *proc, *line, permissions[4];
	size_t n;
	unsigned long address;
	unsigned int oflag = 0;

	if (pid == -1) {
		proc = strdup("/proc/self/maps");
	} else {
		asprintf(&proc, "/proc/%d/maps", pid);
	}

	f = fopen(proc, "r");

	while (getline(&line, &n, f) != EOF) {
		if (strstr(line, name) != NULL) {
			sscanf(line, "%lx-%*x %s %*s %*s %*s %*s", &address, permissions);

			if (prot == -1)
				break;

			for (int i = 0; permissions[i] != 'p'; i++) {
				switch (permissions[i]) {
				case 'r':
					oflag |= PROT_READ;
					break;
				case 'w':
					oflag |= PROT_WRITE;
					break;
				case 'x':
					oflag |= PROT_EXEC;
					break;
				default:
					break;
				}
			}

			if (prot == oflag)
				break;
		}
	}

	fclose(f);
	free(proc);

	return address;
}

/*
 * Read the ELF symbol table (.symtab) of the binary at `path` and return
 * the virtual address of the symbol named `sym_name`, or 0 if not found.
 *
 * The returned value is the in-file VMA (st_value), which for a PIE binary
 * equals the offset from the first PT_LOAD segment's p_vaddr.
 */
unsigned long symbol_vaddr(const char *path, const char *sym_name)
{
	int fd;
	ElfW(Ehdr) ehdr;
	ElfW(Shdr) *shdrs = NULL;
	ElfW(Sym) *syms = NULL;
	char *strtab = NULL;
	unsigned long vaddr = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;

	if (read(fd, &ehdr, sizeof(ehdr)) != (ssize_t)sizeof(ehdr))
		goto done;

	shdrs = malloc((size_t)ehdr.e_shnum * ehdr.e_shentsize);
	if (!shdrs)
		goto done;

	lseek(fd, (off_t)ehdr.e_shoff, SEEK_SET);
	if (read(fd, shdrs, (size_t)ehdr.e_shnum * ehdr.e_shentsize) !=
			(ssize_t)((size_t)ehdr.e_shnum * ehdr.e_shentsize))
		goto done;

	for (int i = 0; i < ehdr.e_shnum; i++) {
		if (shdrs[i].sh_type != SHT_SYMTAB)
			continue;

		ElfW(Shdr) *strtab_sh = &shdrs[shdrs[i].sh_link];
		int num_syms = (int)(shdrs[i].sh_size / sizeof(ElfW(Sym)));

		syms = malloc(shdrs[i].sh_size);
		strtab = malloc(strtab_sh->sh_size);
		if (!syms || !strtab)
			goto done;

		lseek(fd, (off_t)shdrs[i].sh_offset, SEEK_SET);
		if (read(fd, syms, shdrs[i].sh_size) != (ssize_t)shdrs[i].sh_size)
			goto done;

		lseek(fd, (off_t)strtab_sh->sh_offset, SEEK_SET);
		if (read(fd, strtab, strtab_sh->sh_size) != (ssize_t)strtab_sh->sh_size)
			goto done;

		for (int j = 0; j < num_syms; j++) {
			if (syms[j].st_name >= strtab_sh->sh_size)
				continue;
			if (strcmp(&strtab[syms[j].st_name], sym_name) == 0) {
				vaddr = (unsigned long)syms[j].st_value;
				break;
			}
		}

		free(syms); syms = NULL;
		free(strtab); strtab = NULL;

		if (vaddr)
			break;
	}

done:
	if (shdrs) free(shdrs);
	if (syms) free(syms);
	if (strtab) free(strtab);
	close(fd);
	return vaddr;
}
