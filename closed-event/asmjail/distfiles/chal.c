// gcc chal.c -o chal

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/io_uring.h>
#include <linux/seccomp.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define MAX_EXEC_REGIONS 128
#define URING_ENTRIES 4

typedef struct {
  unsigned long start;
  unsigned long end;
} ExecRegion;

typedef struct {
  uint64_t sqe_array;
  uint64_t sq_ring;
  uint32_t sq_off_tail;
  uint32_t sq_off_array;
  uint32_t sq_entries;
  uint32_t _pad;
} ShellboxMeta;

static void install_seccomp(void) {
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_enter, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
  };

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  long ret;

  __asm__ volatile("mov $157, %%rax\n\t"   /* __NR_prctl */
                   "mov $38, %%rdi\n\t"    /* PR_SET_NO_NEW_PRIVS */
                   "mov $1, %%rsi\n\t"
                   "xor %%rdx, %%rdx\n\t"
                   "xor %%r10, %%r10\n\t"
                   "xor %%r8, %%r8\n\t"
                   "syscall\n\t"
                   "mov %%rax, %0\n\t"
                   : "=r"(ret)
                   :
                   : "rax", "rdi", "rsi", "rdx", "r10", "r8", "rcx", "r11",
                     "memory");
  if (ret) {
    __asm__ volatile("mov $60, %%rax\n\t"
                     "mov $1, %%rdi\n\t"
                     "syscall\n\t" ::: "rax", "rdi");
    __builtin_unreachable();
  }

  __asm__ volatile("mov $157, %%rax\n\t"   /* __NR_prctl */
                   "mov $22, %%rdi\n\t"    /* PR_SET_SECCOMP */
                   "mov $2, %%rsi\n\t"     /* SECCOMP_MODE_FILTER */
                   "mov %1, %%rdx\n\t"
                   "syscall\n\t"
                   "mov %%rax, %0\n\t"
                   : "=r"(ret)
                   : "r"(&prog)
                   : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory");
  if (ret) {
    __asm__ volatile("mov $60, %%rax\n\t"
                     "mov $1, %%rdi\n\t"
                     "syscall\n\t" ::: "rax", "rdi");
    __builtin_unreachable();
  }
}

bool is_safe(uint8_t *n) {
  for (int i = 0; i < 0x1000; i++) {
    if (n[i] == 0x48 && n[i + 1] == 0x8D && (n[i + 2] & 0xC7) == 0x05) {
      return false;
    }
    if (n[i] == 0xF3 && n[i + 1] == 0x0F && n[i + 2] == 0xAE) {
      return false;
    }
    if (n[i] == 0xF3 && n[i + 2] == 0x0F && n[i + 3] == 0xAE) {
      return false;
    }
  }
  return true;
}

void safe_box(uint8_t *shellcode) {
  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp) {
    perror("fopen");
    return;
  }

  ExecRegion exec_regions[MAX_EXEC_REGIONS];
  int count = 0;

  char line[256];
  while (fgets(line, sizeof(line), fp)) {
    unsigned long start, end;
    char perms[5];

    if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
      continue;

    if (strchr(perms, 'x') && strstr(line, "lib") && count < MAX_EXEC_REGIONS) {
      exec_regions[count].start = start;
      exec_regions[count].end = end;
      count++;
    }

    if (strchr(perms, 'x') && strstr(line, "vdso") &&
        count < MAX_EXEC_REGIONS) {
      exec_regions[count].start = start;
      exec_regions[count].end = end;
      count++;
    }
  }

  fclose(fp);
  printf("Secure the Shellbox\n");

  for (int i = 0; i < count; i++) {
    __asm__ volatile("mov $10, %%rax\n\t"
                     "mov %0, %%rdi\n\t"
                     "mov %1, %%rsi\n\t"
                     "mov $1, %%rdx\n\t"
                     "syscall\n\t"
                     :
                     : "r"(exec_regions[i].start),
                       "r"(exec_regions[i].end - exec_regions[i].start)
                     : "rax", "rdi", "rsi", "rdx");
  }
  return;
}

static int setup_uring(struct io_uring_params *params, void **sq_ring_out,
                       void **cq_ring_out, void **sqe_array_out) {
  memset(params, 0, sizeof(*params));

  int uring_fd = syscall(__NR_io_uring_setup, URING_ENTRIES, params);
  if (uring_fd < 0) {
    perror("io_uring_setup");
    exit(1);
  }

  size_t sq_ring_sz =
      params->sq_off.array + params->sq_entries * sizeof(uint32_t);
  size_t cq_ring_sz =
      params->cq_off.cqes + params->cq_entries * sizeof(struct io_uring_cqe);

  void *sq_ring = mmap(NULL, sq_ring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, uring_fd, IORING_OFF_SQ_RING);
  if (sq_ring == MAP_FAILED) {
    perror("mmap sq_ring");
    exit(1);
  }

  void *cq_ring = mmap(NULL, cq_ring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, uring_fd, IORING_OFF_CQ_RING);
  if (cq_ring == MAP_FAILED) {
    perror("mmap cq_ring");
    exit(1);
  }

  void *sqe_array =
      mmap(NULL, params->sq_entries * sizeof(struct io_uring_sqe),
           PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, uring_fd,
           IORING_OFF_SQES);
  if (sqe_array == MAP_FAILED) {
    perror("mmap sqes");
    exit(1);
  }

  *sq_ring_out = sq_ring;
  *cq_ring_out = cq_ring;
  *sqe_array_out = sqe_array;

  return uring_fd;
}

int main() {
  uint8_t *shellcode = (uint8_t *)0x100000000;
  uint8_t *max_map = (uint8_t *)0xffffffff000;

  srand(time(NULL));

  size_t max_off = (max_map - shellcode) / 0x2000;
  size_t add_off = (rand() % max_off) * 0x2000;
  shellcode += add_off;

  if (mmap(shellcode, 0x2000, PROT_READ | PROT_WRITE,
           MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE, -1,
           0) == MAP_FAILED) {
    perror("mmap failed");
    exit(EXIT_FAILURE);
  }

  int flag_fd = open("flag.txt", 0 /* O_RDONLY */);
  if (flag_fd < 0) {
    perror("open flag.txt");
    exit(1);
  }

  int pipefd[2];
  if (pipe(pipefd) < 0) {
    perror("pipe");
    exit(1);
  }

  struct io_uring_params params;
  void *sq_ring, *cq_ring, *sqe_array;
  int uring_fd = setup_uring(&params, &sq_ring, &cq_ring, &sqe_array);

  ShellboxMeta *meta = (ShellboxMeta *)(shellcode + 0x1000);
  meta->sqe_array = (uint64_t)sqe_array;
  meta->sq_ring = (uint64_t)sq_ring;
  meta->sq_off_tail = params.sq_off.tail;
  meta->sq_off_array = params.sq_off.array;
  meta->sq_entries = params.sq_entries;

  unsigned char code[] = {
      0x48, 0x31, 0xc0,             // xor rax, rax
      0x48, 0x31, 0xdb,             // xor rbx, rbx
      0x48, 0x31, 0xc9,             // xor rcx, rcx
      0x48, 0x31, 0xd2,             // xor rdx, rdx
      0x48, 0x31, 0xf6,             // xor rsi, rsi
      0x48, 0x31, 0xff,             // xor rdi, rdi
      0x48, 0x31, 0xe4,             // xor rsp, rsp
      0x48, 0x31, 0xed,             // xor rbp, rbp
      0x4d, 0x31, 0xc0,             // xor r8,  r8
      0x4d, 0x31, 0xc9,             // xor r9,  r9
      0x4d, 0x31, 0xd2,             // xor r10, r10
      0x4d, 0x31, 0xdb,             // xor r11, r11
      0x4d, 0x31, 0xe4,             // xor r12, r12
      0x4d, 0x31, 0xed,             // xor r13, r13
      0x4d, 0x31, 0xf6,             // xor r14, r14
      0x4d, 0x31, 0xff,             // xor r15, r15
      0xf3, 0x48, 0x0f, 0xae, 0xd0, // wrfsbase rax
      0xc5, 0xfc, 0x57, 0xc0,
      0xc5, 0xf4, 0x57, 0xc9,
      0xc5, 0xec, 0x57, 0xd2,
      0xc5, 0xe4, 0x57, 0xdb,
      0xc5, 0xdc, 0x57, 0xe4,
      0xc5, 0xd4, 0x57, 0xed,
      0xc5, 0xcc, 0x57, 0xf6,
      0xc5, 0xc4, 0x57, 0xff,
  };

  size_t max = 0x1000 - sizeof(code);
  size_t off = 0;

  printf("Please provide about 0x%lx bytes of input:\n",max);

  while (off < max) {
    ssize_t n = read(STDIN_FILENO, shellcode + sizeof(code) + off, max - off);
    if (n < 0) {
      perror("read failed");
      exit(1);
    }
    if (n == 0)
      break;
    off += (size_t)n;
  }

  int shell_len = (int)off;
  close(STDIN_FILENO);

  if (!is_safe(shellcode)) {
    printf("Input is not Safe\n");
    exit(EXIT_FAILURE);
  }

  printf("Safe Input!\n");

  memcpy(shellcode, code, sizeof(code));
  memset(shellcode + sizeof(code) + shell_len, 0x90,
         0x1000 - sizeof(code) - shell_len);

  if (mprotect(shellcode, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    perror("mprotect failed");
    exit(EXIT_FAILURE);
  }

  safe_box(shellcode);

  install_seccomp();

  void (*shell)() = (void (*)())shellcode;
  shell();
}


__attribute__((constructor))
void setup() {
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
}
