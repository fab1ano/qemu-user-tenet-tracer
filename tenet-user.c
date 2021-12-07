// MIT License
// 
// Copyright (c) 2021 Markus Gaasedelen
// Copyright (c) 2021 Fabian Fleischer
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
//
// Original work:
// https://github.com/gaasedelen/tenet/blob/master/tracers/qemu/tenet.c


#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>

#include <qemu-plugin.h>

#include <linux/limits.h>
#include <fnmatch.h>

//struct X86CPU {
//    /*< private >*/
//    CPUState parent_obj;
//    /*< public >*/
//
//    CPUNegativeOffsetState neg;
//    CPUX86State env; // THIS IS @ 33536
//    [...]

#define CPUState_Size 33536
#define FILTER_PATTERN "*target_binary"


// X86_64-specific registers
#define NUM_REG 16

enum reg
{
    RAX = 0,
    RCX = 1,
    RDX = 2,
    RBX = 3,
    RSP = 4,
    RBP = 5,
    RSI = 6,
    RDI = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15
};

const char *reg_name[NUM_REG] = \
{
    "RAX",
    "RCX",
    "RDX",
    "RBX",
    "RSP",
    "RBP",
    "RSI",
    "RDI",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15"
};


// Plugin version
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;


// QEMU functions
void *qemu_get_cpu(int index);
void *qemu_map_ram_ptr(void *ram_block, uint64_t addr);


// Address region filtering
static GArray *log_regions = NULL;

struct Range
{
    uint64_t lower_b;
    uint64_t upper_b;
};

static void update_log_regions(void)
{
    char buf[PATH_MAX + 200];

    // Read /proc/self/maps
    FILE *fptr = fopen("/proc/self/maps", "r");
    if (!fptr)
        return;

    if (log_regions)
    {
        g_array_unref(log_regions);
        log_regions = NULL;
    }

    log_regions = g_array_new(FALSE, FALSE, sizeof(struct Range));

    while (fgets(buf, sizeof(buf), fptr))
    {
        char *filename;
        char *addr_from_str = strtok(buf, "-");
        char *addr_to_str = strtok(NULL, " ");
        if (!addr_from_str || !addr_to_str)
            break;

        for (int i = 0; i<4; i++)
            strtok(NULL, " ");

        filename = strtok(NULL, " \n");
        if (!filename)
            continue;

        if (!fnmatch(FILTER_PATTERN, filename, 0))
        {
            // Events in this entry shall be traced
            struct Range range;

            range.lower_b = strtol(addr_from_str, NULL, 16);
            range.upper_b = strtol(addr_to_str, NULL, 16);

            g_array_append_val(log_regions, range);
        }
    }

    fclose(fptr);
}

static bool addr_in_log_range(uint64_t addr)
{
    if (log_regions)
    {
        for (unsigned int i = 0; i < log_regions->len; i++)
        {
            struct Range *range = &g_array_index(log_regions, struct Range, i);
            if (range->lower_b <= addr && addr <= range->upper_b)
                return true;
        }
        return false;
    } else
        return false;
}


// Utils
static uint64_t * get_cpu_regs(void)
{
    uint8_t *cpu = (uint8_t *) qemu_get_cpu(0);
    return (uint64_t*)(cpu + CPUState_Size);
}


// QEMU callbacks and data structures
typedef struct mem_entry
{
    qemu_plugin_meminfo_t info;
    uint64_t virt_addr;
    uint64_t ram_addr;
} mem_entry;

static FILE *trace_file = NULL;

static uint64_t *g_cpu = NULL;
static uint64_t g_cpu_prev[NUM_REG] = {};

static char reg_scratch[2048] = {};

static mem_entry g_mem_log[2048] = {};
static size_t g_mem_log_count = 0;

static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
    (void) cpu_index;

    int length = 0;

    // Get all registers that changed
    for (int i = 0; i < NUM_REG; i++)
        if (g_cpu[i] != g_cpu_prev[i])
            length += sprintf(reg_scratch+length, "%s=%lX,", reg_name[i], g_cpu[i]);

    // Get the new instruction pointer
    uint64_t rip = GPOINTER_TO_UINT(udata);
    length += sprintf(reg_scratch+length, "RIP=%lX", rip);

    for (size_t i = 0; i < g_mem_log_count; i++)
    {
        mem_entry *entry = &g_mem_log[i];

        // reconstruct info about the mem access
        size_t access_size = 1 << (entry->info & 0xF);
        char rw = qemu_plugin_mem_is_store(entry->info) ? 'w' : 'r';

        length += sprintf(reg_scratch+length, ",m%c=%lX:", rw, entry->virt_addr);

        // fetch the resulting memory
        unsigned char access_data[16] = {};
        memcpy(access_data, (void *) entry->virt_addr, access_size);

        for(size_t j = 0; j < access_size; j++)
            length += sprintf(reg_scratch+length, "%02X", access_data[j]);
    }

    fprintf(trace_file, "%s\n", reg_scratch);
    fflush(trace_file);

    reg_scratch[0] = '\0';
    g_mem_log_count = 0;

    memcpy(g_cpu_prev, g_cpu, sizeof(g_cpu_prev));
}

static void vcpu_mem_access(unsigned int cpu_index, qemu_plugin_meminfo_t
        mem_info, uint64_t vaddr, void *udata)
{
    (void) cpu_index;
    (void) udata;

    struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(mem_info,
            vaddr);
    if (qemu_plugin_hwaddr_is_io(hwaddr))
        return;

    uint64_t physaddr = qemu_plugin_hwaddr_device_offset(hwaddr);
    assert(physaddr < 0xFFFFFFFF);

    mem_entry *entry = &g_mem_log[g_mem_log_count++];

    entry->info = mem_info;
    entry->virt_addr = vaddr;
    entry->ram_addr = physaddr;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void) id;

    // Update log regions
    update_log_regions();

    size_t n = qemu_plugin_tb_n_insns(tb);

    g_cpu = get_cpu_regs();

    for (size_t i = 0; i < n; i++)
    {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t vaddr = qemu_plugin_insn_vaddr(insn);

        if (!addr_in_log_range(vaddr))
            break;

        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                QEMU_PLUGIN_CB_R_REGS, GUINT_TO_POINTER(vaddr));
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_access,
                QEMU_PLUGIN_CB_R_REGS, QEMU_PLUGIN_MEM_RW,
                GUINT_TO_POINTER(vaddr));
    }
}


// QEMU plugin entry
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const
        qemu_info_t *info, int argc, char **argv)
{
    (void) info;

    const char *filepath = NULL;

    if (argc)
        filepath = argv[0];
    else
        filepath = "trace.log";

    printf("Writing Tenet trace to %s\n", filepath);
    trace_file = fopen(filepath, "w");

    memset(g_cpu_prev, 0xFF, sizeof(g_cpu_prev));
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

    return 0;
}
