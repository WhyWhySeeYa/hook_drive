#pragma once

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE MAP_FIXED
#endif

#define LSDRIVER_PROCESS_NAME "LS"
#define LSDRIVER_REQ_ADDR ((void *)0x2025827000ULL)

#define LSDRIVER_MAX_MODULES 1024
#define LSDRIVER_MAX_SCAN_REGIONS 16534
#define LSDRIVER_MOD_NAME_LEN 256
#define LSDRIVER_MAX_SEGS_PER_MODULE 512
#define LSDRIVER_HOOK_NAME_LEN 64

typedef struct lsdriver_segment_info {
    int16_t index;
    uint8_t prot;
    uint64_t start;
    uint64_t end;
} lsdriver_segment_info_t;

typedef struct lsdriver_module_info {
    char name[LSDRIVER_MOD_NAME_LEN];
    int seg_count;
    lsdriver_segment_info_t segs[LSDRIVER_MAX_SEGS_PER_MODULE];
} lsdriver_module_info_t;

typedef struct lsdriver_region_info {
    uint64_t start;
    uint64_t end;
} lsdriver_region_info_t;

typedef struct lsdriver_virtual_memory {
    int module_count;
    lsdriver_module_info_t modules[LSDRIVER_MAX_MODULES];
    int region_count;
    lsdriver_region_info_t regions[LSDRIVER_MAX_SCAN_REGIONS];
} lsdriver_virtual_memory_t;

typedef struct lsdriver_virtual_memoryrw {
    uint64_t rw_addr;
    uint8_t user_buffer[0x1000];
    int size;
} lsdriver_virtual_memoryrw_t;

typedef struct lsdriver_shadow_hook_request {
    uint64_t hook_addr;
    uint64_t field_offset;
    uint32_t hit_count;
    int32_t last_value;
    char hook_name[LSDRIVER_HOOK_NAME_LEN];
} lsdriver_shadow_hook_request_t;

typedef enum lsdriver_request_op {
    LSD_OP_NONE = 0,
    LSD_OP_VMEM_READ = 1,
    LSD_OP_VMEM_WRITE = 2,
    LSD_OP_VMEM_INFO = 3,
    LSD_OP_SHADOW_HOOK_ADD = 4,
    LSD_OP_SHADOW_HOOK_DEL = 5,
    LSD_OP_SHADOW_HOOK_CLEAR = 6,
    LSD_OP_KERNEL_EXIT = 7,
} lsdriver_request_op_t;

typedef struct lsdriver_request_obj {
    volatile bool kernel;
    volatile bool user;
    volatile lsdriver_request_op_t op;
    volatile int status;
    int tgid;
    lsdriver_virtual_memoryrw_t vmemrw_info;
    lsdriver_virtual_memory_t vmem_info;
    lsdriver_shadow_hook_request_t shadow_hook_info;
} lsdriver_request_obj_t;

typedef struct lsdriver_handle {
    lsdriver_request_obj_t *req;
} lsdriver_t;

static inline uint64_t lsdriver_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static inline int lsdriver_set_name(void)
{
    return prctl(PR_SET_NAME, LSDRIVER_PROCESS_NAME, 0, 0, 0);
}

static inline int lsdriver_find_pid_by_package(const char *package_name, pid_t *out_pid)
{
    DIR *dir;
    struct dirent *entry;

    if (!package_name || !out_pid) return -EINVAL;

    dir = opendir("/proc");
    if (!dir) return -errno;

    while ((entry = readdir(dir)) != NULL)
    {
        char path[128];
        char cmdline[512];
        int fd;
        ssize_t nread;
        pid_t pid;

        if (entry->d_type != DT_DIR) continue;
        pid = (pid_t)strtol(entry->d_name, NULL, 10);
        if (pid <= 0) continue;

        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;

        nread = read(fd, cmdline, sizeof(cmdline) - 1);
        close(fd);
        if (nread <= 0) continue;

        cmdline[nread] = '\0';
        if (strcmp(cmdline, package_name) == 0)
        {
            *out_pid = pid;
            closedir(dir);
            return 0;
        }
    }

    closedir(dir);
    return -ESRCH;
}

static inline int lsdriver_map_request(lsdriver_t *drv)
{
    void *mapped;

    if (!drv) return -EINVAL;

    mapped = mmap(LSDRIVER_REQ_ADDR,
                  sizeof(lsdriver_request_obj_t),
                  PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED_NOREPLACE,
                  -1,
                  0);
    if (mapped == MAP_FAILED) return -errno;

    memset(mapped, 0, sizeof(lsdriver_request_obj_t));
    drv->req = (lsdriver_request_obj_t *)mapped;
    return 0;
}

static inline int lsdriver_wait_ready(lsdriver_t *drv, uint32_t timeout_ms)
{
    uint64_t deadline;

    if (!drv || !drv->req) return -EINVAL;

    deadline = lsdriver_now_ms() + timeout_ms;
    while (lsdriver_now_ms() < deadline)
    {
        if (__atomic_load_n(&drv->req->user, __ATOMIC_ACQUIRE))
        {
            __atomic_store_n(&drv->req->user, false, __ATOMIC_RELEASE);
            return 0;
        }
        usleep(1000);
    }

    return -ETIMEDOUT;
}

static inline int lsdriver_init(lsdriver_t *drv, uint32_t timeout_ms)
{
    int status;

    if (!drv) return -EINVAL;
    memset(drv, 0, sizeof(*drv));

    status = lsdriver_set_name();
    if (status < 0) return -errno;

    status = lsdriver_map_request(drv);
    if (status < 0) return status;

    return lsdriver_wait_ready(drv, timeout_ms);
}

static inline void lsdriver_close(lsdriver_t *drv)
{
    if (!drv || !drv->req) return;
    munmap((void *)drv->req, sizeof(lsdriver_request_obj_t));
    drv->req = NULL;
}

static inline int lsdriver_commit(lsdriver_t *drv)
{
    if (!drv || !drv->req) return -EINVAL;

    __atomic_store_n(&drv->req->kernel, true, __ATOMIC_RELEASE);

    for (;;)
    {
        if (__atomic_load_n(&drv->req->user, __ATOMIC_ACQUIRE))
        {
            int status = drv->req->status;
            __atomic_store_n(&drv->req->user, false, __ATOMIC_RELEASE);
            return status;
        }
        usleep(50);
    }
}

static inline int lsdriver_read(lsdriver_t *drv, pid_t pid, uint64_t address, void *buffer, size_t size)
{
    size_t done = 0;

    if (!drv || !drv->req || !buffer) return -EINVAL;

    while (done < size)
    {
        int status;
        size_t chunk = size - done;

        if (chunk > sizeof(drv->req->vmemrw_info.user_buffer)) chunk = sizeof(drv->req->vmemrw_info.user_buffer);

        drv->req->tgid = pid;
        drv->req->vmemrw_info.rw_addr = address + done;
        drv->req->vmemrw_info.size = (int)chunk;
        drv->req->op = LSD_OP_VMEM_READ;
        status = lsdriver_commit(drv);
        if (status < 0) return status;

        memcpy((uint8_t *)buffer + done, drv->req->vmemrw_info.user_buffer, chunk);
        done += chunk;
    }

    return 0;
}

static inline int lsdriver_write(lsdriver_t *drv, pid_t pid, uint64_t address, const void *buffer, size_t size)
{
    size_t done = 0;

    if (!drv || !drv->req || !buffer) return -EINVAL;

    while (done < size)
    {
        int status;
        size_t chunk = size - done;

        if (chunk > sizeof(drv->req->vmemrw_info.user_buffer)) chunk = sizeof(drv->req->vmemrw_info.user_buffer);

        memcpy(drv->req->vmemrw_info.user_buffer, (const uint8_t *)buffer + done, chunk);
        drv->req->tgid = pid;
        drv->req->vmemrw_info.rw_addr = address + done;
        drv->req->vmemrw_info.size = (int)chunk;
        drv->req->op = LSD_OP_VMEM_WRITE;
        status = lsdriver_commit(drv);
        if (status < 0) return status;

        done += chunk;
    }

    return 0;
}

static inline int lsdriver_query_memory(lsdriver_t *drv, pid_t pid)
{
    if (!drv || !drv->req) return -EINVAL;

    drv->req->tgid = pid;
    drv->req->op = LSD_OP_VMEM_INFO;
    return lsdriver_commit(drv);
}

static inline int lsdriver_install_shadow_hook(lsdriver_t *drv,
                                               pid_t pid,
                                               uint64_t hook_addr,
                                               uint64_t field_offset,
                                               const char *hook_name)
{
    if (!drv || !drv->req || !hook_addr) return -EINVAL;

    memset(&drv->req->shadow_hook_info, 0, sizeof(drv->req->shadow_hook_info));
    drv->req->tgid = pid;
    drv->req->shadow_hook_info.hook_addr = hook_addr;
    drv->req->shadow_hook_info.field_offset = field_offset;
    if (hook_name && hook_name[0])
    {
        strncpy(drv->req->shadow_hook_info.hook_name,
                hook_name,
                sizeof(drv->req->shadow_hook_info.hook_name) - 1);
    }
    drv->req->op = LSD_OP_SHADOW_HOOK_ADD;
    return lsdriver_commit(drv);
}

static inline int lsdriver_remove_shadow_hook(lsdriver_t *drv, pid_t pid, uint64_t hook_addr)
{
    if (!drv || !drv->req || !hook_addr) return -EINVAL;

    memset(&drv->req->shadow_hook_info, 0, sizeof(drv->req->shadow_hook_info));
    drv->req->tgid = pid;
    drv->req->shadow_hook_info.hook_addr = hook_addr;
    drv->req->op = LSD_OP_SHADOW_HOOK_DEL;
    return lsdriver_commit(drv);
}

static inline int lsdriver_clear_shadow_hooks(lsdriver_t *drv, pid_t pid)
{
    if (!drv || !drv->req) return -EINVAL;

    memset(&drv->req->shadow_hook_info, 0, sizeof(drv->req->shadow_hook_info));
    drv->req->tgid = pid;
    drv->req->op = LSD_OP_SHADOW_HOOK_CLEAR;
    return lsdriver_commit(drv);
}

static inline bool lsdriver_name_ends_with(const char *value, const char *suffix)
{
    size_t value_len;
    size_t suffix_len;

    if (!value || !suffix) return false;
    value_len = strlen(value);
    suffix_len = strlen(suffix);
    if (suffix_len > value_len) return false;
    return strcmp(value + value_len - suffix_len, suffix) == 0;
}

static inline int lsdriver_find_module_segment(lsdriver_t *drv,
                                               pid_t pid,
                                               const char *module_suffix,
                                               int segment_index,
                                               uint64_t *out_start,
                                               uint64_t *out_end)
{
    int status;
    int i;
    int j;

    if (!drv || !drv->req || !module_suffix) return -EINVAL;

    status = lsdriver_query_memory(drv, pid);
    if (status < 0) return status;

    for (i = 0; i < drv->req->vmem_info.module_count; ++i)
    {
        lsdriver_module_info_t *mod = &drv->req->vmem_info.modules[i];
        if (!lsdriver_name_ends_with(mod->name, module_suffix)) continue;

        for (j = 0; j < mod->seg_count; ++j)
        {
            lsdriver_segment_info_t *seg = &mod->segs[j];
            if (seg->index != segment_index) continue;
            if (out_start) *out_start = seg->start;
            if (out_end) *out_end = seg->end;
            return 0;
        }

        if (segment_index == 0 && mod->seg_count > 0)
        {
            if (out_start) *out_start = mod->segs[0].start;
            if (out_end) *out_end = mod->segs[0].end;
            return 0;
        }
    }

    return -ENOENT;
}

static inline int lsdriver_read_i32(lsdriver_t *drv, pid_t pid, uint64_t address, int32_t *out_value)
{
    return lsdriver_read(drv, pid, address, out_value, sizeof(*out_value));
}
