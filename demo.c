#include "lsdriver.h"

#define TARGET_PACKAGE "com.tencent.tmgp.sgame"
#define TARGET_DLL_SUFFIX "Scripts.GameCore.dll"
#define HOOK_NAME "CSkillButtonManager.PunishDamage"
#define CSkillButtonManager_PunishDamage_Offset 0x244ULL

static lsdriver_t g_drv;
static pid_t g_pid = 0;
static uint64_t g_hook_addr = 0;

static void print_module_hint(lsdriver_t *drv, pid_t pid)
{
    uint64_t start = 0;
    uint64_t end = 0;
    int status;

    status = lsdriver_find_module_segment(drv, pid, TARGET_DLL_SUFFIX, 0, &start, &end);
    if (status == 0)
    {
        printf("[+] %s seg0: 0x%llx - 0x%llx\n",
               TARGET_DLL_SUFFIX,
               (unsigned long long)start,
               (unsigned long long)end);
    }
    else
    {
        printf("[-] module not found: %s (status=%d)\n", TARGET_DLL_SUFFIX, status);
    }
}

static void cleanup(void)
{
    if (g_drv.req && g_pid > 0 && g_hook_addr != 0)
    {
        lsdriver_remove_shadow_hook(&g_drv, g_pid, g_hook_addr);
        g_hook_addr = 0;
    }
    lsdriver_close(&g_drv);
}

static void on_signal(int signo)
{
    (void)signo;
    cleanup();
    _exit(0);
}

int main(int argc, char **argv)
{
    int status;

    if (argc < 2)
    {
        printf("usage: %s <hook_addr_hex>\n", argv[0]);
        printf("example: %s 0x1234567890\n", argv[0]);
        printf("\n");
        printf("说明:\n");
        printf("  1. hook_addr 必须是目标函数入口地址，且该函数的 this 指针在 x0。\n");
        printf("  2. 安装后驱动会在每次命中时打印 this + 0x244 的 Int32 值。\n");
        printf("  3. 目标 Dll: %s\n", TARGET_DLL_SUFFIX);
        return 0;
    }

    g_hook_addr = strtoull(argv[1], NULL, 16);
    if (g_hook_addr == 0)
    {
        fprintf(stderr, "[-] invalid hook address: %s\n", argv[1]);
        return 1;
    }

    status = lsdriver_find_pid_by_package(TARGET_PACKAGE, &g_pid);
    if (status < 0)
    {
        fprintf(stderr, "[-] find pid failed for %s, status=%d\n", TARGET_PACKAGE, status);
        return 1;
    }

    printf("[+] %s pid = %d\n", TARGET_PACKAGE, g_pid);

    status = lsdriver_init(&g_drv, 10000);
    if (status < 0)
    {
        fprintf(stderr, "[-] lsdriver init failed, status=%d\n", status);
        return 1;
    }

    print_module_hint(&g_drv, g_pid);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    status = lsdriver_install_shadow_hook(&g_drv,
                                          g_pid,
                                          g_hook_addr,
                                          CSkillButtonManager_PunishDamage_Offset,
                                          HOOK_NAME);
    if (status < 0)
    {
        fprintf(stderr, "[-] install shadow hook failed, status=%d\n", status);
        cleanup();
        return 1;
    }

    printf("[+] shadow hook installed at 0x%llx\n", (unsigned long long)g_hook_addr);
    printf("[+] wait for target function hits, then check kernel log for %s\n", HOOK_NAME);
    printf("[+] press Ctrl+C to remove hook and exit\n");

    for (;;)
    {
        pause();
    }
}
