#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "ip6.h"
#include "nd6.h"
#include "slaac.h"

#include "driver/loopback.h"
//#include "driver/ether_pcap.h"
#include "driver/ether_tap.h"
#include "app/config.h"

static int buitin_help();
static int builtin_exit();
static int builtin_neigh();

static void shell_loop();
static char **analys_cmd(char *line);
static int execute_cmd(char **args);

static volatile sig_atomic_t terminate;

#define BUFSIZE 64

/*
 * init microps 
 */

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
    net_interrupt();
    close(0);
}

static int
setup(void)
{
    struct net_device *dev;
    struct ip6_iface *iface;
    int i = 0;

    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }

    /* loopback device */
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip6_iface_alloc(LOOPBACK_IPV6_ADDR, LOOPBACK_IPV6_PREFIXLEN, SLAAC_DISABLE);
    if (!iface) {
        errorf("ip6_iface_alloc() failure");
        return -1;
    }
    if (ip6_iface_register(dev, iface) == -1) {
        errorf("ip6_iface_register() failure");
        return -1;
    }

    /* devices */
    while (i < ETHER_DEVICES_NUM) {
        //dev = ether_pcap_init(ETHER_DEVICES_NAME[i], ETHER_DEVICES_HW_ADDR[i]);
        dev = ether_tap_init(ETHER_DEVICES_NAME[i], ETHER_DEVICES_HW_ADDR[i]);
        if (!dev) {
            errorf("ether_pcap_init() failure");
            return -1;
        }
        iface = ip6_iface_alloc(ETHER_DEVICES_IPV6_ADDR[i], ETHER_DEVICES_IPV6_PREFIXLEN[i], SLAAC_DISABLE);
        if (!iface) {
            errorf("ip6_iface_alloc() failure");
            return -1;
        }
        if (ip6_iface_register(dev, iface) == -1) {
            errorf("ip6_iface_register() failure");
            return -1;
        }
        i++;
    }
    if (ip6_route_set_default_gateway(iface, IPV6_DEFAULT_GATEWAY) == -1) {
        errorf("ip6_route_set_default_gateway() failure");
        return -1;
    }

    /* runnig */
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}


/*
 * CLI for microps
 */

static int 
buitin_help()
{
    printf("CLI for microps\n");
    return 0;
}

static int 
builtin_exit()
{
    printf("Good Bye...\n");
    terminate = 1;
    return 0;
}

static int 
builtin_neigh()
{
    nd6_cache_dump(stderr);
    return 0;
}

static int 
builtin_fib()
{
    ip6_fib_dump(stderr);
    return 0;
}

static int 
builtin_ifconfig()
{
    net_devices_dump(stderr);
    return 0;
}

static void 
shell_loop()
{
    char *line = NULL; 
    size_t len = 0;
    ssize_t nread;
    char **args;
    int status;

    signal(SIGINT, SIG_IGN);
    printf("\nHello, this is microps \n\n");

    do {
		printf("\x1b[32m# \x1b[39m");
        // 標準入力から1行読み取る
        if ( (nread = getline(&line, &len, stdin)) == -1 ) {
            printf("Failed to read line\n");
            exit(EXIT_FAILURE);
        }
        
        // コマンドを解析・実行する
        args = analys_cmd(line);
        status = execute_cmd(args);

        free(args);
    } while(status || !terminate); 
    
    free(line);
}

static char **
analys_cmd(char *line)
{
    char **cmds = malloc(BUFSIZE * sizeof(char*));
    char *cmd;
    int position = 0;

    // コマンドをスペースと改行で分解する
    cmd = strtok(line, " \n");
	while (cmd != NULL) {
        // ポインタ配列に区切り文字のポインタを格納
		cmds[position] = cmd;
        position++;
        cmd = strtok(NULL, " \n");
    }

    return cmds;
}

static int 
execute_cmd(char **args)
{
    pid_t pid;
    int status;

    // コマンド入力がない場合は無視
    if (args[0] == NULL) {
        return 1;
    }

    // ビルトインコマンドが入力された場合の処理
    if (strcmp(args[0], "exit") == 0) {
        return builtin_exit();
    } else if (strcmp(args[0], "help") == 0) {
        return buitin_help();
    } else if (strcmp(args[0], "neigh") == 0) {
        return builtin_neigh();
    } else if (strcmp(args[0], "fib") == 0) {
        return builtin_fib();
    } else if (strcmp(args[0], "ifconfig") == 0) {
        return builtin_ifconfig();
    }

    pid = fork();
    if (pid < 0) {
        printf("Error: can't fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        /* 子プロセス */
        // PATH環境変数からコマンドを実行
        printf("(execvp) %s\n", args[0]);
        if ( (execvp(args[0], args)) == -1 ) {
            printf("command not found: %s\n", args[0]);
            _exit(EXIT_FAILURE);
        } else {
            _exit(EXIT_SUCCESS);
        }
    } else {
        /* 親プロセス */
        wait(&status);
    }

    return 1;
}


int main()
{
    /*
     * Setup protocol stack
     */
    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    while (!terminate) {
        shell_loop();
    }
    /*
     * Cleanup protocol stack
     */
    net_shutdown();
    return 0;
}