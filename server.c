//~ #include <stdio.h>
//~ #include <sys/file.h>
//~ #include <string.h>
//~ #include <stdlib.h>
//~ #include <sys/ioctl.h>
//~ #include <mysql/errmsg.h>
//~ #include <semaphore.h>
//~ #include <pthread.h>
//~ #include <regex.h>
//~ #include <pcre.h>
//~ #include <magic.h> // memory leak, upload whole file to memory to get the magic without freeing it

//~ #include <sys/sendfile.h>
//~ int opened_fd = open(req, O_RDONLY);
//~ sendfile(client_fd, opened_fd, 0, 256);


#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include <sys/poll.h>
#include <sys/epoll.h>
//~ #include <mysql/mysql.h>
#include <threads.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <time.h>

#include "http_define.c"
#include "http_func.c"
#include "http_app.c"


int main(int argc, char const *argv[]) {
	
	struct epoll_event ev, events[MAX_EPOLL_EVENTS];
	struct H2_connection *conn_role;
    //~ struct H2_Frame *frm;
	signal(SIGPIPE, SIG_IGN);
    proc_id = getpid();
    int n, i;
    client_accepted=0;
    conn_sock = ip_socket_listen(8080);
    ux_sock = ux_socket_listen(proc_id);
    
    for (i = 0; i < max_open_files; i++)
	{
		conn_list[i] = NULL;
	}
        
	sslctx_init();
	H2_huff_table_init();
	magic_table_init();
	headers_path_table_init();
    //~ init_regex();
	
	mtx_init(&new_conn_mutex, 0);
	mtx_init(&conn_role_mutex, 0);
	mtx_init(&client_accepted_mutex, 0);
	
	mtx_lock(&conn_role_mutex);
	
	thrd_t t[thread_pool_num];
	for (i = 0; i < thread_pool_num; i++)
	{
		thrd_create(&t[i], &H2_thread, 0);
	}
	
	printf("Server running at https://localhost:8080/ ___ conn_sock is: %d ___ pid=%d\n", conn_sock, proc_id);
	
	epollfd = epoll_create1(0);
	if (epollfd == -1) {
	   perror("epoll_create1");
	   exit(EXIT_FAILURE);
	}
	
	ev.events = EPOLLIN|EPOLLET;
	ev.data.fd = conn_sock;
	//~ ev.data.ptr = malloc(sizeof(struct H2_connection));
	//~ ((struct H2_connection*)ev.data.ptr)->fd = conn_sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock, &ev) == -1) {
	   perror("epoll_ctl: stdin");
	   exit(EXIT_FAILURE);
	}
	
	ev.events = EPOLLIN|EPOLLET;
	ev.data.fd = ux_sock;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ux_sock, &ev) == -1) {
	   perror("epoll_ctl: stdin");
	   exit(EXIT_FAILURE);
	}
	
	//~ struct fd f = fdget(conn_sock);
	//~ printf("FREE the connection %d\n", conn_role->fd);
	
	//~ writeUxSocket(pid, "hello_hello",11);
	while((nfds = epoll_wait(epollfd, events, MAX_EPOLL_EVENTS, -1))) {
		for (n = 0; n < nfds; ++n) {
			if (events[n].events|EPOLLIN) {
				//~ sleep(10000);
				//~ i = ((struct H2_connection*)events[n].data.ptr)->fd;
				i = events[n].data.fd;
				if (i == ux_sock || i == conn_sock) {
					
					i = accept(events[n].data.fd, NULL, NULL);
					
					if (i == -1) {
						perror("accept");
						continue;
					}
					
					printf("connection %d\n", i);
					
					mtx_lock(&client_accepted_mutex);
					client_accepted++;
					mtx_unlock(&client_accepted_mutex);
					
					conn_role = H2_connection_init(i);
					
					if (events[n].data.fd == conn_sock && !H2_createSSL(conn_role)) // 10 ms
					{
						H2_free_connection(conn_role);
						continue;
					}
					
					conn_list[conn_role->fd] = conn_role;
					
					ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
					//~ ev.data.ptr = conn_role;
					ev.data.fd = conn_role->fd;
					
					if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_role->fd, &ev) == -1) {
						perror("epoll_ctl: conn_sock");
						//~ exit(EXIT_FAILURE);
					}
					
					if (client_accepted>max_client_accepted && conn_sock!=-1 && events[n].data.fd == conn_sock) {
						close(events[n].data.fd);
						conn_sock=-1;
					}
					
				} else {
					
					if (!mtx_lock(&new_conn_mutex))
					{
						//~ conn_role = ((struct H2_connection*)events[n].data.ptr);
						thread_conn_role = conn_list[i];
						mtx_unlock(&conn_role_mutex);
					}
				}
			} else {
				printf("FREE the connection %d\n", conn_role->fd);
			}
		}
	}
	
	perror("epoll_wait");
	printf("exit exit exit exit\n");
    exit(EXIT_FAILURE);
    
	//~ exit(0);
    return 0;
}





