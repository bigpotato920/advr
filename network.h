#ifndef NETWORK_H
#define NETWORK_H

int create_unix_server(const char* path_name);
int create_unix_client();
int connect_to_unix_server(int client_fd, const char *server_path);
int server_accept(int server_fd);
int send_to_udp_server(char *ip,  int port, const char* msg);
#endif