#ifndef SERIAL_H
#define SERIAL_H

int set_com_config(int fd,int baud_rate, 
                    int data_bits, char parity, int stop_bits);
int open_port(char *modem_path);

#endif