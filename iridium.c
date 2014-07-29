#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <pthread.h>

#include "queue.h"
#include "network.h"
#include "debug.h"
#include "serial.h"
#include "route_engine.h"
#include "iridium.h"

#define SEQUENTIAL_NUM 0
#define CONFIG_PATH "9602.cfg"

#define FALSE 0
#define TRUE 1
#define SBDOUTPUTMAX 1960
#define SLICE_LEN 100
#define SBDWTMIN 1
#define NO_MT_MSG 0
#define HAS_MT_MSG 1
#define GET_MT_MSG_ERROR 2
#define RETRY_INTERVAL 3

const char *key = "bupt632";

struct iridium9602
{

    int baudrate;
    int serial_descriptor;
    char modem_path[20];
};

//convenient way of holding SBDIX return variables
struct sbdix_return
{
    int MOSTATUS;
    int MOMSN;
    int MTSTATUS;
    int MTMSN;     
    int MTLENGTH;
    int MTQUEUED;
} my_sbdi;

typedef struct
{
    char magic_code[8];
    int sn;
    unsigned long ip;
    int port;
    int index;
    int has_more;
    char msg[];
} slice;

//static const int PAYLOAD_LEN = SLICE_LEN - sizeof(slice);

#define PAYLOAD_LEN (SLICE_LEN - sizeof(slice))
/**
  Function Prototypes for 9602
  more to be listed as part of cleanup.
 **/
int init9602(const char *path, struct iridium9602 *my9602, int maxModems);
int init_serial_port(char *modem_path, int baud);  /* Initiates the serial port for the 9602 */
int init_sbdix_return();
int init_file_server();
int init_iridium_service(int* serial_port_fd);
int init_queue();
int send_at_command(int fd, const char *message, const char *return_cde);
int print_structs(struct iridium9602 *my9602, int max_modems);

int query_reg_status(int fd);
int reg_an_service(int fd);//automatic notification

void confirm_sig_level(int fd);
int parse_csq(char *output);
int parse_sbdreg(char *output);
void parse_sbdix(char *output, struct sbdix_return *my_sbdi);
int parse_sbdrt(char *output);

int send_mo_message(int fd, char* msg, int length, const char *return_code);
int check_mo_status(struct sbdix_return *my_sbdi);
int check_mt_message();
int get_mt_message (int fd);
int clear_mo_mt_buffer(int fd);

int read_from_file(const char *filename, unsigned long* ip_addr, int* port, char* msg);
void send_after_split(int fd, unsigned long ip_addr, int port, const char *msg_recv);
int send_to_iridium(int fd, char *msg, int length);
int recv_from_iridium(int fd);

static void start_service(void *arg);
int cache_in_queue(char* filename);

void* thread_func(void* arg);

char file_server_path[BUFSIZ];
char main_control_path[BUFSIZ];
char udp_server_ip[BUFSIZ];
int udp_server_port;
char output[SBDOUTPUTMAX] =    {0};
int verboseon = 1;
int serial_port_fd;

/**
  start of functions for 9602 program

 **/

/**
 * [Helper function for debug]
 * @param  my9602    [iridium9602 structure]
 * @param  max_modems [max number of the iridium model]
 * @return           [0 on success]
 */
int print_structs(struct iridium9602 *my9602, int max_modems)
{
    int index;
    for (index = 0; index < max_modems; index++)
    {
        printf("Modem %i config:\n BAUDRATE: %i\n ", index + 1, my9602[index].baudrate);
        printf("serial_descriptor: %i\n\n", my9602[index].serial_descriptor);
    }
    return 0;
}

/**
 * [Initialize the iridium9602 structure,get specific value from the configuration file]
 * @param  path      [where the configuration file exits]
 * @param  my9602    [iridium9602 structure]
 * @param  max_modems [max number of the iridium model]
 * @return           [0 on success, -1 on failure]
 */
int init9602(const char *path, struct iridium9602 *my9602, int max_modems)
{
    FILE *file;
    int rv;
    int digit_value;
    int modem_count;
    char index[100] = {0};
    char value[100] = {0};
    struct iridium9602 *ptr;
    file = fopen(path, "r");
    modem_count = -1; //should be read from config file

    while ((rv = fscanf(file, "%s %s", index, value)) > 0)
    {
        if (!(strcmp(index, "MODEMPATH"))) {
            modem_count = modem_count + 1;
            ptr = &my9602[modem_count];
            sprintf(ptr->modem_path, "%s", value);
        } else if (!(strcmp(index, "BAUDRATE"))) {
            digit_value = atoi(value);
            ptr->baudrate = digit_value;
        } else if (!(strcmp(index, "FILE_SERVER_PATH"))) {
            memset(file_server_path, 0, BUFSIZ);
            strcpy(file_server_path, value);
        } else if (!(strcmp(index, "MAIN_CONTROL_PATH"))) {
            memset(main_control_path, 0, BUFSIZ);
            strcpy(main_control_path, value);
        } else if (!(strcmp(index, "UDP_SERVER_IP"))) {
            memset(udp_server_ip, 0, BUFSIZ);
            strcpy(udp_server_ip, value);
        } else if (!(strcmp(index, "UDP_SERVER_PORT"))) {
            sscanf(value, "%d", &udp_server_port);
        }
    }
    fclose(file);

    ptr->serial_descriptor = init_serial_port(ptr->modem_path, ptr->baudrate);
    assert(ptr->serial_descriptor > 0);

    return 0;
}


/**
 * [Init the SBDIX return value structure]
 * @return [0 on success]
 */
int init_sbdix_return()
{
    my_sbdi.MOSTATUS = -1;
    my_sbdi.MOMSN = -1;
    my_sbdi.MTSTATUS = -1;
    my_sbdi.MTMSN = -1;
    my_sbdi.MTLENGTH = -1;
    my_sbdi.MTQUEUED = -1;
    return 0;
}

/**
 * [Parse the return value of the command AT+SBDRT]
 * @param  output [return value]
 * @return        [-1 on failure or bytes send]
 */
int parse_sbdrt(char *output)
{
    char *token;
    int nsend = -1;

#ifdef DEBUG
    printf("parse_sbdrt:%s\n", output);
#endif 

    token = strtok(output, ":");
    token = strtok(NULL, "\n");

#ifdef DEBUG
    printf("Token: %s\n", token);
#endif 

    nsend = send_to_udp_server(udp_server_ip, udp_server_port, token);

    return nsend;
}

/**
 * [Parse the return value of command AT+SBDIX]
 * @param  output [return value]
 * @param  my_sbdi [my SBDI structure]
 */
void parse_sbdix(char *output, struct sbdix_return *my_sbdi)
{
    char *token;
    token = strtok(output, ": ");
    token = strtok(NULL, ", ");
    my_sbdi->MOSTATUS = atoi(token);
    token = strtok(NULL, ", ");
    my_sbdi->MOMSN = atoi(token);
    token = strtok(NULL, ", ");
    my_sbdi->MTSTATUS = atoi(token);
    token = strtok(NULL, ", ");
    my_sbdi->MTMSN = atoi(token);
    token = strtok(NULL, ", ");
    my_sbdi->MTLENGTH = atoi(token);
    token = strtok(NULL, "\n");
    my_sbdi->MTQUEUED = atoi(token);
    //basic error handling
#ifdef DEBUG
    printf("SBDIX Return: +SBDIX: %i, %i, %i, %i, %i, %i\n",
            my_sbdi->MOSTATUS, my_sbdi->MOMSN, my_sbdi->MTSTATUS, 
            my_sbdi->MTMSN, my_sbdi->MTLENGTH, my_sbdi->MTQUEUED);
#endif
}


/**
 * [Check MO message status]
 * @return [0:on success,-1:failed]
 */
int check_mo_status(struct sbdix_return *my_sbdi)
{
    if (my_sbdi->MOSTATUS == 0)
    {
        //complete success
        return 0;
    }
    else if (1 <= my_sbdi->MOSTATUS && my_sbdi->MOSTATUS <= 4)
    {
        //sucess for MO but not for other aspects of SBDIX
        //handle said aspects, if applicable
        return 0;
    }
    else
    {
        return -1;
    }
}

/**
 * [parse_csq parse the result of AT+CSQ]
 * @param  output [results of the execution of the AT command]
 * @return        [signal strength]
 */
int parse_csq(char *output)
{
    int sig = 0;
    if ((strstr(output, "+CSQ:")) != NULL)
    {

        char *token = strtok(output, ":");

        token = strtok(NULL, "\n");
        sig = atoi(token);
    }

    return sig;
}

/**
 * [parse_sbdreg parse the result of AT+SBDREG?]
 * @param  output [description]
 * @return        [0: not registered, 1:process failed,should be retried further,2:registered]
 */
int parse_sbdreg(char *output)
{

    int rv = 0;
    if ((strstr(output, "+SBDREG:")) != NULL)
    {

        char *token = strtok(output, ":");
        token = strtok(NULL, "\n");
        rv = atoi(token);
    }

    return rv;
}



/**
 * [Serial port configuration]
 * @param  modem_path [specific which serial port to use]
 * @param  baud      [specific what baud rate to use]
 * @return           [serial port descriptor we get or -1 if failed]
 */
int init_serial_port(char *modem_path, int baud)
{

    int fd = open_port(modem_path);

    if(set_com_config(fd, baud, 8, 'N', 1) < 0)
    {
        perror("set_com_config");
        return -1;
    }  

    return fd; 
}




/**
 * [confirm_sig_level:confirm weather the signal is enough to send AT commands]
 * @param  fd [serial port descriptor]
 * @return    [-1:error occured,0:enough, 1: poor signal]
 */
void confirm_sig_level(int fd)
{
    int rv = -1;

    while (rv != 0)
    {
        while ((rv = send_at_command(fd, "AT+CSQ\r", "OK")) != 0)
        {
            sleep(3);
        }
        if (parse_csq(output) >= 3)
        {
            rv = 0;
            return;
        }
        sleep(3);
    }
}

/**
 * [Send AT command to iridium gss]
 * @param  fd         [serial descriptor]
 * @param  message    [AT command]
 * @param  return_code [expected return value]
 * @return            [0 on success,-1 on failure]
 */
int send_at_command(int fd, const char *message, const char *return_code)
{

#ifdef DEBUG
    printf("send at command ,message = %s\n", message);
#endif

    memset(output, 0, SBDOUTPUTMAX);
    int res;
    char buf[255] = {0};
    write(fd, message, strlen(message));
    while (1)
    {
        res = read(fd, buf, 255);
        buf[res] = '\0';
        strcat(output, buf);

        if ((strstr(output, return_code) != NULL))
        {
            break;
        }

        else if ((strstr(output, "ERROR") != NULL))
        {
            printf("ERROR with command:%s\n", message);
            return -1;
        }
    }
    return 0;
}
/**
 * [query_reg_status query whether the iridium module register the antomatic notification service]
 * @param  fd [serial port descriptor]
 * @return    [0:successfully register, 1:not register]
 */
int query_reg_status(int fd)
{
    int rv;
    rv = send_at_command(fd, "AT+SBDREG?\r", "OK");
    if (rv == 0)
    {
        rv = parse_sbdreg(output);
    }

    if (rv == 2)
    {
#ifdef DEBUG
        printf("already registered\n");
#endif 

        return 0;
    } else {

#ifdef DEBUG
        printf("doesnt register\n");
#endif 

        return 1;
    }
}
/**
 * [reg_an_service: register the antomatic notification service for MT messages]
 * @param  fd [serial port descriptpr]
 * @return    [0:successfully register the service]
 */
int reg_an_service(int fd)
{
    int rv1 = -1;
    int rv2 = -1;

    rv1 = query_reg_status(fd);
    if (rv1 == 0)
        return 0;
    else {
        while (send_at_command(fd, "AT+SBDMTA=1\r", "OK") != 0)
        {
            sleep(RETRY_INTERVAL);
        }
        while (rv2 != 0)
        {
            confirm_sig_level(fd);
            send_at_command(fd, "AT+SBDREG\r", "OK");
            rv2 = query_reg_status(fd);
        }
    }

    return 0;
}

/**
 * [Check whether the gss has MT messages queued for receiving]
 * @return    [0:no messages,1:messages queued,2:error occured]
 */
int check_mt_message()
{
    if (my_sbdi.MTSTATUS == NO_MT_MSG)
        return 0;
    else if (my_sbdi.MTSTATUS == HAS_MT_MSG)
    {
        return 1;
    }
    else
        return 2;

}

/**
 * [Get messages queued at gss]
 * @param  fd [Serial port number]
 * @return    [0 on success]
 */
int get_mt_message (int fd)
{
    int index;
    int rv;

#ifdef DEBUG
    printf("One message Downloaded.\n Messages waiting: %i \n", my_sbdi.MTQUEUED);
#endif

    //reading of MT messages at gateway
    rv = send_at_command(fd, "AT+SBDRT\r", "OK");
    parse_sbdrt(output);

    rv = clear_mo_mt_buffer(fd);

    if (rv == -1)
    {

        printf("Failed to clear mo mt message buffer\n");

        return -1;
    }

    for (index = 1; index <= my_sbdi.MTQUEUED; index++)
    {
#ifdef DEBUG
        printf("Retrieving messages from gateway.\n");
#endif

        while (1)
        {
            send_at_command(fd, "AT+SBDIXA\r", "OK");
            if (check_mt_message() != GET_MT_MSG_ERROR)
                break;
            sleep(RETRY_INTERVAL);
        }

#ifdef DEBUG
        printf("AT+SBIX return_code: %s\n", output);
#endif

        /**
          There is a MAX number of messages that may be
          QUEUED. Retrieve messages if available and send to
          destination/port in config file.
         **/
        rv = send_at_command(fd, "AT+SBDRT\r", "OK");
        parse_sbdrt(output);
    }

    return rv;
}

/**
 * [Clear both MO and MT message buffer]
 * @param  fd [Serial port number]
 * @return    [0:on success, -1:failed]
 */
int clear_mo_mt_buffer(int fd)
{
    int rv;
    rv = send_at_command(fd, "AT+SBDD2\r", "OK");

#ifdef DEBUG
    printf("AT+SBDD2 return_code: %s\n", output);
#endif

    return rv;
}


/**
 * @TODO seperate msg_len and message
 * @brief [read specific varibles from file]
 * @details read the dst ip, dst port and data from the file
 * 
 * @param filename name of the file to be read
 * @param ip_addr dst ip address    
 * @param port dst port num
 * @param msg_recv data to send
 * @return 0 on success or -1 on failure
 */
int read_from_file(const char *filename, unsigned long *ip_addr, int *port, 
        char *msg_recv)
{

    int msg_len = 0;
    int nread = 0;
    FILE* fp = NULL;
    int rv;
printf("read from file\n");
    if ((fp = fopen(filename, "rb")) == NULL) {
        perror("fopen");
        return -1;
    }

    if ((rv = fscanf(fp, "%lu%d%d", ip_addr, port, &msg_len)) == 3) {

        memset(msg_recv, 0, SBDOUTPUTMAX);
        nread = fread(msg_recv, sizeof(char), msg_len, fp);
        msg_recv[nread] = '\0';

#ifdef DEBUG
        printf("ip = %lu , port = %d msg_len = %d, msg = %s\n", *ip_addr, *port, msg_len, msg_recv);
#endif 
        fclose(fp);
#ifndef DEBUG
        unlink(filename);
#endif

    } else {

        return -1;
    }
    return 0;
}

/**
 * Split the msg read from the file into small pieces and
 * send them to the iridium gateway
 * @param fd       [serial descriptor]
 * @param msg_recv [msg read from the file]
 */
void send_after_split(int fd, unsigned long ip_addr, int port, const char *msg_recv) {

    int index = 0;
    int count = 0;

    slice* m_slice = NULL;
    m_slice = (slice*)malloc(SLICE_LEN);
    if (m_slice == NULL) {
        perror("failed to create m_msg"); 
        return;
    }

    char temp_msg[SBDOUTPUTMAX];
    memset(temp_msg, 0, SBDOUTPUTMAX);
    if (strlen(msg_recv) % PAYLOAD_LEN == 0) 
        count = strlen(msg_recv) / (PAYLOAD_LEN);
    else
        count = strlen(msg_recv) / (PAYLOAD_LEN) + 1;

#ifdef DEBUG
    printf("count = %d\n", count);
#endif 

    for (index = 0; index < count; index++) {
        
        strcpy(m_slice->magic_code, key);
        m_slice->sn = SEQUENTIAL_NUM;
        m_slice->ip = ip_addr;
        m_slice->port = port;
        m_slice->index = index;

        if (index != count-1)
            m_slice->has_more = 1;
        else
            m_slice->has_more = 0;
        memcpy(m_slice->msg, msg_recv + index*PAYLOAD_LEN, PAYLOAD_LEN);
        printf("index = %d,PAYLOAD_LEN = %d, index*PAYLOAD_LEN = %d\n", 
                index, PAYLOAD_LEN, index*PAYLOAD_LEN);
        memcpy(temp_msg, msg_recv + index*PAYLOAD_LEN, PAYLOAD_LEN);

#ifdef DEBUG
        printf("sn = %d ip = %lu, port = %d, msg slice %d, has_more = %d, msg = %s\n", 
                m_slice->sn, m_slice->ip, m_slice->port, m_slice->index,  m_slice->has_more, temp_msg);
#endif 

        send_to_iridium(fd, (char*)m_slice, SLICE_LEN);
    }
    free(m_slice);

}

/**
 * @brief [brief description]
 * @details [long description]
 * 
 * @param fd [description]
 * @param msg [description]
 * @param length [description]
 * @param return_code [description]
 * @param X [description]
 * @return [description]
 */
int send_mo_message(int fd, char* msg, int length, const char *return_code)
{

    memset(output, 0, SBDOUTPUTMAX);
    int res;
    int i;
    uint16_t checksum = 0;
    char buf[255] = {0};
    uint8_t fb;
    uint8_t sb;
    for (i = 0; i < length; i++) {
        checksum += (uint8_t)msg[i];
    }

    write(fd, msg, length);
    fb = checksum >> 8;
    sb = checksum & 0xFF;

#ifdef DEBUG
    printf("checksum = %2x, fb = %x, sb = %x\n", checksum, fb, sb);
#endif 

    write(fd, &fb, 1);
    write(fd, &sb, 1);

    while (1)
    {
        res = read(fd, buf, 255);
        buf[res] = '\0';
        strcat(output, buf);

        if ((strstr(output, return_code) != NULL))
        {
            break;
        }

        else if ((strstr(output, "ERROR") != NULL))
        {

            printf("ERROR with command\n");
            return -1;
        }
    }
    return 0;
}
/**
 * [Send message to iridium gss]
 * @param  fd  [serial descriptor]
 * @param  msg [string message]
 * @return     [0 on success]
 */
int send_to_iridium(int fd, char *msg, int length)
{

    int rv;
    char sbdwb[BUFSIZ];
    sprintf(sbdwb, "%s=%d\r", "AT+SBDWB", length);
    rv = send_at_command(fd, sbdwb, "READY");

#ifdef DEBUG
    printf("AT+SBDWT return_code: %s\n", output);
#endif

    //do stuff with return code...i.e. retry

    rv = send_mo_message(fd, msg, length, "OK");

#ifdef DEBUG
    printf("MESSAGE LOADING return_code: %s\n", output);
#endif

    //Ensure that the AT+SBDIXA command was sent successfully
    while (1)
    {

        rv = send_at_command(fd, "AT+SBDIX\r", "OK");
        parse_sbdix(output, &my_sbdi);

#ifdef DEBUG
        printf("AT+SBDI return_code: %s\n", output);
#endif    

        if (check_mo_status(&my_sbdi) == 0)
            break;
        sleep(RETRY_INTERVAL);
    }



    rv = check_mt_message();
    if (rv == HAS_MT_MSG)
    {
        rv = get_mt_message(fd);
    }
    else if (rv == GET_MT_MSG_ERROR)
    {

        printf("Failed to recv from gss\n");
        return -1;
    }
    return rv;
}


/**
 * [retrive message from the iridium gss]
 * @param  fd [serial descriptor]
 * @return    [0 on success]
 */
int recv_from_iridium(int fd)
{
    int rv;


    rv = send_at_command(fd, "AT+SBDIXA\r", "OK");
    parse_sbdix(output, &my_sbdi);

#ifdef DEBUG
    printf("AT+SBDI return_code: %s\n", output);
#endif

    if (check_mt_message() == HAS_MT_MSG)
    {
        rv = get_mt_message(fd);
    }

    return rv;
}

/**
 * Initialize the filename udp server
 * @return [specific file descriptor or -1 on failure]
 */
int init_file_server() 
{
    int file_service_fd;

    file_service_fd = create_unix_server(file_server_path);

    return file_service_fd;
}

/**
 * Initialize specific resources for the iridium service
 * @param  serial_port_fd  [serial port file descriptor]
 * @param  file_service_fd [socket file descriptor which provides files containing ip datagrams ]
 * @return                 [0 on success, or -1]
 */
int init_iridium_service(int* serial_port_fd)
{
    int fd, rv;
    struct iridium9602 my9602[1];
    struct iridium9602 *ptr; //reference to my9602
    ptr = &my9602[0];
    rv = init9602(CONFIG_PATH, my9602, 1);
    if (rv == -1)
        return -1;

#ifdef DEBUG
    print_structs(my9602, 1);
#endif

    init_sbdix_return();

    fd = ptr->serial_descriptor;
    //reg_an_service(fd);

    *serial_port_fd = fd;

    return 0;
}

/**
 * [Start the iridium service]
 * @param fd [serial descriptor]
 */
static void start_service(void *arg)
{
    int max_fd;
    int nread = 0;
    int finish = 0;
    unsigned long ip_addr;
    int port;
    int rv;
    int flags;
    fd_set readfds;
    fd_set testfds;

    char iridium_buf[SBDOUTPUTMAX];
    char filename[FILENAME_MAX];
    char pipe_buf[1];
    char msg_recv[SBDOUTPUTMAX];

    sate_info *sate_arg = (sate_info*)arg;
    int pipe_read_fd = sate_arg->pipe_fds[0];
    queue *m_queue = sate_arg->req_queue;
    FD_ZERO(&readfds);
    FD_SET(serial_port_fd, &readfds);
    FD_SET(pipe_read_fd, &readfds);


    flags = fcntl(pipe_read_fd, F_GETFL, 0);
    fcntl(pipe_read_fd, F_SETFL, flags | O_NONBLOCK);

    max_fd = serial_port_fd > pipe_read_fd ? serial_port_fd : pipe_read_fd;

    while (1)
    {

        testfds = readfds;
        finish = 0;
        rv = select(max_fd + 1, &testfds, (fd_set *)NULL, (fd_set *)NULL, (struct timeval *)NULL);
        switch (rv)
        {

            case -1:
                perror("select");
                break;
            default:

                if (FD_ISSET(serial_port_fd, &testfds)) {
                    nread = read(serial_port_fd, iridium_buf, SBDOUTPUTMAX);
                    if (nread > 0) {
                        iridium_buf[nread] = '\0';

#ifdef DEBUG
                        printf("iridium buf = %s\n", iridium_buf);
#endif 

                        if (strstr(iridium_buf, "SBDRING") != NULL) {
                            recv_from_iridium(serial_port_fd);
                        }
                    }
                }

                else if (FD_ISSET(pipe_read_fd, &testfds)) {
                    while ((nread = read(pipe_read_fd, pipe_buf, 1)) > 0) {

                        if (de_queue(m_queue, filename)) {

                            finish = read_from_file(filename, &ip_addr, &port, msg_recv);
                            if (finish < 0) {
                                printf("failed to read from file\n");
                                continue;
                            }

                            send_after_split(serial_port_fd, ip_addr, port, msg_recv);

                        } else {

                            printf("can not dequeue\n");
                            break;
                        }
                    }

                }
                break;
        }
    }

}



void *start_iridium_service(void *arg)
{ 
    int rv;
    printf("iridium start ....\n");

    rv = init_iridium_service(&serial_port_fd);
    if (rv == -1) {
        perror("Cant not initialize iridium service");
        exit(EXIT_FAILURE);
    }

    start_service(arg);
    return (void*)1;
}


