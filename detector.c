#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <sys/epoll.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>

#include "log.h"
#include "route_engine.h"
#define PACKET_SIZE 4096
#define MAX_EPOLL_EVENTS 1
#define MAX_PACKET_NUM 5
#define DATA_LENGTH 56
#define GW_EXPIRE_INTERVAL 60
#define MAX_RTT 5000

int sockfd;

struct sockaddr_in dest_addr;
struct sockaddr_in from;

pid_t pid;

double total_rtt[MAX_PACKET_NUM];

//两个timeval相减
void tv_sub(struct timeval *recvtime,struct timeval *sendtime)
{
    long sec = recvtime->tv_sec - sendtime->tv_sec;
    long usec = recvtime->tv_usec - sendtime->tv_usec;
    if(usec >= 0){
        recvtime->tv_sec = sec;
        recvtime->tv_usec = usec;
    }else{
        recvtime->tv_sec = sec - 1;
        recvtime->tv_usec = -usec;
    }
}

/****检验和算法****/
unsigned short cal_chksum(unsigned short *addr,int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short check_sum = 0;

    while(nleft>1)      //ICMP包头以字（2字节）为单位累加
    {
        sum += *w++;
        nleft -= 2;
    }

    if(nleft == 1)      //ICMP为奇数字节时，转换最后一个字节，继续累加
    {
        *(unsigned char *)(&check_sum) = *(unsigned char *)w;
        sum += check_sum;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    check_sum = ~sum;   //取反得到校验和
    return check_sum;
}

/*设置ICMP报头*/
int pack(int pack_no, char *sendpacket)
{
    int packsize;
    struct icmp *icmp;
    struct timeval *tval;
    icmp = (struct icmp*)sendpacket;
    icmp->icmp_type = ICMP_ECHO;    //ICMP_ECHO类型的类型号为0
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = pack_no;   //发送的数据报编号
    icmp->icmp_id = pid;

    packsize = 8 + DATA_LENGTH;     //数据报大小为64字节
    tval = (struct timeval *)icmp->icmp_data;
    gettimeofday(tval,NULL);        //记录发送时间
    //校验算法
    icmp->icmp_cksum =  cal_chksum((unsigned short *)icmp,packsize);    
    return packsize;
}


/******剥去ICMP报头******/
int unpack(char *buf,int len)
{
    int iphdrlen;       //ip头长度
    struct ip *ip;
    struct icmp *icmp;
    struct timeval *tvsend;
    double rtt;
    struct timeval tvrecv; 

    ip = (struct ip *)buf;
    iphdrlen = ip->ip_hl << 2;  //求IP报文头长度，即IP报头长度乘4
    icmp = (struct icmp *)(buf + iphdrlen); //越过IP头，指向ICMP报头
    len -= iphdrlen;    //ICMP报头及数据报的总长度
    if(len < 8)     //小于ICMP报头的长度则不合理
    {
        printf("ICMP packet\'s length is less than 8\n");
        return -1;
    }
    gettimeofday(&tvrecv, NULL);     //记录接收时间
    //确保所接收的是所发的ICMP的回应
    if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))
    {
        tvsend = (struct timeval *)icmp->icmp_data;
        tv_sub(&tvrecv,tvsend); //接收和发送的时间差
        //以毫秒为单位计算rtt
        rtt = tvrecv.tv_sec*1000 + tvrecv.tv_usec/1000;
        total_rtt[icmp->icmp_seq] = rtt;
        printf("%d bytes  icmp_seq=%u ttl=%d time=%.1f ms\n",
                len,  icmp->icmp_seq,ip->ip_ttl,rtt);
    }
    
    return -1;
}

int average_rtt()
{
    int i;
    double sum = 0.0;
    for (i = 0; i < MAX_PACKET_NUM; i++) {
        sum += total_rtt[i];
        printf("total_rtt[%d] = %lf\n", i, total_rtt[i]);
    }

    return (int)(sum / MAX_PACKET_NUM + 0.5);
}

int start_service(int sockfd, gateway_info *gw_info)
{
    int efd;
    int res;
    struct epoll_event event;
    struct epoll_event *events;
    char sendpacket[PACKET_SIZE];

    event.data.fd = sockfd;
    event.events = EPOLLIN | EPOLLET;
    efd = epoll_create(1);
    res = epoll_ctl(efd, EPOLL_CTL_ADD, sockfd, &event);

    events = (struct epoll_event*)calloc(MAX_EPOLL_EVENTS, sizeof(event));
    int timeout = 1 * 1000;
    int packet_send = 0;
    time_t init_time;
    int avg_rtt;
    while (1) {
        init_time = time(NULL);
        res  = epoll_wait(efd, events, MAX_EPOLL_EVENTS, timeout);
        if (res == 0) {
            if (packet_send < MAX_PACKET_NUM) {
                int packet_size;
                memset(sendpacket, 0, PACKET_SIZE);
                packet_size = pack(packet_send, sendpacket);
                if (sendto(sockfd,sendpacket,packet_size,0,
                    (struct sockaddr *)&dest_addr,sizeof(dest_addr)) < 0) {
                    perror("sendto error");
                }
                packet_send++;
                timeout = 5 * 1000;

            } else {

                int i;
                avg_rtt = average_rtt();
                printf("average RTT is %d\n", avg_rtt);
                pthread_mutex_lock(&(gw_info->gw_info_lock));
                if (gw_info->ping_gw_ip == gw_info->default_gw_ip) {
                    gw_info->rtt = avg_rtt;
                    gw_info->expire_timer = time(NULL) + GW_EXPIRE_INTERVAL;
                } else {
                    if (avg_rtt < gw_info->rtt) {
                        gw_info->rtt = avg_rtt;
                        gw_info->default_gw_ip = gw_info->ping_gw_ip;
                        gw_info->expire_timer = time(NULL) + GW_EXPIRE_INTERVAL;
                    }
                }
 
                pthread_mutex_unlock(&(gw_info->gw_info_lock));
                for (i = 0; i < MAX_PACKET_NUM; i++) {
                    total_rtt[i] = 5000.0;
                }
                packet_send = 0;
                timeout = 25 * 1000;

               
            }
        } else {
            int n;
            char recvpacket[PACKET_SIZE];
            //接收数据报
            if((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, 0, 0)) < 0)
            {
                perror("recvfrom error");
            }
            unpack(recvpacket, n);       //剥去ICMP报头
            timeout = timeout - (time(NULL) - init_time) * 1000;
        }
    
    }
}

int init_3g_detector(in_addr_t ping_ip)
{
    int sockfd;
    int i;


    if((sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)) < 0)
    {
        perror("socket error");
        return -1;
    }

    bzero(&dest_addr,sizeof(dest_addr));    //初始化
    dest_addr.sin_family = AF_INET;     //套接字域是AF_INET(网络套接字)
    dest_addr.sin_addr.s_addr = ping_ip;

    for (i = 0; i < MAX_PACKET_NUM; i++) {

        total_rtt[i] = MAX_RTT;
        printf("total_rtt[%d] = %lf\n", i, total_rtt[i]);
    }
    return sockfd;
}

void *start_detection_service(void *arg)
{
    int sockfd;

    gateway_info *gi_list = (gateway_info*)arg;

    sockfd = init_3g_detector(gi_list->ping_ip);
    assert(sockfd > 0);
    log_info("sockfd = %d\n", sockfd);
    start_service(sockfd, gi_list);
    return (void*)0;
}