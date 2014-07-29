#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/in_systm.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>
#include <sys/un.h>
#include <pcap.h>
#include <assert.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "packet_sniffer.h"
#include "route_engine.h"

#define MAX_PCAP_IF_COUNT 2
typedef struct thread_arg
{
    int index;
    sate_info *sate_info;
} thread_arg;

int linkhdrlen;
pcap_t *pds[MAX_PCAP_IF_COUNT];
pthread_t pcap_threads[MAX_PCAP_IF_COUNT];
thread_arg args[MAX_PCAP_IF_COUNT];



int create_tmp_folder()
{
    int rv = 0;
    const char *folder_name = "tmp";
    if (access(folder_name, F_OK) == 0)
        return 0;
    rv = mkdir("tmp", S_IRWXU);
    
    return rv;
}

int create_tmp_file(char *filename)
{
    int fd;
    char temp_file[] = "./tmp/tmp_XXXXXX";

    if ((fd = mkstemp(temp_file)) < 0)
        return -1;
    strcpy(filename, temp_file);
    close(fd);

    return 0;
}

pcap_t* open_pcap_socket(char* device, const char* bpfstr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pd;
    uint32_t  srcip, netmask;
    struct bpf_program  bpf;


    // If no network interface (device) is specfied, get the first one.
    if (!*device && !(device = pcap_lookupdev(errbuf)))
    {
        printf("pcap_lookupdev(): %s\n", errbuf);
        return NULL;
    }
    
    // Open the device for live capture, as opposed to reading a packet
    // capture file.
    if ((pd = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) < 0)
    {
        printf("pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    // Convert the packet filter epxression into a binary packet
    // filter.
    if (pcap_compile(pd, &bpf, (char*)bpfstr, 0, netmask))
    {
        printf("pcap_compile(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    // Assign the packet filter to the given libpcap socket.
    if (pcap_setfilter(pd, &bpf) < 0)
    {
        printf("pcap_setfilter(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    return pd;
}

void capture_loop(pcap_t* pd, int packets, pcap_handler func, sate_info *sate_arg)
{
    int linktype;
    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(pd)) < 0)
    {
        printf("pcap_datalink(): %s\n", pcap_geterr(pd));
        return;
    }

    // Set the datalink layer header size.
    switch (linktype)
    {
        case DLT_NULL:
        linkhdrlen = 4;
        break;

        case DLT_EN10MB:
        linkhdrlen = 14;
        break;

        case DLT_SLIP:
        case DLT_PPP:
        linkhdrlen = 24;
        break;

        default:
        printf("Unsupported datalink (%d)\n", linktype);
        return;
    }

    printf("begin sniff\n");
    if (pcap_loop(pd, packets, func, (u_char*)sate_arg) < 0)
        printf("pcap_loop failed: %s\n", pcap_geterr(pd));
}

void parse_packet(u_char *args, const struct pcap_pkthdr *header, 
    const u_char *packetptr)
{

    struct ip* iphdr;
    struct udphdr* udphdr;
    char *udp_data;
    char iphdrInfo[256], srcip[256], dstip[256];
    int nwrite;
    unsigned long dst_ip;
    char filename[512];
    int res;

    sate_info *sate_arg = (sate_info*)args;

    //ignore unwanted packet
    pthread_mutex_lock(&sate_arg->cond_mutex);
    int flag = sate_arg->running;
    pthread_mutex_unlock(&sate_arg->cond_mutex);

    if (flag != 1)
        return;



    // Skip the datalink layer header and get the IP header fields.
    packetptr += 14;
    iphdr = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    dst_ip = ntohl(iphdr->ip_dst.s_addr);
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
        ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
        4*iphdr->ip_hl, ntohs(iphdr->ip_len));

    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packetptr += 4*iphdr->ip_hl;
    if (iphdr->ip_p == IPPROTO_UDP)
    {

        udphdr = (struct udphdr*)packetptr;
        int udp_data_len = ntohs(udphdr->len) - sizeof(struct udphdr);

        fprintf(stderr, "dst ip:%s dst port:%d data len:%d\n", dstip, 
            ntohs(udphdr->dest), udp_data_len);
        int rv = create_tmp_file(filename);
        if (rv < 0) {
            printf("failed to create temp file\n");
            return;
        }

        FILE *fp = fopen(filename, "wb");
        fprintf(fp, "%lu %d %d", dst_ip, ntohs(udphdr->dest), 
            udp_data_len);
        packetptr += sizeof(struct udphdr);
        udp_data = (char*)packetptr;

        fwrite(udp_data, udp_data_len, 1, fp);
        fclose(fp);

        
        queue *req_queue = sate_arg->req_queue;
        res = en_queue(req_queue, filename);
        if (res < 0) {
            log_err("Failed to enqueue filename :%s", filename);
            return;
        }
        nwrite = write(sate_arg->pipe_fds[1], "0", 1);
        if (nwrite < 0) {
            log_err("Failed to send notification");
            return;
        }

    }

}

void *pcap_thread_func(void *arg)
{
    
    thread_arg *t_arg = (thread_arg*)arg;
    sate_info *sate_arg = t_arg->sate_info;
    printf("pcap thread %d\n", t_arg->index);
    int i = t_arg->index;
    while (1) {
        pthread_mutex_lock(&sate_arg->cond_mutex);
        printf("running = %d\n", sate_arg->running);
        while (sate_arg->running != 1) {
            printf("stop sniffing\n");
            if (pds[i] != NULL)
                pcap_close(pds[i]);
            pthread_cond_wait(&sate_arg->last_choice, &sate_arg->cond_mutex);
            sate_info_entry *entry = &(sate_arg->entries[i]);
            if (!(pds[i] = open_pcap_socket(entry->interface, entry->rule)))  {
                log_err("Failed to open pcap socket");
                return (void*)1;
            }
        }
        pthread_mutex_unlock(&sate_arg->cond_mutex);

        capture_loop(pds[t_arg->index], 1, (pcap_handler)parse_packet,
             t_arg->sate_info);        
    }

    return (void*)0;
}

int create_cap_threads(sate_info *sate_info)
{
    int i;
    int rv;

    printf("create pcap threads:%d\n", sate_info->pcap_if_count);
    for (i = 0; i < sate_info->pcap_if_count; i++) {

        pds[i] = NULL;
        args[i].index = i;
        args[i].sate_info = sate_info;
        rv = pthread_create(&pcap_threads[i], NULL, pcap_thread_func, (void*)&args[i]);
        if (rv != 0) {
            perror("failed to create worker thread");
            return -1;
        }
    }

    return 0;
}

int start_pcap_service(void *arg)
{
    int rv;
    sate_info *sate_arg = (sate_info*)arg;
    rv = create_tmp_folder();
    if (rv == -1) {
        perror("failed to create folder for temperory files\n");
        return -1;      }

    rv = create_cap_threads(sate_arg);
    if (rv == -1) {
        perror("failed to create cap threads\n");
        return -1;
    }

    return 0;
}