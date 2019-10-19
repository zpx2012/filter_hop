
#include "hping2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#include <sys/stat.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "logging.h"
#include "util.h"
#include "cache.h"
#include "redis.h"


#define NF_QUEUE_NUM 6

/* uncomment below unless you want to specify local ip */
//#define LOCAL_IP ""

/*
 * Options
 */

int opt_measure = 0;

/*
 * Global variables
 */

struct nfq_handle *g_nfq_h;
struct nfq_q_handle *g_nfq_qh;
int g_nfq_fd;

int nfq_stop;

pid_t tcpdump_pid = 0;

timespec start, end;

int type1rst, type2rst, succrst, succsynack;

char type1gfw[30], type2gfw[30];

unsigned char last_ttl;
unsigned char legal_ttl;

char pkt_data[10000];
size_t pkt_len;

char local_ip[16];
unsigned short local_port = 38324;

char remote_ip[16];
unsigned short remote_port = 80;

char local_host_name[64];
char remote_host_name[64];

char payload_sk[1000] = "GET /?keyword=ultrasurf HTTP/1.1\r\nHOST: whatever.com\r\nUser-Agent: test agent\r\n\r\n";


int start_ttl = 5;


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, 
              struct nfq_data *nfa, void *data);


int start_redis_server()
{
    int ret;
    log_info("Starting redis server.");
    ret = system("redis-server redis.conf");
    if (ret != 0) {
        log_error("Failed to start redis server.");
        return -1;
    }

    return 0;
}

int stop_redis_server()
{
    FILE *fp = fopen("redis.pid", "r");
    if (fp == NULL) {
        log_warn("Redis server is not running?");
        return -1;
    }

    char s[10] = "";
    fread(s, 1, 10, fp);
    pid_t redis_pid = strtol(s, NULL, 10);
    log_info("Killing redis server (pid %d).", redis_pid);
    kill(redis_pid, SIGTERM);

    return 0;
}

int setup_nfq()
{
    g_nfq_h = nfq_open();
    if (!g_nfq_h) {
        log_error("error during nfq_open()");
        return -1;
    }

    log_debug("unbinding existing nf_queue handler for AF_INET (if any)");
    if (nfq_unbind_pf(g_nfq_h, AF_INET) < 0) {
        log_error("error during nfq_unbind_pf()");
        return -1;
    }

    log_debug("binding nfnetlink_queue as nf_queue handler for AF_INET");
    if (nfq_bind_pf(g_nfq_h, AF_INET) < 0) {
        log_error("error during nfq_bind_pf()");
        return -1;
    }

    // set up a queue
    log_debug("binding this socket to queue %d", NF_QUEUE_NUM);
    g_nfq_qh = nfq_create_queue(g_nfq_h, NF_QUEUE_NUM, &cb, NULL);
    if (!g_nfq_qh) {
        log_error("error during nfq_create_queue()");
        return -1;
    }
    log_debug("nfq queue handler: %p", g_nfq_qh);

    log_debug("setting copy_packet mode");
    if (nfq_set_mode(g_nfq_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        log_error("can't set packet_copy mode");
        return -1;
    }

    g_nfq_fd = nfq_fd(g_nfq_h);

    return 0;
}

int teardown_nfq()
{
    log_debug("unbinding from queue %d", NF_QUEUE_NUM);
    if (nfq_destroy_queue(g_nfq_qh) != 0) {
        log_error("error during nfq_destroy_queue()");
        return -1;
    }

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    log_debug("unbinding from AF_INET");
    nfq_unbind_pf(g_nfq_h, AF_INET);
#endif

    log_debug("closing library handle");
    if (nfq_close(g_nfq_h) != 0) {
        log_error("error during nfq_close()");
        return -1;
    }

    return 0;
}


void add_iptables_rules()
{
    char cmd[1000];
    sprintf(cmd, "iptables -A OUTPUT -t raw -p tcp -d %s --dport %u --tcp-flags RST,ACK RST -j DROP", remote_ip, remote_port);
    system(cmd);
    sprintf(cmd, "iptables -A INPUT -p tcp -s %s --sport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, NF_QUEUE_NUM);
    system(cmd);
    sprintf(cmd, "iptables -A OUTPUT -t raw -p tcp -d %s --dport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, NF_QUEUE_NUM);
    system(cmd);
}


void remove_iptables_rules()
{
    char cmd[1000];
    sprintf(cmd, "iptables -D OUTPUT -t raw -p tcp -d %s --dport %u --tcp-flags RST,ACK RST -j DROP", remote_ip, remote_port);
    system(cmd);
    sprintf(cmd, "iptables -D INPUT -p tcp -s %s --sport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, NF_QUEUE_NUM);
    system(cmd);
    sprintf(cmd, "iptables -D OUTPUT -t raw -p tcp -d %s --dport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, NF_QUEUE_NUM);
    system(cmd);
}

void cleanup()
{
    fin_log();

    teardown_nfq();

    //char tmp[64];
    //log_info("Killing tcpdump.");
    //sprintf(tmp, "kill %d", tcpdump_pid);
    //system(tmp);

    stop_redis_server();

    remove_iptables_rules();
}

void signal_handler(int signum)
{
    log_debug("Signal %d recved.", signum);
    cleanup();
    exit(EXIT_FAILURE);
}


void init()
{
    // init random seed
    srand(time(NULL));

    init_log();

    // initializing globals
    sockraw = open_sockraw();

    int portno = 80;
    sockpacket = open_sockpacket(portno);
    if (sockpacket == -1) {
        log_error("[main] can't open packet socket\n");
        exit(EXIT_FAILURE);
    }

    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        log_error("register SIGINT handler failed.\n");
        exit(EXIT_FAILURE);
    }
    if (signal(SIGSEGV, signal_handler) == SIG_ERR) {
        log_error("register SIGSEGV handler failed.");
        exit(EXIT_FAILURE);
    }

    if (setup_nfq() == -1) {
        log_error("unable to setup netfilter_queue");
        exit(EXIT_FAILURE);
    }

    start_redis_server();

    connect_to_redis();

    add_iptables_rules();
}



/* Process TCP packets
 * Return 0 to accept packet, otherwise to drop packet 
 */
int process_tcp_packet(struct mypacket *packet)
{
    struct myiphdr *iphdr = packet->iphdr;
    struct mytcphdr *tcphdr = packet->tcphdr;
    unsigned char *payload = packet->payload;

    char sip[16], dip[16];
    ip2str(iphdr->saddr, sip);
    ip2str(iphdr->daddr, dip);

    unsigned short sport, dport;
    //unsigned int seq, ack;
    sport = ntohs(tcphdr->th_sport);
    dport = ntohs(tcphdr->th_dport);
    //seq = tcphdr->th_seq;
    //ack = tcphdr->th_ack;
    //log_debug("[TCP] This packet goes from %s:%d to %s:%d", sip, sport, dip, dport);
    //log_debug("TCP flags: %s", tcp_flags_str(tcphdr->th_flags));

    log_exp("%s:%d -> %s:%d <%s> seq %u ack %u ttl %u plen %d", sip, sport, dip, dport, tcp_flags_str(tcphdr->th_flags), ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack), iphdr->ttl, packet->payload_len);

    struct fourtuple fourtp;
    fourtp.saddr = iphdr->saddr;
    fourtp.daddr = iphdr->daddr;
    fourtp.sport = tcphdr->th_sport;
    fourtp.dport = tcphdr->th_dport;

    if (sport == remote_port) {
        if (tcphdr->th_flags == (TH_SYN | TH_ACK)) {
            cache_synack(&fourtp, iphdr->ttl);
        }
        else if (tcphdr->th_flags == TH_RST && iphdr->frag_flags == 0) {
            cache_rst(&fourtp, iphdr->ttl);
        }
        else if (tcphdr->th_flags == (TH_RST | TH_ACK)) {
            cache_rstack(&fourtp, iphdr->ttl);
        }
        last_ttl = iphdr->ttl;
    }
    else {
        if (tcphdr->th_flags == TH_SYN) {
        }
    }

    return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, 
              struct nfq_data *nfa, void *data)
{
    //log_debug("entering callback");
    //u_int32_t id = print_pkt(nfa);
    //char buf[1025];
    //nfq_snprintf_xml(buf, 1024, nfa, NFQ_XML_ALL);
    //log_debug("%s", buf);
    
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        log_error("nfq_get_msg_packet_hdr failed");
        return -1;
    }
    u_int32_t id = ntohl(ph->packet_id);
    //log_debug("packet id: %d", id);

    // get data (IP header + TCP header + payload)
    unsigned char *pkt_data;
    int plen = nfq_get_payload(nfa, &pkt_data);
    //if (plen >= 0)
    //    log_debug("payload_len=%d", plen);
    //hex_dump(pkt_data, plen);

    struct mypacket packet;
    packet.data = pkt_data;
    packet.len = plen;
    packet.iphdr = ip_hdr(pkt_data);
    
    // parse ip
    char sip[16], dip[16];
    ip2str(packet.iphdr->saddr, sip);
    ip2str(packet.iphdr->daddr, dip);
    //log_debugv("This packet goes from %s to %s.", sip, dip);

    int ret = 0;

    switch (packet.iphdr->protocol) {
        case 6: // TCP
            packet.tcphdr = tcp_hdr(pkt_data);
            packet.payload = tcp_payload(pkt_data);
            packet.payload_len = packet.len - packet.iphdr->ihl*4 - packet.tcphdr->th_off*4;
            //show_packet(&packet);
            ret = process_tcp_packet(&packet);
            break;
        default:
            log_error("Invalid protocol: %d", packet.iphdr->protocol);
    }
    
    if (ret == 0)
        nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    else
        nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        
    // return <0 to stop processing
    return 0;
}

void nfq_process(int timeout = 1)
{
    int rv;
    char buf[65536];
    
    clock_gettime(CLOCK_REALTIME, &start);
    clock_gettime(CLOCK_REALTIME, &end);
    //log_debug("%d:%d", end.tv_sec, end.tv_sec);

    while (diff(end,start).tv_sec < timeout){
        rv = recv(g_nfq_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (rv >= 0) {
        //while ((rv = recv(g_nfq_fd, buf, sizeof(buf), 0)) && rv >= 0) {
            //hex_dump((unsigned char *)buf, rv);
            //log_debugv("pkt received");
            nfq_handle_packet(g_nfq_h, buf, rv);
        //}
        }
        else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                log_debug("recv() ret %d errno: %d", rv, errno);
            }
            usleep(100000);
        }
	clock_gettime(CLOCK_REALTIME, &end);
    }
    //log_debug("%d:%d", end.tv_sec, end.tv_sec);
}

void *nfq_loop(void *arg)
{
    int rv;
    char buf[65536];

    while (!nfq_stop) {
        rv = recv(g_nfq_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (rv >= 0) {
            //log_debug("%d", rv);
            //hex_dump((unsigned char *)buf, rv);
            //log_debugv("pkt received");
            nfq_handle_packet(g_nfq_h, buf, rv);
        }
        else 
            usleep(10000);
    }
}

int main(int argc, char *argv[])
{
    int opt;

    if (argc != 6) {
        printf("Usage: %s <remote_ip> <remote_port> <local_port> <local_host_name> <remote_host_name>\n", argv[0]);
        exit(-1);
    }

    strncpy(remote_ip, argv[1], 16);
    resolve((struct sockaddr*)&remote, remote_ip);

#ifndef LOCAL_IP
    get_local_ip(local_ip);
#else
    local_ip[0] = 0;
    strncat(local_ip, LOCAL_IP, 16);
#endif

    remote_port = atoi(argv[2]);
    local_port = atoi(argv[3]);

    strncpy(remote_host_name, argv[4], 63);
    strncpy(local_host_name, argv[5], 63);

    //start_ttl = atoi(argv[6]);

    /* records are saved in folder results */
    /* create the directory if not exist */
    mkdir("results", 0755);

    char hostname_pair_path[64], result_path[64];

    time_t rawtime;
    struct tm * timeinfo;
    char time_str[20];
    char tmp[64];

    sprintf(hostname_pair_path, "results/%s-%s", local_host_name, remote_host_name);
    mkdir(hostname_pair_path, 0755);

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(time_str, 20, "%Y%m%d_%H%M%S", timeinfo);
    sprintf(result_path, "%s/%s", hostname_pair_path, time_str);
    mkdir(result_path, 0755);

    pid_t pid;
    pid = fork();
    if (pid < 0) {
        log_error("fork() failed.");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        char pcap_file[256];
        char filter[256];
        sprintf(pcap_file, "%s/packets.pcap", result_path);
        sprintf(filter, "tcp and host %s and port %d", remote_ip, remote_port);
        char *args[] = {"tcpdump", "-i", "any", "-w", pcap_file, filter, 0};
        //char *env[] = { 0 };
        execv("/usr/sbin/tcpdump", args);
        exit(EXIT_SUCCESS);
    }

    sleep(2);

    tcpdump_pid = pid;

    init();

    // start the nfq proxy thread
    nfq_stop = 0;
    pthread_t nfq_thread;
    if (pthread_create(&nfq_thread, NULL, nfq_loop, NULL) != 0){
        log_error("Fail to create nfq thread.");
        exit(EXIT_FAILURE);
    }
    
    /* init experiment log */
    sprintf(tmp, "%s/experiment.log", result_path);
    init_exp_log(tmp);

    log_exp("Local IP: %s", local_ip);
    log_exp("Local Port: %d", local_port);
    log_exp("Remote IP: %s", remote_ip);
    log_exp("Remote Port: %d", remote_port);

    //log_exp("Finding server packet TTL...");
    //get_legal_ttl(remote_ip);
    //log_exp("Server packet TTL = %d", legal_ttl);

    log_exp("Running traceroute...");
    sprintf(tmp, "%s/traceroute.txt", result_path);
    traceroute(remote_ip, tmp);

    log_exp("Locating GFW devices...");
    locate_gfw(remote_ip);

    char ttl_file_path[64];
    sprintf(ttl_file_path, "%s/filter_hop_%s_%s.csv", hostname_pair_path, local_host_name, remote_host_name);
    FILE *f_output = fopen(ttl_file_path, "a");
    int type1ttl = -1, type2ttl = -1;
    for (int i = 0; i < 30; i++) {
        if (type1ttl == -1 && type1gfw[i] == 1) {
            type1ttl = i;
        }
        if (type2ttl == -1 && type2gfw[i] == 1) {
            type2ttl = i;
        }
    }
    strftime(time_str, 20, "%Y-%m-%d %H:%M:%S", timeinfo);
    fprintf(f_output, "%s,%d,%d\n", time_str, type1ttl, type2ttl);
    fclose(f_output);

    nfq_stop = 1;

    sleep(2);

    log_exp("Killing tcpdump.");
    sprintf(tmp, "kill %d", tcpdump_pid);
    system(tmp);

    cleanup();

    return 0;
}
