#include<iostream>
#include<vector>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/ip_icmp.h>
#include<string.h>
#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<ifaddrs.h>
#include<linux/if_link.h>
#include<netdb.h>
#include<iomanip>


#include "ps_parser.cpp"
#define BUF_LEN 4096

using namespace std;
class combination
{
	public:
		string ip;
		int port;
		string scan;
		int flag;
		string status;
	combination(string i, int p, string s)
	{
		//cout<<endl<<" i "<<i;
		ip = i;
		//cout<<endl<<" ip "<<ip;
		port = p;
		scan = s;
		flag = 0;
	}
	void setip(string Ip)
	{
		ip = Ip;
	}
	void setport(int p){ port = p;}
	void setscan(string s)
	{
		scan = s;
	}
	void setstatus(string s){ status =s; }
	void printComb(){
	 cout<<endl<<ip;
	 cout<<" ";
	 cout<<port;
	 cout<<" "<<scan;}
};
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

vector<combination> task;

vector<string> ips;

int total_tasks = 0;
unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

void detectip(char ip1[])
{

    char ip[NI_MAXHOST], service[NI_MAXSERV];
    struct ifaddrs *addr, *ptr;

    getifaddrs(&addr);
    int i=0;
    for(ptr=addr;ptr!=NULL;i++,ptr=ptr->ifa_next)
    {

        if(ptr->ifa_addr!=NULL)
        {
            if(ptr->ifa_addr->sa_family==AF_INET && strcmp(ptr->ifa_name, "eth0")==0)
            {
                getnameinfo(ptr->ifa_addr, sizeof(struct sockaddr_in),ip, NI_MAXHOST,service,NI_MAXSERV, NI_NUMERICHOST);
                break;
            }
        }
    }
    strcpy(ip1, ip);
    freeifaddrs(addr);

}

int scan(int tcp_flags[], int p, string dt)
{
char packet[BUF_LEN], *pseudogram;
struct iphdr *ip1 = (struct iphdr *) packet;
struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));
memset(packet,0,BUF_LEN);
char *dest = new char[strlen(dt.c_str())+1];
strcpy(dest,dt.c_str());
struct sockaddr_in src;
struct pseudo_header ps;
int sockfd;
int opt = 1;
const int *optval = &opt;

int icmp_sockfd=0;


sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
if(sockfd<0)
{
   perror("socket() error");
   exit(-1);
}
else
printf("socket() done\n");
char myip[NI_MAXHOST];
int sport= 0;
while(sport<1025)
{
    sport=rand()%65535;
}
detectip(myip);
printf("my ip %s %d", myip,sport);

src.sin_family = AF_INET;
src.sin_port = htons(p);
src.sin_addr.s_addr = inet_addr(dest);

ip1->ihl = 5;
ip1->version = 4;
ip1->tos = 0;
ip1->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
ip1->id = htons(54321);
ip1->frag_off = 0;
ip1->ttl = 64;
ip1->protocol = IPPROTO_TCP; // TCP
ip1->check = 0;
ip1->saddr = inet_addr(myip);
ip1->daddr = inet_addr(dest);

tcp->source = htons(sport);
tcp->dest = htons(p);
tcp->seq = 0;
tcp->ack_seq = 0;
tcp->doff = 5;
tcp->syn= tcp_flags[0];
tcp->ack= tcp_flags[1];
tcp->fin= tcp_flags[2];
tcp->rst= tcp_flags[3];
tcp->psh= tcp_flags[4];
tcp->urg= tcp_flags[5];
tcp->window = htons(1212);
tcp->check = 0;
tcp->urg_ptr = 0;

ip1->check = csum((unsigned short *) packet, sizeof(struct iphdr)+(sizeof(struct tcphdr)));
//tcp->check = csum((unsigned short *)(packet + sizeof(struct ip)),(sizeof(struct tcphdr)));
    ps.source_address = inet_addr(myip);
    ps.dest_address = inet_addr(dest);
    ps.placeholder = 0;
    ps.protocol = IPPROTO_TCP;
    ps.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    pseudogram = (char*)malloc(sizeof(char)*psize);

    memcpy(pseudogram , (char*) &ps , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcp, sizeof(struct tcphdr));

    tcp->check = csum( (unsigned short*) pseudogram , psize);
    cout<<"setsockopt";
    if(setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,optval,sizeof(int))<0)
    {
        perror("setsockopt() error");
        exit(-1);
    }

    struct timeval tx;
    tx.tv_sec=4;
    tx.tv_usec=0;

    if(setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,&tx,sizeof(tx))<0)
    {
        perror("\nrecv timeout error");
        exit(-1);
    }

    socklen_t len = sizeof(src);
    int flag=0;
    char recv_buf[BUF_LEN];
    int j=0, r =0;
     for(j=0;j<3 && flag==0;j++)
    {
        if(sendto(sockfd,packet,sizeof(struct iphdr) + sizeof(struct tcphdr),0,(struct sockaddr *)&src,sizeof(src))<=0)
        {
           perror("sendto() error");
           exit(-1);
        }
        cout<<"sent\n";
        memset(recv_buf, 0, sizeof(recv_buf)-1);
        while((r=recvfrom(sockfd,recv_buf,sizeof(struct iphdr)+sizeof(struct tcphdr),0,(struct sockaddr *)&src,&len))>0)
        {
            cout << "Recv" << endl;
            struct iphdr *ip2 = (struct iphdr *)recv_buf;
            char *saddr=inet_ntoa(*(struct in_addr*)&ip1->daddr);
            char *daddr=inet_ntoa(*(struct in_addr*)&ip2->saddr);
            printf("\ndest addr: %s ", daddr);
            printf("\nsource addr: %s", saddr);
            if(strcmp(saddr, dest)==0)
            {
                printf("\nok");
                flag=1;
                break;
            }
        }
    }
    if(j==3 && flag==0)
    {
		cout << "icmp" <<endl;
		icmp_sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
		if(setsockopt(icmp_sockfd,IPPROTO_IP,IP_HDRINCL,optval,sizeof(int))<0)
		{
			perror("setsockopt() error");
			exit(-1);
		}
		if(icmp_sockfd<0)
		{
		   perror("socket() error");
		   exit(-1);
		}
		if(setsockopt(icmp_sockfd,SOL_SOCKET,SO_RCVTIMEO,&tx,sizeof(tx))<0)
		{
			perror("\nrecv timeout error");
			exit(-1);
		}
		cout<<"sending\n";
		if(sendto(icmp_sockfd,packet,sizeof(struct iphdr)+sizeof(tcphdr),0,(struct sockaddr *)&src,sizeof(src))<=0)
        {
           perror("sendto() error");
           exit(-1);
        }
        printf("j=3");
        if(recvfrom(icmp_sockfd,recv_buf,sizeof(struct iphdr)+sizeof(struct icmp),0,(struct sockaddr *)&src,&len)>0)
        {
            printf("icmp recv");
            struct icmp *icmp1 = (struct icmp *) (recv_buf + sizeof(struct iphdr));
            if(icmp1->icmp_type == 3 && (icmp1->icmp_code==1 || icmp1->icmp_code==2 || icmp1->icmp_code==3 || icmp1->icmp_code==9 || icmp1->icmp_code==10 || icmp1->icmp_code==13))
            {
                cout << "Unreachable error" << endl;
            }
        }
    }
    printf("\ncomplete");
    delete dest;
    close(sockfd);

    /*create socket for icmp */
    close(icmp_sockfd);
    return 0;
}

int main(int argc, char *argv[])
{
	ps_args_s ps_args;
	parse_args(&ps_args, argc, argv);
	//print all arguments
	if(ps_args.ip==1)
		ips.push_back(ps_args.ip_addr);
		//cout<<endl<<ps_args.ip_addr;
	if(ps_args.f==1)
	{
		for(int i=0;i<ps_args.file_ips.size();i++)
			{ips.push_back(ps_args.file_ips.at(i));
			cout<<endl<<ps_args.file_ips.at(i);}
	}
	if(ps_args.prefix!=-1)
	{
		for(int i=0;i<ps_args.p_ips.size();i++)
			ips.push_back(ps_args.p_ips.at(i));
			//cout<<endl<<ps_args.p_ips.at(i);
	}
	cout<<"\nno of ports"<<ps_args.num_ports<<endl;
	for(int i=0;i<ps_args.num_ports;i++)
	{
		//ports.push_back(ps_args.ports[i]);
		cout<<ps_args.ports[i]<<endl;
	}
	//copy(ps_args.scan_flags.begin(), ps_args.scan_flags.end(), scans.begin());
	for(int i=0;i<ips.size();i++)
	{
		for(int j=0;j<ps_args.num_ports;j++)
		{
			for(int k=0;k<ps_args.scan_flags.size();k++)
			{
				combination c(ips.at(i),ps_args.ports[j],ps_args.scan_flags.at(k));
				task.push_back(c);
			}
		}
	}
	int t[6] = {0,0,0,0,0,0};
	for(int i=0;i<task.size();i++)
	{
		if(task.at(i).scan.compare("SYN")==0)
		{
			t[0] = 1;
		}
		if(task.at(i).scan.compare("FIN")==0)
		{
			t[2] = 1;
		}
		if(task.at(i).scan.compare("XMAS")==0)
		{
			t[2] = 1;
			t[4] = 1;
			t[5] = 1;
		}
		if(task.at(i).scan.compare("ACK")==0)
		{
			t[1] = 1;
		}
		scan(t,task.at(i).port,task.at(i).ip);
	}
}
