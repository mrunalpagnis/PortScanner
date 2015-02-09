#include<stdio.h>
#include<stdlib.h>
#include<getopt.h>
#include<iostream>
#include<ctype.h>
#include<string.h>
#include<vector>
#include<fstream>
#include<arpa/inet.h>

#include "parse.h"

#define MAX_IP_BITS 32
#define MAX_IP_STR 15
#define OCTET_LEN 8
#define IP_OCTETS 4
#define MAX_PREOPT_LEN 18

using namespace std;

static struct option opt_long[] = {
			{"help",  no_argument,       0,'h'},
			{"ports", required_argument, 0,'p'},
			{"ip",    required_argument, 0,'i'},
			{"prefix",required_argument, 0,'r'},
			{"file",  required_argument, 0,'f'},
			{"speedup",required_argument,0,'s'},
			{"scan",   required_argument,0,'k'},
			{0,0,0,'?'}
		};

void usage(FILE * file){
  if(file == NULL){
    file = stdout;
  }

  fprintf(file,
          "portScanner [OPTIONS] [Arguments]\n\n"
          "  -h			\t Print this help screen\n"
		  "			\t e.g: ./portScanner --help\n\n"
          "  -p port		\t Scans the specified ports\n"
		  "			\t e.g: ./portScanner --port 1,2,3-10\n\n"
          "  -i ip			\t ip address to be scanned is given\n"
		  "			\t e.g: ./portScanner --ip 127.0.0.1\n\n"
          "  -r ip/prefix		\t scans the specified ip prefix\n"
		  "			\t e.g: ./portScanner --prefix 127.14.0.1/24\n\n"
          "  -file			\t File name containing IP addresses to scan\n"
		  "			\t e.g: ./portScanner --file file.txt\n\n"
          "  -s threads		\t Number of threads to be used\n"
		  "			\t e.g: ./portScanner --speedup 10\n\n"
          "  -k flags		\t Performs the scan by selecting flags\n"
		  "			\t e.g: ./portScanner --scan SYN NULL FIN XMAS\n\n");
}
int power_two(int p)
{
	int r = 1;
	for(int i=0;i<p;i++)
	{
		r = r*2;
	}
	return r;
}

int isIP(char *ip)
{
	int tem = 0;
	if (0 == inet_pton(AF_INET, ip, &tem))
	{
		fprintf(stderr, " ERROR: Invalid IP %s \n",ip);
		usage(stderr);
		exit(-1);
	}
	return 1;
}

void binary2decimal(char oct[], int dec){

    int and1 = power_two(OCTET_LEN-1);

    // for each bit
    for( int i = 0; i < OCTET_LEN; i++ ){
        // if the bit is set, print 1

        if( dec & and1 ){
            oct[i] = '1';
        }
        // if the bit is not set, print 0
        else{
            oct[i] = '0';
        }
        // shift the constant using right shift
        and1 = and1 >> 1;
    }
    //printf("\n");
}
int isNumber(char * num)
{
	int len = strlen(num);
	for(int i=0;i<len;i++)
	{
		if(!isdigit(num[i]))
			return 0;
	}
	return 1;
}

int isflag(char *flag)
{
	//printf("\n flag - %s",flag);
	if(strcmp(flag,"SYN")==0 || strcmp(flag,"NULL")==0 || strcmp(flag,"FIN")==0 || strcmp(flag,"XMAS")==0 || strcmp(flag,"ACK")==0 || strcmp(flag,"UDP")==0 )
	{
		return 1;
	}
	return 0;
}

int scan_ports(int ports[], char *optarg)
{
	int len_of_string=0;
	int d_flag=0;
	int c_flag=0;
	int h_flag=0;
	int d_pos=0;
	int i=0;
	int r_s=0;
	int r_e=0;
	//int ports[MAX_PORTS];
	int j=0;
	if(!isdigit(optarg[0]))
	{
		fprintf(stderr,"ERROR: Wrong argument\n");
        usage(stderr);
		return -1;
	}
	len_of_string=strlen(optarg);
	if(isNumber(optarg))
	{
        ports[0]=atoi(optarg);
        if(ports[0]>65535)
            return -1;
        return 1;
	}
	for(i=0;i<len_of_string;i++)
	{
		if(!isdigit(optarg[i]))
		{
			if(optarg[i]==',')
			{
				d_flag=0;
				int size=0;
				size=i-d_pos;
				char temp[size+1];
				strncpy(temp, optarg+d_pos, size);
				temp[size] = '\0';
				c_flag=1;
				if(h_flag==1)
				{
					r_e=atoi(temp);
					h_flag=0;
					if(r_e<=r_s)
					{
						fprintf(stderr,"\nError: Invalid range\n");
						usage(stderr);
						exit(-1);
					}
					if(r_e>MAX_PORTS-1)
					{
						fprintf(stderr,"\nError: Invalid range\n");
						usage(stderr);
						exit(-1);
					}
					for(int k=0;k<=r_e-r_s;k++)
					{
						ports[j++]=r_s+k;
					}
				}
				else
				{
					if(atoi(temp)>MAX_PORTS-1)
					{
						fprintf(stderr,"\nError: Invalid range\n");
						usage(stderr);
						exit(-1);
					}
					ports[j++]=atoi(temp);
				}

			}
			else if(optarg[i]=='-')
			{
				d_flag=0;
				int size=0;
				size=i-d_pos;
				char temp[size+1];
				strncpy(temp, optarg+d_pos, size);
				temp[size] = '\0';
				if(h_flag==0)
				{
					r_s=atoi(temp);
					h_flag=1;
					c_flag=0;
				}
			}
			else
			{
				fprintf(stderr,"\nError: Incorrect format\n");
				usage(stderr);
				exit(-1);
			}
			if(i+1 <= len_of_string && !isdigit(optarg[i+1]))
			{
				fprintf(stderr,"\nError: Invalid range\n");
				usage(stderr);
				return -1;
			}
		}
		else if(d_flag==0)
		{
			d_flag=1;
			d_pos=i;
		}
	}
	if(d_flag==1)
	{
		if(c_flag==1)
		{
			int size=0;
			size=i-d_pos;
			char temp[size+1];
			strncpy(temp, optarg+d_pos, size);
			temp[size] = '\0';
			if(atoi(temp)>MAX_PORTS-1)
			{
				fprintf(stderr,"\nError: Invalid range\n");
				usage(stderr);
				exit(-1);
			}
			ports[j++]=atoi(temp);

		}
		else if(h_flag==1)
		{
			int size=0;
			size=i-d_pos;
			char temp[size+1];
			strncpy(temp, optarg+d_pos, size);
			temp[size] = '\0';
			r_e=atoi(temp);
			if(r_e<=r_s)
            {
                fprintf(stderr,"\nError: Invalid range\n");
                usage(stderr);
                exit(-1);
            }
			if(r_e>MAX_PORTS-1)
			{
				fprintf(stderr,"\nError: Invalid range\n");
				usage(stderr);
				exit(-1);
			}
			for(int k=0;k<=r_e-r_s;k++)
			{
				ports[j++]=r_s+k;
			}
		}
	}
	if(j>MAX_PORTS)
	{
		fprintf(stderr,"\nError: Number of ports exceeding than Maximum ports\n");
		usage(stderr);
		exit(-1);
	}
	return j;
}

int read_file_ip(vector<string> &ips, char *optarg)
{
	ifstream file(optarg);
	string str;
	if(!file.good())
	{
		fprintf(stderr, "Error: File doesnot exist");
		return -1;
	}

	while(getline(file,str))
	{
		char *t_ip = (char *)(str.c_str());
		ips.push_back(str);
	}
	return 1;
}

int parse_prefix(vector<string> &ips, char *optarg)
{
	int prefix = -1;
	char *dl;
	if(strlen(optarg)>MAX_PREOPT_LEN)
	{
		fprintf(stderr,"ERROR: Invalid argument for prefix option\n");
		usage(stdout);
		exit(-1);
	}
	if((dl=strchr(optarg,'/'))==NULL)
	{
		fprintf(stderr,"ERROR: Invalid argument for prefix option\n");
		usage(stdout);
		exit(-1);
	}
	if(!isdigit(*(dl+1)))
	{
		fprintf(stderr,"ERROR: Invalid argument for prefix option\n");
		usage(stdout);
		exit(-1);
	}
	char *ip;
	int pr = 0;
	int s=0;
	int r = 0;
	r = power_two(pr);
	int oct[IP_OCTETS];
	char octet[IP_OCTETS];
	char decIp[MAX_IP_BITS];
	int cnt = 0;
	char *x;
	int k =0;
	char subnet[MAX_IP_BITS];
	int start = 0;
	int end = OCTET_LEN;
	int pow = OCTET_LEN-1;
	int n_oct = 0;
	int oct_pr[IP_OCTETS] = {0,0,0,0};
	int oct_r[IP_OCTETS] = {0,0,0,0};
	char addr[MAX_IP_STR];
	int o0=0,o1=0,o2=0,o3=0;

	char temp[MAX_PREOPT_LEN];// = (char*)malloc(sizeof(char)*strlen(optarg));
	strcpy(temp,optarg);
	ip = strtok(temp,"/");

	char *p = strtok(NULL,"/");

	if(!isNumber(p))
	{
		fprintf(stderr,"ERROR: Invalid argument for prefix option\n");
		usage(stdout);
		exit(-1);
	}
	prefix = atoi(p);
	pr = MAX_IP_BITS - prefix;
	r = power_two(pr);
	for(x = strtok(ip,".");x!=NULL;k++,x = strtok(NULL,"."))
	{
		oct[k] = atoi(x);
		binary2decimal(octet,oct[k]);
		for(int m=0;m<OCTET_LEN;m++)
		{
			decIp[cnt] = octet[m];
			cnt++;
		}
	}
	decIp[MAX_IP_BITS] = '\0';
	strcpy(subnet,decIp);
	for(int i=prefix;i<MAX_IP_BITS;i++)
	{
		subnet[i]='0';
	}
	subnet[MAX_IP_BITS] = '\0';
	for(int oc=0; oc<IP_OCTETS; oc++)
	{
		pow = OCTET_LEN-1;
		oct[oc] = 0;
		for(;start<end;start++,pow--)
		{
			if(subnet[start] == '1')
				oct[oc] += power_two(pow);
		}
		end += OCTET_LEN;
	}
	if((int)pr%OCTET_LEN==0)
		n_oct=pr/OCTET_LEN;
	else
		n_oct=(int)pr/OCTET_LEN+1;
	for(int j=0;j<n_oct;j++)
	{
		if(pr>=OCTET_LEN)
		{
			oct_pr[j] = OCTET_LEN;
			pr = pr - OCTET_LEN;
		}
		else
			oct_pr[j] = pr;
	}
	for(int l=0;l<IP_OCTETS;l++)
	{
		oct_r[l] = power_two(oct_pr[l]);
	}
	o0=oct[0];
	for(int l=0;l<oct_r[3];l++)
	{
		o1 = oct[1];
		for(int k=0;k<oct_r[2];k++)
		{
			o2 = oct[2];
			for(int j=0;j<oct_r[1];j++)
			{
				o3 = oct[3];
				for(int i=0;i<oct_r[0];i++)
				{
					memset(addr,0,MAX_IP_STR);
					sprintf(addr,"%d.%d.%d.%d\0",o0,o1,o2,o3++);
					//cout<<endl<<addr;
					ips.push_back(addr);
				}
				o2++;
			}
			o1++;
		}
		o0++;
	}
}

int parse_args(ps_args_s *ps_args, int argc, char *argv[])
{
	int ch;
	vector<string> ips;
	vector<string> pips;
	int opt_index = 0;
	int r =0;
	//defaults
	char pt[1024] = "0-1024";
	ps_args->ip = -1;
	ps_args->speedup = 5;
	ps_args->prefix = -1;
	ps_args->f = -1;
	ps_args->scan = -1;
	while((ch = getopt_long(argc,argv,"hp:i:r:f:s:k:",opt_long,&opt_index))!=-1)
	{
		switch(ch)
		{
			case 'h':
				usage(stdout);
				break;
			case 'p':
				printf("\nports");
				memset(pt,0,sizeof(pt)-1);
				strcpy(pt,optarg);
				break;
			case 'i':
				ps_args->ip = 1;
				if(isIP(optarg))
					ps_args->ip_addr = optarg;
				break;
			case 'r':
				ps_args->prefix = 1;
				parse_prefix(pips,optarg);
				ps_args->p_ips = pips;
				break;
			case 'f':
				ps_args->f = 1;
				strcpy(ps_args->fileName,optarg);
				if(read_file_ip(ips,optarg))
					ps_args->file_ips = ips;
				//copy(ips.begin(),ips.end(),ps_args->file_ips.begin());
				else
				{
					fprintf(stderr,"ERROR: Invalid IP in file\n");
					usage(stdout);
					exit(-1);
				}
				break;
			case 's':
				if(isNumber(optarg))
					ps_args->speedup = atoi(optarg);
				else
				{
					fprintf(stderr,"ERROR: speed up should be a number\n");
					usage(stdout);
					exit(-1);
				}
				break;
			case 'k':
				ps_args->scan = 1;
				if(isflag(optarg))
					ps_args->scan_flags.push_back(optarg);
				else
				{
					fprintf(stderr,"ERROR: Invalid flag\n");
					usage(stdout);
					exit(-1);
				}
				if(optind<argc)
				{
					while(optind<argc)
					{
						if(isflag(argv[optind])==1)
						{
							//printf("\n scan with %s",argv[optind++]);
							ps_args->scan_flags.push_back(argv[optind]);
							optind++;
						}
						else
						{
							//printf("\n no match");
							//optind--;
							break;
						}
					}
				}
				break;
			case '?':
				usage(stdout);
				exit(1);
				break;

		}
		//opt_index++;
	}
	if(argc<2)
	{
		fprintf(stderr,"ERROR: too few arguments \n");
		usage(stdout);
		exit(-1);
	}
	if(optind<argc)
	{
		fprintf(stderr,"ERROR: too many arguments \n");
		usage(stdout);
		exit(-1);
	}
	if(ps_args->scan == -1)
	{
		ps_args->scan_flags.push_back("SYN");
		ps_args->scan_flags.push_back("NULL");
		ps_args->scan_flags.push_back("FIN");
		ps_args->scan_flags.push_back("UDP");
		ps_args->scan_flags.push_back("XMAS");
		ps_args->scan_flags.push_back("ACK");
	}
	if(ps_args->scan_flags.size()>MAX_SCAN_FLAGS)
	{
		fprintf(stderr,"ERROR: too many scan flags \n");
		usage(stdout);
		exit(-1);
	}
	r = scan_ports(ps_args->ports, pt);
	if(r==-1)
		exit(-1);
	ps_args->num_ports = r;
}
