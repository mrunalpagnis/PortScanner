#include<iostream>
#include<stdlib.h>
#include<netinet/ip.h>
#include<string.h>
#include<vector>
#define MAX_FILE_NAME 1024
#define MAX_SCAN_FLAGS 6
#define MAX_PORTS 65535
using namespace std;

typedef struct 
{
	int num_ports;
	int ports[MAX_PORTS];
	int ip;
	string ip_addr;
	int prefix;
	vector<string> p_ips;
	int f;
	char fileName[MAX_FILE_NAME];
	vector<string> file_ips;
	int speedup;
	int scan;
	vector<string> scan_flags;
}ps_args_s;