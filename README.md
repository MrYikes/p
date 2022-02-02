#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Ws2ipdef.h>
#include <windows.h>
#include <crtdbg.h>
 
#include <iostream>
using std::cout;
 
 
#pragma comment (lib,"ws2_32")
 
 
//#define TRACERT //если вместо пинга нужен трэйс
 
#define MANUAL //если надо сформировать IP заголовок вручную.
 
 
 
#ifdef MANUAL
#define PACKET_ FullPack
#else
#define PACKET_ Packet
#endif
 
typedef struct ip_hdr //заголовок IP 
{
    unsigned char verhlen;
    unsigned char tos:6;
    unsigned char additional:2;
    unsigned short totallent;
    unsigned short id;  
    unsigned short offset;
    unsigned char ttl;
    unsigned char proto;
    unsigned short checksum;
    unsigned int source;
    unsigned int destination;   
}IpHeader;
 
typedef  struct icmp_hdr //заголовок ICMP
{
    unsigned char i_type;
    unsigned char i_code;
    unsigned short i_crc;
    unsigned short i_seq;
    unsigned short i_id;
    
}IcmpHeader;
 
 
 
 
USHORT crc2 (USHORT* addr, int count) //http://www.ietf.org/rfc/rfc1071.txt подсчет CRC
{
 
    register long sum = 0;
 
    while( count > 1 )  {
        /*  This is the inner loop */
        sum += * (unsigned short*) addr++;
        count -= 2;
    }
 
    /*  Add left-over byte, if any */
    if( count > 0 )
        sum += * (unsigned char *) addr;
 
    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);
 
    return (USHORT)(~sum);
    
}
 
 
unsigned int analize(char* data, SOCKADDR_IN* adr) //разбор ответа
{
 
 
char* Ip = "";
IpHeader *pHe = (IpHeader*)data;
char Name[NI_MAXHOST]={0};
char servInfo[NI_MAXSERV]={0};
getnameinfo((struct sockaddr *) adr,sizeof (struct sockaddr),Name,  NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);
Ip = inet_ntoa(adr->sin_addr);
 
#ifdef TRACERT
IcmpHeader *ic = (IcmpHeader*)data;
cout<<"Reply from "<<" "<<Name<<" ["<<Ip<<"]\n";
return pHe->source;
 
#else
int TTL = (int)pHe->ttl;
data+=sizeof(IpHeader);
IcmpHeader *ic = (IcmpHeader*)data;
if(GetCurrentProcessId()==ic->i_id)//проверка что это мы слали.
cout<<"Reply from "<<Ip<<" TTL="<<TTL<<"\n";
else
cout<<"Fake packet\n";
return pHe->source;
#endif
 
}
 
int main()
{
    _CrtSetDbgFlag(33);
    const char* Ip = "213.180.204.3"; //сюда вбить пингуемый адрес, сейчас это ЯНДЕКС
        const char* IpLocal  = "тут ваш локальный адрес, для заголовка IPv4";
 
    //удаленный адрес
    SOCKADDR_IN list_adr = {0};
    list_adr.sin_addr.S_un.S_addr = inet_addr(Ip);
    list_adr.sin_family = AF_INET;
    list_adr.sin_port = htons(6666);
 
    //локальный адрес
    SOCKADDR_IN bnd = {0};
    bnd.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
    bnd.sin_family = AF_INET;
    bnd.sin_port = htons(6666);
 
    WSADATA wsd = {0};
    WSAStartup(0x202,&wsd);
 
    SOCKET listn = WSASocket(AF_INET,SOCK_RAW,IPPROTO_ICMP,0,0,WSA_FLAG_OVERLAPPED);
    bind(listn,(sockaddr*)&bnd,sizeof(bnd));
    IcmpHeader pac = {0};
    int timeout = 3000;
    setsockopt(listn,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout)); //таймаут получения
    pac.i_type = 8;
    pac.i_code = 0;
    pac.i_seq = 0x2;
    pac.i_crc =0;
    pac.i_id = (USHORT)GetCurrentProcessId();//записать в ICMP идентификатор процесса.      
    //создаем довесок из данных в 32 байта заполненый буквой Z, чтоб было похоже на настоящее
    int size = sizeof(pac)+32;
    char* Icmp = new char [size];
    memcpy(Icmp,&pac,sizeof(pac));
    memset(Icmp+sizeof(pac),'Z',32);
 
    IcmpHeader *Packet = (IcmpHeader *)Icmp;
    Packet->i_crc = crc2((USHORT*)Packet,size);//считаем контрольную сумму пакета, заголовок+данные
    char bf [256] = {0};
    int outlent = sizeof(SOCKADDR_IN);
    SOCKADDR_IN out_ = {0};
    out_.sin_family = AF_INET;
 
 
 
#ifdef MANUAL
 
 //здесь формируем IP заголовок вручную
 // и собираем пакет наш IP+Icmp+32байта данных 
 
    int icmp_size = sizeof(pac)+32;
    size = sizeof(IpHeader)+sizeof(IcmpHeader)+32;
    int param = 1;
    setsockopt(listn,IPPROTO_IP,IP_HDRINCL,(char*)&param,sizeof(param));//сообщаем что сами слепим заголовок
    IpHeader IpHead = {0};
    IpHead.verhlen = 69;
    IpHead.ttl = 200;
    IpHead.source = inet_addr(IpLocal );
    IpHead.destination = inet_addr(Ip);
    IpHead.totallent = size-icmp_size;
    IpHead.proto = 1;
    char* FullPack = new char [size];
 
    memcpy(FullPack,&IpHead,sizeof(IpHeader));
    memcpy(FullPack+sizeof(IpHeader),Packet,icmp_size);
 
 
    //crc IP система посчитает сама, с ним можно не париться
    //однако для ICMP расчет обязателен 
 
 
#endif
 
 
#ifdef TRACERT
 
    unsigned int control = list_adr.sin_addr.S_un.S_addr; 
 
    cout<<"TRACE route to >>> "<<Ip<<" with 20 hops\n";
    for(int i=1;i<=20;++i)
    {
#ifdef MANUAL
        IpHeader* ipH = (IpHeader*)PACKET_;
        ipH->ttl = i;
#else
        setsockopt(listn,IPPROTO_IP,IP_TTL,(char*)&i,4);
#endif
        int bytes =sendto(listn,(char*)PACKET_,size,0,(sockaddr*)&list_adr,sizeof(list_adr));
        Sleep(1000);
 
        if(recvfrom(listn,bf,256,0,(sockaddr*)&out_,&outlent)==SOCKET_ERROR)
        {
            
            if(WSAGetLastError()==WSAETIMEDOUT)
            {
                cout<<"Request timeout\n";
                continue;
            }
        }   
        cout<<i<<" ";
        if(analize(bf,&out_)==control)break;
        memset(bf,0,0);
 
    }
 
#else
   //ПИНГИ
    cout<<"Pinging address >) "<<Ip<<"\n";
    
    for(int i = 0;i<4; ++i)
    {
    int bytes =sendto(listn,(char*)PACKET_,size,0,(sockaddr*)&list_adr,sizeof(list_adr));
    Sleep(1000);
 
    if(recvfrom(listn,bf,256,0,(sockaddr*)&out_,&outlent)==SOCKET_ERROR)
    {
        if(WSAGetLastError()==WSAETIMEDOUT)
        {
            cout<<"Request timeout\n";
            continue;
        }
    }
    analize(bf,&out_);
    memset(bf,0,0);
    }
#endif
 
    delete [] Icmp;
#ifdef MANUAL 
    delete [] FullPack;
#endif
 
    cout<<"COMLETE\n";
    closesocket(listn);
    WSACleanup();
 
    system("Pause");
return 0;
}
