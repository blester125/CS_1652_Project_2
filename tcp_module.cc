// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be 
// copied over as part of the build process

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <iostream>

#include "Minet.h"
#include "tcpstate.h"

using namespace std;

void handle_packet(MinetHandle &mux, MinetHandle &sock, 
                     ConnectionList<TCPState> &clist);
void handle_sock(MinetHandle &mux, MinetHandle &sock, 
                     ConnectionList<TCPState> &clist);

//struct TCPState {
    // need to write this
  //  std::ostream & Print(std::ostream &os) const { 
    //  os << "TCPState()" ; 
      //return os;
    //}
//};

int main(int argc, char * argv[]) {
  MinetHandle mux;
  MinetHandle sock;
    
  ConnectionList<TCPState> clist;

  MinetInit(MINET_TCP_MODULE);
  mux = MinetIsModuleInConfig(MINET_IP_MUX) ?  
    MinetConnect(MINET_IP_MUX) : 
    MINET_NOHANDLE;
    
  sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? 
    MinetAccept(MINET_SOCK_MODULE) : 
    MINET_NOHANDLE;

  if ((mux == MINET_NOHANDLE) && 
    (MinetIsModuleInConfig(MINET_IP_MUX))) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));
    return -1;
  }

  if ((sock == MINET_NOHANDLE) && 
    (MinetIsModuleInConfig(MINET_SOCK_MODULE))) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));
    return -1;
  }
  cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";
  MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));

  MinetEvent event;
  double timeout = 1;
  cerr << "BUTTS\n";

  while (MinetGetNextEvent(event, timeout) == 0) {
    if ((event.eventtype == MinetEvent::Dataflow) && 
       (event.direction == MinetEvent::IN)) {
	    if (event.handle == mux) {
        // ip packet has arrived!
        handle_packet(mux, sock, clist);
	    }

      if (event.handle == sock) {
        // socket request or response has arrived
        handle_sock(mux, sock, clist);
	    }
	}

    if (event.eventtype == MinetEvent::Timeout) {
	   // timeout ! probably need to resend some packets
    }
  }

  MinetDeinit();
  return 0;
}

void handle_packet(MinetHandle &mux, MinetHandle &sock, 
                     ConnectionList<TCPState> &clist) {
  Packet p;
  MinetReceive(mux, p);
  p.Print(cerr);
  unsigned short len;
  len = TCPHeader::EstimateTCPHeaderLength(p);
  p.ExtractHeaderFromPayload<TCPHeader>(len);
  TCPHeader tcph;
  tcph = p.FindHeader(Headers::TCPHeader);
  IPHeader iph;
  iph = p.FindHeader(Headers::IPHeader);
}

void handle_sock(MinetHandle &mux, MinetHandle &sock, 
                   ConnectionList<TCPState> &clist) {
  SockRequestResponse req;
  MinetReceive(sock, req);
  switch (req.type) {
    case CONNECT:
      // Active Open
    case ACCEPT:
      // Passive Open
    case STATUS:
    case WRITE:
    case FORWARD:
    case CLOSE:
    default:  
      ;
  }
}