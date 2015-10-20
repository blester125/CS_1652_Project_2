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
#include "tcp.h"
#include "ip.h"

using namespace std;

enum TYPE {
  SYN,
  SYNACK,
  ACK
};

void handle_packet(MinetHandle &mux, MinetHandle &sock, 
                     ConnectionList<TCPState> &clist);
void handle_sock(MinetHandle &mux, MinetHandle &sock, 
                   ConnectionList<TCPState> &clist);
void make_packet(Packet &p, ConnectionToStateMapping<TCPState> &CTSM, 
                   TYPE HeaderType, int size, bool isTimeout);

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
  cerr << "tcp_module Part A VERSION handling tcp traffic.......\n";
  MinetSendToMonitor(MinetMonitoringEvent("tcp_module Part A VERSION handling tcp traffic........"));

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
  cerr << "\n~~~~~~~~~~~~~~~STARTING HANDLE PACKET~~~~~~~~~~~~~~~\n";
  Packet p;
  MinetReceive(mux, p);
  unsigned short len;
  len = TCPHeader::EstimateTCPHeaderLength(p);
  p.ExtractHeaderFromPayload<TCPHeader>(len);
  TCPHeader tcph;
  tcph = p.FindHeader(Headers::TCPHeader);
  IPHeader iph;
  iph = p.FindHeader(Headers::IPHeader);
  //Testing Make Packet
  /*
  Connection conn;
  conn.src = "192.168.1.1";
  conn.dest = "192.169.122.1";
  conn.destport = 5050;
  conn.srcport = 5050;
  ConnectionToStateMapping<TCPState> CTSM(conn, Time(0.0), TCPState(), false);
  make_packet(p, CTSM, SYN, 0, false);
  */
}

void handle_sock(MinetHandle &mux, MinetHandle &sock, 
                   ConnectionList<TCPState> &clist) {
  SockRequestResponse req;
  MinetReceive(sock, req);
  Packet p;
  ConnectionList<TCPState>::iterator iter = clist.FindMatching(req.connection);
  if (iter == clist.end()) {
    cerr << "\nUnable to find the connection in the list.\n";
    switch (req.type) {
      case CONNECT: {
        // Active Open
        cerr << "\n~~~~~~~~~~~~~~~CONNECT CASE~~~~~~~~~~~~~~~\n";
        TCPState state(1, SYN_SENT, 5);
        ConnectionToStateMapping<TCPState> CTSM(req.connection, 
                                                  Time(), state, false);
        clist.push_back(CTSM);
        make_packet(p, CTSM, SYN, 0, false);
        MinetSend(mux, p);
        // Tell other modules?
        cerr << "\n~~~~~~~~~~~~~~~End CONNECT CASE~~~~~~~~~~~~~~~\n";
        break; 
      }
      case ACCEPT: {
        // Passive Open
        cerr << "\n~~~~~~~~~~~~~~~ACCEPT CASE~~~~~~~~~~~~~~~\n";
        TCPState state(1, LISTEN, 5);
        ConnectionToStateMapping<TCPState> CTSM(req.connection, Time(),
                                                  state, false);
        clist.push_back(CTSM);
        // Tell other modules?
        cerr << "\n~~~~~~~~~~~~~~~END ACCEPT CASE~~~~~~~~~~~~~~~\n";
        break;
      }
      case STATUS: {
        // Later
      }
      case WRITE: {
        // Later
      }
      case FORWARD: {
        // Later
      }
      case CLOSE: {
        // Later
      }
      default: {  
        break;
      }
    }
  }
  else {
    // Found an existing connection This is for later
  }
}

void make_packet(Packet &p, ConnectionToStateMapping<TCPState> &CTSM, 
                   TYPE HeaderType, int size, bool isTimeout) {
  cerr << "\n~~~~~~~~~~~~~~~MAKING PACKET~~~~~~~~~~~~~~~\n";
  unsigned char flags = 0;
  int packetsize = size + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;
  IPHeader ipheader;
  TCPHeader tcpheader;

  ipheader.SetSourceIP(CTSM.connection.src);
  ipheader.SetDestIP(CTSM.connection.dest);
  ipheader.SetTotalLength(packetsize);
  ipheader.SetProtocol(IP_PROTO_TCP);
  p.PushFrontHeader(ipheader);
  cerr << "\nIP Header: \n" << ipheader << endl;
 
  tcpheader.SetSourcePort(CTSM.connection.srcport, p);
  tcpheader.SetDestPort(CTSM.connection.destport, p);
  tcpheader.SetHeaderLen(TCP_HEADER_BASE_LENGTH, p);
  tcpheader.SetAckNum(CTSM.state.GetLastRecvd(), p);
  tcpheader.SetWinSize(CTSM.state.GetRwnd(), p);
  tcpheader.SetUrgentPtr(0, p);
  switch (HeaderType) {
    case SYN: {
      SET_SYN(flags);
      cerr << "\nSetting SYN Flags\n";
      break;
    }
    case ACK: {
      SET_ACK(flags);
      cerr << "\nSetting ACK Flags\n";
      break;
    }
    case SYNACK: {
      SET_SYN(flags);
      SET_ACK(flags);
      cerr << "\n Setting SYN and ACK Flags\n";
      break;
    }
    default: {
      break;
    }
  }
  tcpheader.SetFlags(flags, p);
  cerr << "\nTCP Header: \n" << tcpheader << endl;
  // Time out stuff changing the Seq\ACK?
  tcpheader.RecomputeChecksum(p);
  p.PushBackHeader(tcpheader);
  cerr << "\n~~~~~~~~~~~~~~~Done Making Packet~~~~~~~~~~~~~~~\n";
  p.Print(cerr); 
}
