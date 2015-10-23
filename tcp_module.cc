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

#define TCP_HEADER_BASE_LENGTH_IN_WORDS 5

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
       cerr << "\n~~~~~~~~~~~~~~MINET EVENT ARRIVES~~~~~~~~~~~~\n";
	    if (event.handle == mux) {
        // ip packet has arrived!
        handle_packet(mux, sock, clist);
	    }

      if (event.handle == sock) {
        // socket request or response has arrived
        MinetSendToMonitor(MinetMonitoringEvent("tcp_module socket req or resp"));
        cerr << "tcp_module socket req or resp arrived\n";
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
  //announce mux processing start
  cerr << "\n -----------handle_packet start-----------\n";

  //Receive packet from Minet
  Packet p;
  MinetReceive(mux, p);

  //Get TCP and IP headers from packet
  unsigned short len;
  len = TCPHeader::EstimateTCPHeaderLength(p);
  p.ExtractHeaderFromPayload<TCPHeader>(len);
  TCPHeader tcph;
  tcph = p.FindHeader(Headers::TCPHeader);
  IPHeader iph;
  iph = p.FindHeader(Headers::IPHeader);

  //cerr headers
  cerr << "IP Header: \n" << iph << endl;
  cerr << "----\n";
  cerr << "TCP Header: \n" << tcph << endl;
  cerr << "----\n";

  //examine checksum
  bool checksum = tcph.IsCorrectChecksum(p);
  if(!checksum){
    cerr << "Checksum is invalid! \n";
    return;
  }

  //get source/dest IPs and Ports, place in new connection
  //account for flipping of source/dest here as well
  Connection conn;
  iph.GetSourceIP(conn.dest);
  iph.GetDestIP(conn.src);
  tcph.GetSourcePort(conn.destport);
  tcph.GetDestPort(conn.srcport);
  iph.GetProtocol(conn.protocol);
  cerr << "Connection Rcvd: \n" << conn << endl;
  cerr << "----\n";

  //Get information from packet via headers
  unsigned char flag;
  unsigned int ack;
  unsigned int seqnum;
  unsigned short window_size;
  unsigned short urgent;
  unsigned char tcph_size;
  unsigned char iph_size;
  unsigned short content_size;

  tcph.GetFlags(flag);
  tcph.GetAckNum(ack);
  tcph.GetSeqNum(seqnum);
  tcph.GetWinSize(window_size);
  tcph.GetUrgentPtr(urgent);
  tcph.GetHeaderLen(tcph_size);
  iph.GetHeaderLength(iph_size);
  iph.GetTotalLength(content_size);

  cerr << "Header Flags: " << static_cast<unsigned>(flag) << endl;
  cerr << "Ack Num: " << ack << endl;
  cerr << "Seq Num: " << seqnum << endl;
  cerr << "Window Size: " << window_size << endl;
  cerr << "Urgent: " << urgent << endl;
  cerr << "TCP Header Size: " << static_cast<unsigned>(tcph_size) << endl;
  cerr << "IP Header Size: " << static_cast<unsigned>(iph_size) << endl;
  cerr << "Content Size: " << content_size << endl;
  cerr << "----\n";

  content_size = content_size - tcph_size - iph_size;

  cerr << "Packet Content Size: \n" << content_size << endl;
  cerr << "----\n";

  //Get packet content
  Buffer content;
  content = p.GetPayload().ExtractFront(content_size);

  //get state information
  unsigned int curr_state;

  ConnectionList<TCPState>::iterator list_search = clist.FindMatching(conn);

  if( list_search == clist.end() ){
    cerr << "Connection is not in the ConnectionList." << endl;
  }

  curr_state = list_search->state.GetState();

  cerr << "Current State: " << curr_state << endl;
  cerr << "----\n";

  Packet p_send;

  switch(curr_state){

    case LISTEN:
        cerr << "\n -----------LISTEN-----------\n";
        if( IS_SYN(flag) ){

          //update data
          list_search->connection = conn;
          list_search->state.SetState(SYN_RCVD);
          list_search->state.last_acked = list_search->state.last_sent;
          list_search->state.SetLastRecvd(seqnum + 1);

          // for timeout, dont need right now
          // list_search-->bTmrActive = true;
          // list_search-->timeout=Time() + 5;

          //synack packet
          list_search->state.last_sent = list_search->state.last_sent + 1;

          make_packet(p_send, *list_search, SYNACK, 0, false);
          cerr << "\n~~~~~~~~~~~~~~~SENDING PACKET~~~~~~~~~~~~~~~~\n";
          cerr << p_send << endl;
          cerr << "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
          MinetSend(mux, p_send);
          sleep(2);
          MinetSend(mux, p_send);
        }
        cerr << "\n -----------END LISTEN-----------\n";
        break;

    case SYN_RCVD:
        cerr << "\n -----------SYN_RCVD-----------\n";
        if (IS_ACK(flag)) {
          list_search->state.SetState(ESTABLISHED);
          list_search->state.SetLastAcked(ack);
          list_search->state.SetSendRwnd(window_size);
          list_search->state.last_sent = list_search->state.last_sent + 1;

          //for timeout
          // list_search-->bTmrActive = false;

          static SockRequestResponse * write = NULL;
          write = new SockRequestResponse(WRITE, list_search->connection, 
                                            content, 0, EOK);
          MinetSend(sock, *write);
          delete write;

          cerr << "\n Connection Established. \n";
          cerr << "\n -----------END SYN_RCVD-----------\n";
        }
        break;
    case SYN_SENT:
        cerr << "\n -----------SYN_SENT-----------\n";

        if( (IS_SYN(flag) && IS_ACK(flag)) ){

          list_search->state.SetSendRwnd(window_size);
          list_search->state.SetLastRecvd(seqnum + 1);
          list_search->state.last_acked = ack;

          //make ack packet
          list_search->state.last_sent = list_search->state.last_sent + 1;
          make_packet(p_send, *list_search, ACK, 0, false);

          MinetSend(mux, p_send);

          list_search->state.SetState(ESTABLISHED);

          //for timeout
          list_search->bTmrActive = false;

          SockRequestResponse write (WRITE, list_search->connection, content, 0, EOK);
          MinetSend(sock, write);

        }
      cerr << "\n -----------END SYN_RCVD-----------\n";
      break;
  }




  //show end of this packet processing
  cerr << "\n -----------handle_packet end-----------\n";
}

void handle_sock(MinetHandle &mux, MinetHandle &sock, 
                   ConnectionList<TCPState> &clist) {
  cerr << "\n~~~~~~~~~~~~~~~HANDLE SOCKET REQUEST~~~~~~~~~~~~~~~\n";
  SockRequestResponse req;
  SockRequestResponse repl;
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
                                                  Time()+2, state, true);
        clist.push_back(CTSM);
        make_packet(p, CTSM, SYN, 0, false);
        MinetSend(mux, p);
        sleep(2);
        MinetSend(mux, p);
         
        repl.type = STATUS;
        repl.connection = req.connection;
        repl.bytes = 0;
        repl.error = EOK;
        MinetSend(sock, repl);
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
        repl.type = STATUS;
        repl.bytes = 0;
        repl.connection = req.connection;
        repl.error = EOK;
        MinetSend(sock, repl);
        CTSM.Print(cerr);
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
  tcpheader.SetHeaderLen(TCP_HEADER_BASE_LENGTH_IN_WORDS, p);
  tcpheader.SetAckNum(CTSM.state.GetLastRecvd(), p);

  tcpheader.SetWinSize(CTSM.state.GetN(), p);
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
  tcpheader.SetSeqNum(CTSM.state.GetLastSent() + 1, p);
  tcpheader.RecomputeChecksum(p);
  p.PushBackHeader(tcpheader);
  cerr << "\n~~~~~~~~~~~~~~~Done Making Packet~~~~~~~~~~~~~~~\n"; 
}
