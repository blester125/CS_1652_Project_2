// CS 1652 Data Communications and Computer Networking
// University of Pittsburgh
// Brian Lester bdl20@pitt.edu
// Carmen Condeluci crc73@pitt.edu

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
#define NUM_BYTES_IN_A_WORD 4

// The type of packet that will be sent (What flags are set).
// SYN - initating a TCP connection.
// SYNACK - responding to a TCP SYN Packet.
// ACK - Acknowledging a packet was recived.
enum TYPE {
  SYN,
  SYNACK,
  ACK,
  PSHACK,
  FIN,
  FINACK,
  RESET
};

/* void handle_packet
 * Arguments:
 *   MinetHandle &mux: The minet mux that the minet Event 
 *   MinetHandle &sock: The minet socket from the minet Event
 *   ConnectionList<TCPState> &clist: Global list of all connections
 *
 * Returns: 
 *   void
 *
 * Use:
 *   Handle an incoming IP Packet that is pulled from the MinetEvent mux
 *   It extracts IP Header, TCP Header, Finds or Creates a Connection 
 *   based on the 4-tuple and acts on it.  
 */
void handle_packet(MinetHandle &mux, MinetHandle &sock, 
                     ConnectionList<TCPState> &clist);

/* void handle_sock
 * Arguments:
 *   MinetHandle &mux: The minet mux that the minet Event 
 *   MinetHandle &sock: The minet socket from the minet Event
 *   ConnectionList<TCPState> &clist: Global list of all connections
 *
 * Returns: 
 *   void
 *
 * Use:
 *   Handle an incoming Socket request from the MinetEvent sock
 *   It finds or Creates a Connection based on the request's 
 *   4-tuple and acts on it.  
 */
void handle_sock(MinetHandle &mux, MinetHandle &sock, 
                   ConnectionList<TCPState> &clist);

void handle_timeout(MinetHandle &mux, ConnectionList<TCPState>::iterator iter, 
                      ConnectionList<TCPState> &clist); 

/* void make_packet
 * Arguments:
 *   Packet &p: The packet object that will have the headers added to it
 *   ConnectionToSateMapping<TCPState> &CTSM: The connection that the 
 *     packet is for with information that will be added to the Headers,
 *   TYPE HeaderType: The type of packet that decides what the flags 
 *     will be.
 *   int size: The size of the data that will be sent.
 *   bool isTimeOut: Is this packet a timeout? If so it will change 
 *     the sequence numbers.
 *
 * Returns:
 *   void
 *
 * Output:
 *   Packet &p: The packet passed in will now include the IP and TCP 
 *     headers needed for the connection the packet is for.
 *
 * Use: 
 *   Creating the headers for a new packet that will be sent out.
 */
void make_packet(Packet &p, ConnectionToStateMapping<TCPState> &CTSM, 
                   TYPE HeaderType, int size, bool isTimeout);

int send_data(const MinetHandle &mux, ConnectionToStateMapping<TCPState> &CTSM,
                Buffer data);

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
     
     MinetSendToMonitor(
       MinetMonitoringEvent("Can't accept from sock_module"));
     return -1;
  }

  cerr << "tcp_module Part A handling tcp traffic.......\n";
  MinetSendToMonitor(
    MinetMonitoringEvent(
      "tcp_module Part A VERSION handling tcp traffic........"));

  MinetEvent event;
  double timeout = 1;
 
  while (MinetGetNextEvent(event, timeout) == 0) {
    if ((event.eventtype == MinetEvent::Dataflow) && 
       (event.direction == MinetEvent::IN)) {
       
      cerr << "\n!~~~~~~~~~~~~~~MINET EVENT ARRIVES~~~~~~~~~~~~!\n";
      if (event.handle == mux) {
        // ip packet has arrived!
        handle_packet(mux, sock, clist);
      }

      if (event.handle == sock) {
        // socket request or response has arrived  
        cerr << "tcp_module socket req or resp arrived\n";
        handle_sock(mux, sock, clist);
      }
    }

    if (event.eventtype == MinetEvent::Timeout) {
      // timeout ! probably need to resend some packets
      ConnectionList<TCPState>::iterator iter = clist.FindEarliest();
      if (cs != clist.end()) {
        if (Time().operator > ((*iter).timeout)) {
          handle_timeout(mux, iter, clist);
      }
    }
  }

  MinetDeinit();
  return 0;
}

void handle_packet(MinetHandle &mux, MinetHandle &sock, 
                     ConnectionList<TCPState> &clist) {
  // Rewrite the Order so that the prints are easier to understand. 

  //announce mux processing start
  cerr << "\n-----------------------handle_packet start-----------------------\n";

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
  cerr << "---------------\n";
  cerr << "TCP Header: \n" << tcph << endl;
  cerr << "---------------\n";

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
  cerr << "---------------\n";

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
  cerr << "---------------\n";

  content_size = (content_size - 
                   (tcph_size * NUM_BYTES_IN_A_WORD) - 
                   (iph_size * NUM_BYTES_IN_A_WORD));

  cerr << "Packet Content Size: \n" << content_size << endl;
  cerr << "---------------\n";

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
  cerr << "---------------\n";

  Packet p_send;

  switch(curr_state){

    case LISTEN:
        cerr << "\n--------------------LISTEN--------------------\n";
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
          MinetSend(mux, p_send);
          sleep(2);
          MinetSend(mux, p_send);
        }
        cerr << "\n--------------------END LISTEN--------------------\n";
        break;

    case SYN_RCVD:
        cerr << "\n--------------------SYN_RCVD--------------------\n";
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
          cerr << "\n--------------------END SYN_RCVD--------------------\n";
        }
        break;
    case SYN_SENT:
        cerr << "\n--------------------SYN_SENT--------------------\n";

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

          SockRequestResponse write (WRITE, 
                                       list_search->connection, content, 0, EOK);
          MinetSend(sock, write);

        }
      cerr << "\n--------------------END SYN_RCVD--------------------\n";
      break;
    case ESTABLISHED:
      cerr << "\n--------------------ESTABLISHED--------------------\n";
      if (IS_FIN(flag)) {
        cerr << "\n~~~~~~~~~~~~RECIVED FIN~~~~~~~~~~~~\n";
        list_search->state.SetState(CLOSE_WAIT);
        list_search->state.SetLastRecvd(seqnum + 1);
        //list_search->state.last_acked = ack;
        make_packet(p_send, *list_search, ACK, 0, false);
        MinetSend(mux, p_send);
        Packet p;
        list_search->state.SetState(LAST_ACK);
        make_packet(p, *list_search, FIN, 0, false); 
        MinetSend(mux, p);
      }
      if (IS_PSH(flag) || content_size != 0) {
        cerr << "\n------------Received Push------------\n";
        cerr << "\nRecived '" << content << "'\nSize: "<< content.GetSize() << ".\n";
        list_search->state.SetSendRwnd(window_size);
        list_search->state.last_recvd = seqnum + content.GetSize();
        //list_search->state.last_acked = ack;
        list_search->state.RecvBuffer.AddBack(content);
        SockRequestResponse write(WRITE, list_search->connection,
                                   list_search->state.RecvBuffer, 
                                   list_search->state.RecvBuffer.GetSize(), 
                                   EOK);
        MinetSend(sock, write);
        // Remove the data from the recvbuffer once passed up.
        cerr << "\n~Sent up Data:\n" << list_search->state.RecvBuffer;
        list_search->state.RecvBuffer.Clear();
        //Send ACK
        make_packet(p_send, *list_search, ACK, 0, false);
        MinetSend(mux, p_send);
        cerr << "\n------------ END PUSH -------------\n";
      }
      if (IS_ACK(flag)) {
        cerr << "\n~~~~~~~~~~~~~~RECIVED ACK~~~~~~~~~~~~\n";
        // If the ack number is larger than last ack it is new
        // otherwise the ack is a duplicate
        if (ack > list_search->state.last_acked) {
          list_search->state.last_acked = ack;
        }
        if (list_search->state.GetState() == LAST_ACK) {
          list_search->state.SetState(CLOSED);
          clist.erase(list_search); 
        }
      }
      else {
        cerr << "\nUnknown Packet\n";
      }
      break;
    case LAST_ACK:
      cerr << "\n~~~~~~~~~~~~~~~~~CASE LAST ACK~~~~~~~~~~~~~~~~~~~\n";
      if (IS_ACK(flag)) {
        cerr << "\n~~~~~~~~~~~~RECIVED ACK~~~~~~~~~~~\n";
        list_search->state.SetState(CLOSED);
        clist.erase(list_search);
      }
      break;
    case FIN_WAIT1:
      // If we sent a FIN
      cerr << "\n~~~~~~~~~~~~~~CASE FIN_WAIT1~~~~~~~~~~~~~~~\n";
      if (IS_ACK(flag)) {
        // If we recived an ACK
        cerr << "\n~~~~~~~~~~~~RECEIVED ACK~~~~~~~~~~~~\n";
        list_search->state.SetState(FIN_WAIT2);
      }
      if (IS_FIN(flag)) {
        // If we recived a FINACK
        cerr << "\n~~~~~~~~~~~~RECEIVED FINACK~~~~~~~~~~~~\n";
        list_search->state.SetState(TIME_WAIT);
        list_search->state.SetLastRecvd(seqnum + 1);
        make_packet(p_send, *list_search, ACK, 0, false);
        MinetSend(mux, p_send);
      }
      break;
    case FIN_WAIT2:
      // If we have sent a syn and recived an ACK
      cerr << "\n~~~~~~~~~~~~~~~CASE FIN_WAIT2~~~~~~~~~~~~~~\n";
      if (IS_FIN(flag)) {
        cerr << "\n~~~~~~~~~~~~RECEIVED FIN~~~~~~~~~~~~\n";
        list_search->state.SetState(TIME_WAIT);
        list_search->state.SetLastRecvd(seqnum + 1);
        make_packet(p_send, *list_search, ACK, 0 ,false);
        MinetSend(mux, p_send); 
      }
      break;
    case TIME_WAIT:
      cerr << "\n~~~~~~~~~~~~~~~CASE TIME_WAIT~~~~~~~~~~~~~\n";
      if (IS_FIN(flag)) {
        cerr << "\n~~~~~~~~~~~~Received FIN AGAIN~~~~~~~~~~~~\n";
        list_search->state.SetLastRecvd(seqnum + 1);
        make_packet(p_send, *list_search, ACK, 0 ,false);
        MinetSend(mux, p_send); 
      }
      break;
  }

  cerr << "\nNew State:\n";
  cerr << list_search->state.GetState();

  //show end of this packet processing
  cerr << "\n---------------handle_packet end---------------\n";
}

void handle_sock(MinetHandle &mux, MinetHandle &sock, 
                   ConnectionList<TCPState> &clist) {
  cerr << "\n~~~~~~~~~~~~~~~~~~~~~~~~HANDLE SOCKET REQUEST~~~~~~~~~~~~~~~~~~~~~~~\n";
  SockRequestResponse req;
  SockRequestResponse repl;
  // Recive Connection info from socket
  MinetReceive(sock, req);
  Packet p;
  // Find the connection in the golbal list
  ConnectionList<TCPState>::iterator iter;
  iter = clist.FindMatching(req.connection);
  if (iter == clist.end()) {
    cerr << "\nUnable to find the connection in the list.\n";
    // Need to create a new connection
    switch (req.type) {
      case CONNECT: {
        // Active Open
        cerr << "\n~~~~~~~~~~~~~~~~~~~~CONNECT CASE~~~~~~~~~~~~~~~~~~~~\n";
        // Create the state in SYN_SENT. ISN is currently 1 should 
        // be changed to rand()
        TCPState state(1, SYN_SENT, 5);
        // Create a Connection State Mapping and add it to the list.
        ConnectionToStateMapping<TCPState> CTSM(req.connection, 
                                                  Time()+2, state, true);
        clist.push_back(CTSM);
        // Make the packet
        make_packet(p, CTSM, SYN, 0, false);
        // Send the packet (twice in case there is not ARP entry and Minet
        // drops the packet).
        MinetSend(mux, p);
        sleep(2);
        MinetSend(mux, p);
         
        // Tell the socket that you sent the data
        repl.type = STATUS;
        repl.connection = req.connection;
        repl.bytes = 0;
        repl.error = EOK;
        MinetSend(sock, repl);
        cerr << "\n~~~~~~~~~~~~~~~Connection Created~~~~~~~~~~~~~~~\n";
        cerr << CTSM.connection << endl;
        cerr << "Current State: " << CTSM.state.GetState() << endl; 
        cerr << "\n~~~~~~~~~~~~~~~~~~~~End CONNECT CASE~~~~~~~~~~~~~~~~~~~~\n";
        break; 
      }
      case ACCEPT: {
        // Passive Open
        cerr << "\n~~~~~~~~~~~~~~~~~~~~ACCEPT CASE~~~~~~~~~~~~~~~~~~~~\n";
        // Create the state in LISTEN mode. ISN() should ne set to rand()?
        TCPState state(1, LISTEN, 5);
        // Create a connection State Mapping and add it to the list.
        ConnectionToStateMapping<TCPState> CTSM(req.connection, Time(),
                                                  state, false);
        clist.push_back(CTSM);
        // Tell the socket that you set up the connection.
        repl.type = STATUS;
        repl.bytes = 0;
        repl.connection = req.connection;
        repl.error = EOK;
        MinetSend(sock, repl);
        cerr << "\n~~~~~~~~~~~~~~~Connection Created~~~~~~~~~~~~\n";
        cerr << CTSM.connection << endl;
        cerr << "Current State: " << CTSM.state.GetState() << endl;
        cerr << "\n~~~~~~~~~~~~~~~~~~~~END ACCEPT CASE~~~~~~~~~~~~~~~~~~~~\n";
        break;
      }
      case STATUS: {
        // No action needed.
        break;
      }
      case WRITE: {
        // Can't Write to a connection that doesn't exist.
        repl.type = STATUS;
        repl.connection = req.connection;
        repl.bytes = 0;
        repl.error = ENOMATCH;
        MinetSend(sock, repl);
        break;
      }
      case FORWARD: {
        // No Action needed.
        break;
      }
      case CLOSE: {
        // Can't close a connection that doesn't exist.
        repl.type = STATUS;
        repl.connection = req.connection;
        repl.bytes = 0;
        repl.error = ENOMATCH;
        MinetSend(sock, repl);
        break;
      }
      default: {  
        break;
      }
    }
  }
  else {
    // Found an existing connection This is for later
    cerr << "\nFound existing connection in the list!" << endl;
    unsigned int state;
    state = iter->state.GetState();
    Buffer buf;
    switch (req.type) {
      case CONNECT: {
        break;
      }
      case ACCEPT: {
        // Allow a new Accept on a an old connection?
        break;
      }
      case WRITE: {
        cerr << "\n~~~~~~~~~~~~~~WRITE REQUEST FROM SOCK~~~~~~~~~~~~~~~\n";
        if (state == ESTABLISHED) {
          if (iter->state.SendBuffer.GetSize() + req.data.GetSize() 
             > iter->state.TCP_BUFFER_SIZE) {
            repl.type = STATUS;
            repl.connection = req.connection;
            repl.bytes = 0;
            repl.error = EBUF_SPACE;
            MinetSend(sock, repl);
          } else {
            Buffer copy = req.data; 
            // Send Data
            int return_value = send_data(mux, *iter, copy);  

            if (return_value == 0) {
              repl.type = STATUS;
              repl.connection = req.connection;
              repl.bytes = copy.GetSize();
              repl.error = EOK;
              MinetSend(sock, repl);    
            }
          }
        }
        cerr << "\n~~~~~~~~~~~~End Write CASE~~~~~~~~~~~~\n";
        break;   
      }
      case FORWARD: {
        // Later
        break;
      }
      case CLOSE: {
        cerr << "\n~~~~~~~~~~~~START Close CASE~~~~~~~~~~~~\n";
        if (state == ESTABLISHED) {
          iter->state.SetState(FIN_WAIT1);
          iter->state.last_acked = iter->state.last_acked + 1;
          // Can send a FINACK
          make_packet(p, *iter, FIN, 0, false);
          MinetSend(mux, p);
         
          repl.type = STATUS;
          repl.connection = req.connection;
          repl.bytes = 0;
          repl.error = EOK;
          MinetSend(sock, repl);
        }
        cerr << "\n~~~~~~~~~~~~END Close CASE~~~~~~~~~~~~\n";
        break;
      }
      case STATUS: {
        // Return Status of connection
        break;
      }
      default:
        break;
    }
  }
  cerr << "\n~~~~~~~~~~~~~~~END Handle Socket~~~~~~~~~~~~~~~\n";
}

void make_packet(Packet &p, ConnectionToStateMapping<TCPState> &CTSM, 
                   TYPE HeaderType, int size, bool isTimeout) {
  cerr << "\n~~~~~~~~~~~~~~~MAKING PACKET~~~~~~~~~~~~~~~\n";
  unsigned char flags = 0;
  int packetsize = size + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;
  IPHeader ipheader;
  TCPHeader tcpheader;

  // Set the IP Header Data
  ipheader.SetSourceIP(CTSM.connection.src);
  ipheader.SetDestIP(CTSM.connection.dest);
  ipheader.SetTotalLength(packetsize);
  ipheader.SetProtocol(IP_PROTO_TCP);
  // Add IP header to Packet
  p.PushFrontHeader(ipheader);
  cerr << "\nIP Header: \n" << ipheader << endl;
 
  // Set the TCP Header Data
  tcpheader.SetSourcePort(CTSM.connection.srcport, p);
  tcpheader.SetDestPort(CTSM.connection.destport, p);
  tcpheader.SetHeaderLen(TCP_HEADER_BASE_LENGTH_IN_WORDS, p);
  // Acknum is LastRecvd because lastRecved is set to seqnum + 1
  tcpheader.SetAckNum(CTSM.state.GetLastRecvd(), p);
  tcpheader.SetWinSize(CTSM.state.GetN(), p);
  tcpheader.SetUrgentPtr(0, p);
  
  // Set the flags
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
    case PSHACK: {
      SET_PSH(flags);
      SET_ACK(flags);
      break;
    }
    case FIN: {
      SET_FIN(flags);
      break;
    }
    case FINACK: {
      SET_FIN(flags);
      SET_ACK(flags);
      break;
    }
    case RESET: {
      SET_RST(flags);
      break;
    }
    default: {
      break;
    }
  }
  tcpheader.SetFlags(flags, p);

  // Time out stuff changing the Seq\ACK?
  if (isTimeout) {
    tcpheader.SetSeqNum(CTSM.state.GetLastAcked(), p);
  }
  else {
    tcpheader.SetSeqNum(CTSM.state.GetLastSent() + 1, p);
  }
  tcpheader.RecomputeChecksum(p);
  
  cerr << "\nTCP Header: \n" << tcpheader << endl;
  // Add TCP header behind IP header
  p.PushBackHeader(tcpheader);
  cerr << "\n~~~~~~~~~~~~~~~Done Making Packet~~~~~~~~~~~~~~~\n"; 
}

int send_data(const MinetHandle &mux, ConnectionToStateMapping<TCPState> &CTSM,
                 Buffer data) {
  cerr << "\n~~~~~~~~~~~Start Sending Data~~~~~~~~~~\n";
  Packet p;
  CTSM.state.SendBuffer.AddBack(data);
  unsigned int bytes_left = data.GetSize();
  while (bytes_left != 0) {
    unsigned int bytes_to_send = min(bytes_left, TCP_MAXIMUM_SEGMENT_SIZE);
    p = CTSM.state.SendBuffer.Extract(0, bytes_to_send);
    make_packet(p, CTSM, PSHACK, bytes_to_send, false);
    MinetSend(mux, p);
    CTSM.state.last_sent = CTSM.state.last_sent + bytes_to_send;
    bytes_left = bytes_left - bytes_to_send;
  }
  cerr << "\n~~~~~~~~~~~~Done Sending Data~~~~~~~~~~~~\n";
  return bytes_left;
}

void handle_timeout(MinetHandle &mux, ConnectionList<TCPState>::iterator iter,
                      ConnectionList<TCPState> clist) {
  unsigned int state = iter->state.GetState();
  Packet p;
  switch (state) {
    case SYN_SENT:
      // Resend SYN
      break;
    case SYN_RECVD:
      // Resend SYNACK
      break;
    case ESTABLISHED:
      // Go Back N stuff
      break;
    case LAST_ACK:
      // Resend FIN
      make_packet(p, *iter, FIN, 0, false);
      MinetSend(mux, p);
      break;
    case TIME_WAIT:
      cerr << "~~~~~~~~TIME WAIT ENDED~~~~~~~"
      iter->state.SetState(CLOSED);
      clist.erase(iter);
    default:
      break;
  }
} 
