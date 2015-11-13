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

/* void handle_timeout
 * Arguements:
 *   MinetHandle &mux: The minet mux that packets are sent out on
 *   ConnectionList<TCPState>::iterator iter: A iterator that points to the 
 *                                            connection that timed out
 *   ConnectionList<TCOState> &clist: The list of all connection.
 *
 * Returns:
 *   void
 *
 * Use:
 *   Handle a timeout event. It looks that the state of the connection that 
 *   times out and retransmits packets and adjust state variables as needed. 
 */
void handle_timeout(const MinetHandle &mux, ConnectionList<TCPState>::iterator iter, 
                      ConnectionList<TCPState> &clist); 

/* void make_packet
 * Arguments:
 *   Packet &p: The packet object that will have the headers added to it
 *   ConnectionToSateMapping<TCPState> &CTSM: The connection that the 
 *     packet is for with information that will be added to the Headers,
 *   TYPE HeaderType: The type of packet that decides what the flags 
 *     will be.
 *   int size: The size of the data that will be sent.
 *   bool isTimeout: Is this packet a timeout? If so it will change 
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

/* int send_data
 * Arguments:
 *   const MinetHandle &mux: The minet mux that packets will be sent out on.
 *   ConnectionToStateMapping<TCPState> &CTSM: The connection that the packet 
 *     if for with information that will be added to the Headers.
 *   TYPE HeaderType: The type if data that will be sent.
 *   Buffer data: A buffer full of the data that will be sent.
 *   // TOADD
 *   boolean isTimeout?
 *
 * Returns:
 *   int: returns the number of bytes send or 0 is error.
 *
 * Use:
 *   Creating and sending packets until all the data in the Buffer has been 
 *   sent.
 */
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

  cerr << "tcp_module handling tcp traffic using Go Back N.......\n";
  MinetSendToMonitor(
    MinetMonitoringEvent(
      "tcp_module handling tcp traffic using Go Back N........"));

  MinetEvent event;
  double timeout = 1;
 
  while (MinetGetNextEvent(event, timeout) == 0) {
    if ((event.eventtype == MinetEvent::Dataflow) && 
       (event.direction == MinetEvent::IN)) {
       
      cerr << "\n!~~~~~~~~~~~~~~MINET EVENT ARRIVES~~~~~~~~~~~~!\n";
      if (event.handle == mux) {
        cerr << "\ntcp_module mux packet has arrived\n";
        // ip packet has arrived!
        handle_packet(mux, sock, clist);
      }

      if (event.handle == sock) {
        // socket request or response has arrived  
        cerr << "\ntcp_module socket req or resp arrived\n";
        handle_sock(mux, sock, clist);
      }
    }

    if (event.eventtype == MinetEvent::Timeout) {
      // timeout ! probably need to resend some packets
      // Find the first connection in the list that has timedout
      ConnectionList<TCPState>::iterator iter = clist.FindEarliest();
      // If you found something
      if (iter != clist.end()) {
        // If it did time out
        if (Time().operator > ((*iter).timeout)) {
          handle_timeout(mux, iter, clist);
        }
      }
    }
  }

  MinetDeinit();
  return 0;
}

void handle_packet(MinetHandle &mux, MinetHandle &sock, 
                     ConnectionList<TCPState> &clist) {
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
  // When receiving a packet we are the dest and they are the src but our
  // view of the connection has us as the source and them as the dest.
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
    // We are a server waiting for someone to connect to us.
    case LISTEN:
        cerr << "\n--------------------LISTEN--------------------\n";
        if( IS_SYN(flag) ){
          // We received a SYN and must send a SYNACK for the 
          //three-way handshake

          //update data
          list_search->connection = conn;
          list_search->state.SetState(SYN_RCVD);
          list_search->state.last_acked = list_search->state.last_sent;
          list_search->state.SetLastRecvd(seqnum + 1);

          // Set timeout on our SYNACK
          list_search->bTmrActive = true;
          list_search->timeout=Time() + 8;

          //synack packet
          list_search->state.last_sent = list_search->state.last_sent + 1;
          make_packet(p_send, *list_search, SYNACK, 0, false);
          cerr << "\n~~~~~~~~~~~~~~~SENDING PACKET~~~~~~~~~~~~~~~~\n";
          MinetSend(mux, p_send);
        }
        cerr << "\n--------------------END LISTEN--------------------\n";
        break;
    // We are a server that sent a SYNACK and is waiting for an ACK
    case SYN_RCVD:
        cerr << "\n--------------------SYN_RCVD--------------------\n";
        if (IS_ACK(flag)) {
          // We received and ACK and the three way handshake is complete
          list_search->state.SetState(ESTABLISHED);
          list_search->state.SetLastAcked(ack);
          list_search->state.SetSendRwnd(window_size);
          list_search->state.last_sent = list_search->state.last_sent + 1;
          
          // timeout (set for out SYNACK) is turned off because we got an ACK
          list_search->bTmrActive = false;

          // Tell the other modules that the connection was created
          static SockRequestResponse * write = NULL;
          write = new SockRequestResponse(WRITE, list_search->connection, 
                                            content, 0, EOK);
          MinetSend(sock, *write);
          delete write;
          cerr << "\n Connection Established. \n";
          cerr << "\n--------------------END SYN_RCVD--------------------\n";
        }
        break;
    // We are a client and have sent a SYN packet and are waiting for an SYNACK
    case SYN_SENT:
        cerr << "\n--------------------SYN_SENT--------------------\n";
        if( (IS_SYN(flag) && IS_ACK(flag)) ){
          // We received a SYNACK and must send an ACK
          list_search->state.SetSendRwnd(window_size);
          list_search->state.SetLastRecvd(seqnum + 1);
          list_search->state.last_acked = ack;
          //make ack packet
          list_search->state.last_sent = list_search->state.last_sent + 1;
          make_packet(p_send, *list_search, ACK, 0, false);
          MinetSend(mux, p_send);
          list_search->state.SetState(ESTABLISHED);
          // We received an ACK for our SYN (in the SYNACK) so we turn off the 
          // timer set by our SYN
          list_search->bTmrActive = false;
          SockRequestResponse write (WRITE, 
                                       list_search->connection, content, 0, EOK);
          MinetSend(sock, write);

        }
      cerr << "\n--------------------END SYN_SENT--------------------\n";
      break;
    // The three way handshake is complete.
    case ESTABLISHED:
      cerr << "\n--------------------ESTABLISHED--------------------\n";
      if (IS_FIN(flag)) {
        // We receive a FIN so we start to close the connection.
        cerr << "\n~~~~~~~~~~~~RECIVED FIN~~~~~~~~~~~~\n";
        list_search->state.SetState(CLOSE_WAIT);
        list_search->state.SetLastRecvd(seqnum + 1);
        //Set a timeout for the FIN we are about to send.
        list_search->bTmrActive = true;
        list_search->timeout=Time() + 8;        
        // Send an ACK for the FIN we received
        make_packet(p_send, *list_search, ACK, 0, false);
        MinetSend(mux, p_send);
        // Send our own FIN and wait until we get an ACK.
        Packet p;
        list_search->state.SetState(LAST_ACK);
        make_packet(p, *list_search, FIN, 0, false); 
        MinetSend(mux, p);
      }
      // If there is data in the packet.
      if (IS_PSH(flag) || content_size != 0) {
        cerr << "\n------------Received Push------------\n";
        cerr << "\nRecived '" << content << "'\nSize: "<< content.GetSize() << ".\n";
        list_search->state.SetSendRwnd(window_size);
        list_search->state.last_recvd = seqnum + content.GetSize();
        // pass the data to the socket.
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
      // If the packet is an ACK
      // TODO remove data from the sendbuffer once it is ACK's
      if (IS_ACK(flag)) {
        cerr << "\n~~~~~~~~~~~~~~RECIVED ACK~~~~~~~~~~~~\n";
        // If the ack number is larger than last ack it is new
        // otherwise the ack is a duplicate
        if (ack >= list_search->state.last_acked) {
          list_search->state.last_acked = ack;
          // Turn off the timer for if there is no data in-flight
          list_search->bTmrActive = false; 
        }
        // If we have moved into LAST_ACK from this packet move to CLOSED
        // This happens when the received packet is a FINACK
        if (list_search->state.GetState() == LAST_ACK) {
          list_search->state.SetState(CLOSED);
          clist.erase(list_search); 
        }
      }
      else {
        cerr << "\nUnknown Packet\n";
      }
      break;
    // We received a FIN and sent our own FIN, waiting for an ACK
    case LAST_ACK:
      cerr << "\n~~~~~~~~~~~~~~~~~CASE LAST ACK~~~~~~~~~~~~~~~~~~~\n";
      if (IS_ACK(flag)) {
        // Got an ACK so we delete ourself from the list of connections
        cerr << "\n~~~~~~~~~~~~RECIVED ACK~~~~~~~~~~~\n";
        list_search->state.SetState(CLOSED);
        clist.erase(list_search);
      }
      break;
    // We sent the initial FIN
    case FIN_WAIT1:
      cerr << "\n~~~~~~~~~~~~~~CASE FIN_WAIT1~~~~~~~~~~~~~~~\n";
      if (IS_ACK(flag)) {
        // If we received an ACK
        cerr << "\n~~~~~~~~~~~~RECEIVED ACK~~~~~~~~~~~~\n";
        list_search->state.SetState(FIN_WAIT2);
      }
      if (IS_FIN(flag)) {
        // If we received a FINACK
        cerr << "\n~~~~~~~~~~~~RECEIVED FINACK~~~~~~~~~~~~\n";
        list_search->state.SetState(TIME_WAIT);
        list_search->state.SetLastRecvd(seqnum + 1);
        make_packet(p_send, *list_search, ACK, 0, false);
        // Set timeout for our ACK if this times out without receiving a 
        // new FIN we will close the connection.
        list_search->bTmrActive = true;
        list_search->timeout=Time() + 5; //(2*MSL_TIME_SECS);
        MinetSend(mux, p_send);
      }
      break;
    // We sent the initial FIN and received an ACK
    case FIN_WAIT2:
      cerr << "\n~~~~~~~~~~~~~~~CASE FIN_WAIT2~~~~~~~~~~~~~~\n";
      if (IS_FIN(flag)) {
        // We receive their FIN
        cerr << "\n~~~~~~~~~~~~RECEIVED FIN~~~~~~~~~~~~\n";
        list_search->state.SetState(TIME_WAIT);
        list_search->state.SetLastRecvd(seqnum + 1);
        make_packet(p_send, *list_search, ACK, 0 ,false);
        // TIME_WAIT timeout to close the connection.
        list_search->bTmrActive = true;
        list_search->timeout=Time() + 5; //(2*MSL_TIME_SECS);
        MinetSend(mux, p_send); 
      }
      break;
    // We sent the initial FIN and received their ACK and their FIN
    case TIME_WAIT:
      cerr << "\n~~~~~~~~~~~~~~~CASE TIME_WAIT~~~~~~~~~~~~~\n";
      // If we get their FIN again we resend the ACK as it must have been lost.
      if (IS_FIN(flag)) {
        cerr << "\n~~~~~~~~~~~~Received FIN AGAIN~~~~~~~~~~~~\n";
        list_search->state.SetLastRecvd(seqnum + 1);
        // We got a dup FIN so they didn't get our ACK, send it again and 
        // reset timer?
        list_search->timeout = Time() + 5;
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
      // We are a client connecting and need to send a SYN
      case CONNECT: {
        cerr << "\n~~~~~~~~~~~~~~~~~~~~CONNECT CASE~~~~~~~~~~~~~~~~~~~~\n";
        // Create the state in SYN_SENT. ISN is currently 1 should 
        // be changed to rand()
        TCPState state(1, SYN_SENT, 5);
        // Create a Connection State Mapping and add it to the list.
        ConnectionToStateMapping<TCPState> CTSM(req.connection, 
                                                  Time()+2, state, true);
        CTSM.state.last_acked = 0;
        clist.push_back(CTSM);
        // Make the packet
        make_packet(p, CTSM, SYN, 0, false);
        
        // send the packet. The initial drop from Minet (due to no ARP entry) 
        // is handled via timeout
        iter->bTmrActive = true;
        iter->timeout=Time() + 2;
        
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
      // We are the server and wait to receive a SYN.
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
      // We received data to send.
      case WRITE: {
        cerr << "\n~~~~~~~~~~~~~~WRITE REQUEST FROM SOCK~~~~~~~~~~~~~~~\n";
        if (state == ESTABLISHED) {
          // If there is room in the Send buffer
          if (iter->state.SendBuffer.GetSize() + req.data.GetSize() 
             > iter->state.TCP_BUFFER_SIZE) {
            repl.type = STATUS;
            repl.connection = req.connection;
            repl.bytes = 0;
            repl.error = EBUF_SPACE;
            MinetSend(sock, repl);
          } else {
            Buffer copy = req.data;
            // Set timer for these sends
            iter->bTmrActive = true;
            iter->timeout=Time() + 8;
            // Send Data
            int return_value = send_data(mux, *iter, copy);  
            // If the send was successful tell the socket
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
      // We receive a close request from the socket
      case CLOSE: {
        cerr << "\n~~~~~~~~~~~~START Close CASE~~~~~~~~~~~~\n";
        if (state == ESTABLISHED) {
          // We send a FIN
          iter->state.SetState(FIN_WAIT1);
          iter->state.last_acked = iter->state.last_acked + 1;
          // Start a timeout for this FIN
          iter->bTmrActive = true;
          iter->timeout=Time() + 8;
          make_packet(p, *iter, FIN, 0, false);
          MinetSend(mux, p);
          // We tell the connection we did it.
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
      cerr << "\n Setting SYN flag \n";
      break;
    }
    case ACK: {
      SET_ACK(flags);
      cerr << "\n Setting ACK flag \n";
      break;
    }
    case SYNACK: {
      SET_SYN(flags);
      SET_ACK(flags);
      cerr << "\n Setting SYN and ACK flags\n";
      break;
    }
    case PSHACK: {
      SET_PSH(flags);
      SET_ACK(flags);
      cerr << "\n Setting PSH and ACK flags\n";
      break;
    }
    case FIN: {
      SET_FIN(flags);
      cerr << "\n Setting FIN flag \n";
      break;
    }
    case FINACK: {
      SET_FIN(flags);
      SET_ACK(flags);
      cerr << "\n Setting FIN and ACK flags \n";
      break;
    }
    case RESET: {
      SET_RST(flags);
      cerr << "\n setting RST flag \n";
      break;
    }
    default: {
      break;
    }
  }
  tcpheader.SetFlags(flags, p);

  cerr << "\nLast Acked(): " << CTSM.state.GetLastAcked() << endl;
  cerr << "\nSeqNum  +  1: " << CTSM.state.GetLastSent() + 1;

  // If this is a retransmission the sequence number is the last 
  // seq number that the other party ACK'd other wise it is the last thing you
  // sent plus 1
  // Not 100% about this
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

// TODO update for retransmissions? maybe just adjust the CTSM before calling
int send_data(const MinetHandle &mux, ConnectionToStateMapping<TCPState> &CTSM,
                 Buffer data) {
  cerr << "\n~~~~~~~~~~~Start Sending Data~~~~~~~~~~\n";
  Packet p;
  // Add the data to the send buffer
  CTSM.state.SendBuffer.AddBack(data);
  unsigned int bytes_left = data.GetSize();
  // While you haven't sent everything in the buffer
  while (bytes_left != 0) {
    // Send either the number of bytes left or the most you can
    unsigned int bytes_to_send = min(bytes_left, TCP_MAXIMUM_SEGMENT_SIZE);
    // Add the data to the packet
    p = CTSM.state.SendBuffer.Extract(0, bytes_to_send);
    // Make the packet and send it
    make_packet(p, CTSM, PSHACK, bytes_to_send, false);
    MinetSend(mux, p);
    CTSM.state.last_sent = CTSM.state.last_sent + bytes_to_send;
    // update the number of bytes left to send.
    bytes_left = bytes_left - bytes_to_send;
  }
  cerr << "\n~~~~~~~~~~~~Done Sending Data~~~~~~~~~~~~\n";
  return bytes_left;
}

void handle_timeout(const MinetHandle &mux, ConnectionList<TCPState>::iterator iter,
                      ConnectionList<TCPState> &clist) {
  cerr << "\nTime Out Occured with a connection in the list\n";
  unsigned int state = iter->state.GetState();
  Packet p;
  Buffer data;
  switch (state) {
    // If the timeout is on the original SYN packet resend it
    case SYN_SENT:
      // isTimeout is false because no ACK as occurred so far so each SYN 
      // Seq num is just the ISN
      make_packet(p, *iter, SYN, 0, false);
      MinetSend(mux, p);
      break;
    // Time out as a server after getting a SYN and sending our SYNACK 
    case SYN_RCVD:
      // Resend SYNACK
      make_packet(p, *iter, SYNACK, 0, true);
      MinetSend(mux, p);
      break;
    // Time out on Data that was sent
    case ESTABLISHED:
      // resend the SendBuffer
      data = iter->state.SendBuffer;
      send_data(mux, *iter, data);
      break;
    // Timeout after our initial FIN
    case FIN_WAIT1:
    // Timeout after our FIN in response to their FIN
    case LAST_ACK:
      // Resend FIN
      make_packet(p, *iter, FIN, 0, true);
      MinetSend(mux, p);
      break;
    // Timeout after ACKing their response FIN, If this happens we 
    // Assume they got our ACK and close.
    case TIME_WAIT:
      cerr << "\n~~~~~~~~TIME WAIT ENDED~~~~~~~\n";
      iter->state.SetState(CLOSED);
      clist.erase(iter);
    default:
      break;
  }
} 
