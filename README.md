A functional packet sniffer built using python, existing socket programming tools and scapy that can
effectively convey protocol (TCP/UDP) behavior with packets and extracting out essential packet
information.

A basic UI created with tkinter has been utilized. The initial plan was to use streamlit for a more clean and modern looking easy UI but I had been facing threading issues and needed the packet information to display in real time which streamlit made it harder. 

The project would ideally require two users, one for sending the packet and the other for recieving and sniffing the packet. 

Common Information displayed: Source and Dest IP, TTL, Payload, Timestamp, Packet Length, IP-ID, IP-Checksum
- TCP Specific: Flag, Seq Number, Ack Number, TCP Checksum
