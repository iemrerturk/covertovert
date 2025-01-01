Covert Storage Channel that exploits Protocol Field Manipulation using RD Flag field in DNS [Code: CSC-PSV-DNS-RDF]

This project demonstrates a covert storage channel implemented using the DNS RD (Recursion Desired) flag. It transmits secret messages bit by bit in a way that bypasses typical communication methods. The project includes a sender that encodes and sends a random message, and a receiver that decodes the message from captured DNS packets.

How It Works

Sender

1-Generate Random Message
A 16-character random plaintext message is generated using generate_random_message.
The message is converted to binary (1s and 0s) using convert_string_message_to_binary.
2-Encode and Send Bits
Each binary bit is XOR-encoded with a state bit (state_bit) for obfuscation:
encoded_bit = 𝑏 ⊕ state_bit , state_bit = 1 − state_bit
encoded_bit=b⊕state_bit,state_bit=1−state_bit
Each encoded bit is embedded in the DNS RD flag of a packet:
packet = IP(dst=dst_ip) / UDP(dport=dport, sport=sport) / DNS(rd=encoded_bit)
The packet is sent using the super().send method.
3-Log the Sent Message
The plaintext message is logged to a file (log_file_name) for verification.


Receiver
1-Sniff DNS Packets
The receiver listens on the specified interface (parameter1) for DNS packets (udp port 53) until a timeout or the end of the message is detected.

2-Decode Bits
Each packet's RD flag is XOR-decoded using a similar decode_state:
recovered_bit = rd_val ⊕ decode_state , decode_state = 1 − decode_state
recovered_bit=rd_val⊕decode_state,decode_state=1−decode_state
Bits are collected into a buffer (bit_buffer), and every 8 bits are converted back to a character.

3-Stop on End Marker
If a . (dot) is decoded, the receiver stops capturing packets.

4-Log the Received Message
The decoded message is logged to a file (log_file_name).

Explanation of Parameters

Sender (send.parameters)
-dst_ip: The IP address of the receiver (e.g., 172.18.0.3 in this setup).
-dport: Destination port number (always 53 for DNS).
-sport: Source port number (e.g., 1234).
-log_file_name: File where the plaintext message is logged.

Receiver (receive.parameters)
-parameter1: The network interface to sniff on (e.g., eth0).
-parameter2: Currently unused but represents an additional parameter for flexibility (e.g., 1234).
-timeout: Maximum duration (in seconds) for sniffing packets (e.g., 30 seconds).
-log_file_name: File where the decoded message is logged.

Conclusion
This project demonstrates how to create a covert communication channel using the DNS protocol. By leveraging the RD flag, we transmit secret messages in a manner that mimics legitimate network traffic. While this implementation is simple, it provides a foundation for exploring more advanced covert communication techniques.

0.026