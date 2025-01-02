from CovertChannelBase import CovertChannelBase
from scapy.all import Ether, IP, UDP, DNS, DNSQR, sniff
import time
class MyCovertChannel(CovertChannelBase):
   

    def __init__(self):
        super().__init__()
        self.decoded_message = ""
        self.stop_sniffing = False

    def send(self, dst_ip, dport, sport, log_file_name):
        
        random_message = self.generate_random_message()
        binary_message = self.convert_string_message_to_binary(random_message)


        state_bit = 0

        for bit_char in binary_message:
            b = int(bit_char)
            encoded_bit = b ^ state_bit
            state_bit = 1 - state_bit

            packet = IP(dst=dst_ip) / UDP(dport=dport, sport=sport) / DNS(rd=encoded_bit)

            super().send(packet=packet)
        
    
        self.log_message(random_message, log_file_name)
    
    def receive(self, parameter1, parameter2, timeout, log_file_name):
        
        self.decoded_message = ""
        self.stop_sniffing = False
        bit_buffer = ""
        decode_state = 0

        def process_packet(pkt):
            nonlocal bit_buffer, decode_state
            if DNS in pkt:
                rd_val = pkt[DNS].rd
                recovered_bit = rd_val ^ decode_state
                decode_state = 1 - decode_state
                bit_buffer += str(recovered_bit)

                if len(bit_buffer) == 8:
                    char = self.convert_eight_bits_to_character(bit_buffer)
                    bit_buffer = ""
                    self.decoded_message += char
                    if char == ".":
                        self.stop_sniffing = True
 
        def stop_filter(_):
            return self.stop_sniffing

        sniff(
            iface=parameter1,
            filter="udp port 53",
            prn=process_packet,
            stop_filter=stop_filter,
            timeout=int(timeout) 
        )


        self.log_message(self.decoded_message, log_file_name)
