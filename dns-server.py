import socket

class DNSHeader:
    def __init__(self, id, qr = 1, opcode = 0, aa = 0, tc = 0, rd=0, ra = 0, z = 0, rcode=0, qdcount=0, ancount=0, nscount=0, arcount=0):
        """
        Bytes 0-1: ID (16 bits)
        Byte 2   : Flags (QR | Opcode (4) | AA | TC | RD)   ← we'll call this `byte3` in the code
        Byte 3   : Flags (RA | Z (3) | RCODE (4))           ← `byte4` in the code
        Bytes 4-5 : QDCOUNT (16 bits)
        Bytes 6-7 : ANCOUNT (16 bits)
        Bytes 8-9 : NSCOUNT (16 bits)
        Bytes 10-11: ARCOUNT (16 bits)
        """
        
        self.id = id            # 16 bits: Packet identifier
        self.qr = qr            # 1 bit: Query/Response
        self.opcode = opcode    # 4 bits: Operation Code
        self.aa = aa            # 1 bit: Authoritative Answer
        self.tc = tc            # 1 bit: Truncation 
        self.rd = rd            # 1 bit: Recursive Desired 
        self.ra = ra            # 1 bit: Recursive available
        self.z = z              # 3 bits: Reserved 
        self.rcode = rcode      # 4 bits: Response code
        self.qdcount = qdcount  # 16 bits: Question Count
        self.ancount = ancount  # 16 bits: Answer record count
        self.nscount  = nscount # 16 bits: Authority Record Count
        self.arcount = arcount  # 16 bits: Additional Record Count  
    
    def pack(self):
        # The header is 12 bytes = 96 bits long. We build it piece-by-piece
        packed_header = b''
        # ID: 16 bits = 2 bytes 
        packed_header += self.id.to_bytes(2, 'big')
        # Byte 3: from qr to rd
        byte_3 =  (self.qr << 7)+ (self.opcode << 3)+(self.aa << 2)+ (self.tc << 1)+ self.rd
        packed_header += byte_3.to_bytes(1, 'big')
        # Byte 4: from ra to rcode 
        byte_4 = (self.ra << 7)+ (self.z << 4)+ self.rcode
        packed_header += byte_4.to_bytes(1, 'big')
        packed_header += self.qdcount.to_bytes(1, 'big')
        packed_header += self.ancount.to_bytes(1, 'big')
        packed_header += self.nscount.to_bytes(1, 'big')
        packed_header += self.arcount.to_bytes(1, 'big')
        
        return packed_header

   
class DNSQuestion:
    def __init__(self, name, type, q_class):
        self.name = name # Domain name as a string
        self.type = type # 1 for A record (IPv4)
        self.q_class = q_class # 1 for IN (internet)
    def pack(self):
        packed_question = b""
        packed_question += encode_domain_name(self.name)
        packed_question += self.type.to_bytes(2, 'big')
        packed_question += self.q_class.to_bytes(2, 'big')
        return packed_question
        

def main():
    print("Logs from your program will appear here.")
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    print("UDP server is listening on port 2053...")
    while True:
        try:
            buf, source_address = udp_socket.recvfrom(512)
            print(f"Received {len(buf)} bytes from {source_address}")
            header = DNSHeader(id = 1234, qr=1, rcode=1)
            question = DNSQuestion(name="codecrafters.io", type=1, q_class=1)
            
            response = header.pack() + question.pack()
            udp_socket.sendto(response, source_address)
            print(f"Sent {len(response)} bytes to {source_address}")
        except Exception as e:
            print(f"An error occurred: {e}")
            break 
# A helper function to encode the domain name
def encode_domain_name(domain_name):
     encoded = b""
     for label in domain_name.split('.'):
         encoded += len(label).to_bytes(1, 'big')
         encoded += label.encode('utf-8')
     encoded += b'\x00'
     return encoded 

if __name__ == "__main__":
    main()