# main.py
import socket
import struct # Import the struct module

class DNSHeader:
    def __init__(self, id, qr=1, opcode=0, aa=0, tc=0, rd=0, ra=0, z=0, rcode=0, qdcount=0, ancount=0, nscount=0, arcount=0):
        self.id, self.qr, self.opcode, self.aa, self.tc, self.rd, self.ra, self.z, self.rcode = id, qr, opcode, aa, tc, rd, ra, z, rcode
        self.qdcount, self.ancount, self.nscount, self.arcount = qdcount, ancount, nscount, arcount

    @classmethod
    def unpack(cls, data):
        # Unpack the first 12 bytes of the data using struct
        # > denotes big-endian, H is for unsigned short (2 bytes), B is for unsigned char (1 byte)
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack('>H H HHHH', data[:12])
        
        # Extract individual flags from the 16-bit flags field using bitwise operations
        qr = (flags >> 15) & 0b1
        opcode = (flags >> 11) & 0b1111
        aa = (flags >> 10) & 0b1
        tc = (flags >> 9) & 0b1
        rd = (flags >> 8) & 0b1
        ra = (flags >> 7) & 0b1
        z = (flags >> 4) & 0b111
        rcode = flags & 0b1111
        
        return cls(id, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount)

    def pack(self):
        # We need to pack the flags back into a single 2-byte integer
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | (self.tc << 9) | (self.rd << 8) | \
                (self.ra << 7) | (self.z << 4) | self.rcode
        
        packed_header = struct.pack('>H H HHHH', self.id, flags, self.qdcount, self.ancount, self.nscount, self.arcount)
        return packed_header

def encode_domain_name(domain_name):
    encoded = b""
    for label in domain_name.split('.'):
        encoded += len(label).to_bytes(1, 'big')
        encoded += label.encode("utf-8")
    encoded += b'\x00'
    return encoded

class DNSQuestion:
    def __init__(self, name, type, q_class):
        self.name, self.type, self.q_class = name, type, q_class
    def pack(self):
        return encode_domain_name(self.name) + self.type.to_bytes(2, 'big') + self.q_class.to_bytes(2, 'big')

class DNSAnswer:
    def __init__(self, name, type, a_class, ttl, data):
        self.name, self.type, self.a_class, self.ttl, self.data = name, type, a_class, ttl, data
    def pack(self):
        return encode_domain_name(self.name) + self.type.to_bytes(2, 'big') + self.a_class.to_bytes(2, 'big') + \
               self.ttl.to_bytes(4, 'big') + len(self.data).to_bytes(2, 'big') + self.data

def main():
    print("Logs from your program will appear here!")
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    print("UDP server is listening on port 2053...")

    while True:
        try:
            buf, source_address = udp_socket.recvfrom(512)
            print(f"Received {len(buf)} bytes from {source_address}")

            # 1. Parse the header from the incoming request
            request_header = DNSHeader.unpack(buf)

            # 2. Determine the RCODE for the response
            response_rcode = 0 if request_header.opcode == 0 else 4

            # 3. Create the response header, MIMICKING the ID and other fields
            response_header = DNSHeader(id=request_header.id, qr=1, opcode=request_header.opcode, 
                                        rd=request_header.rd, rcode=response_rcode, qdcount=1, ancount=1)

            # For now, we still send a hardcoded question and answer
            question = DNSQuestion(name="codecrafters.io", type=1, q_class=1)
            ip_address_bytes = socket.inet_aton("8.8.8.8")
            answer = DNSAnswer(name="codecrafters.io", type=1, a_class=1, ttl=60, data=ip_address_bytes)
            
            response = response_header.pack() + question.pack() + answer.pack()
            udp_socket.sendto(response, source_address)
            print(f"Sent {len(response)} byte response to {source_address}")

        except Exception as e:
            print(f"An error occurred: {e}")
            break

if __name__ == "__main__":
    main()