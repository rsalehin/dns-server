# main.py
import sys
import socket
import struct

class DNSHeader:
    def __init__(self, id, qr=0, opcode=0, aa=0, tc=0, rd=0, ra=0, z=0, rcode=0, qdcount=0, ancount=0, nscount=0, arcount=0):
        self.id, self.qr, self.opcode, self.aa, self.tc, self.rd, self.ra, self.z, self.rcode = id, qr, opcode, aa, tc, rd, ra, z, rcode
        self.qdcount, self.ancount, self.nscount, self.arcount = qdcount, ancount, nscount, arcount

    @classmethod
    def unpack(cls, data):
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack('>H H HHHH', data[:12])
        qr = (flags >> 15) & 0b1; opcode = (flags >> 11) & 0b1111; aa = (flags >> 10) & 0b1
        tc = (flags >> 9) & 0b1; rd = (flags >> 8) & 0b1; ra = (flags >> 7) & 0b1
        z = (flags >> 4) & 0b111; rcode = flags & 0b1111
        return cls(id, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount)

    def pack(self):
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | (self.tc << 9) | (self.rd << 8) | \
                (self.ra << 7) | (self.z << 4) | self.rcode
        return struct.pack('>H H HHHH', self.id, flags, self.qdcount, self.ancount, self.nscount, self.arcount)

def encode_domain_name(domain_name):
    encoded = b""
    for label in domain_name.split('.'):
        encoded += len(label).to_bytes(1, 'big') + label.encode("utf-8")
    return encoded + b'\x00'

def decode_name(data, offset):
    labels = []
    while True:
        length = data[offset]; offset += 1
        if (length & 0b11000000) == 0b11000000:
            pointer_byte2 = data[offset]; offset += 1
            pointer_offset = ((length & 0b00111111) << 8) | pointer_byte2
            pointed_name, _ = decode_name(data, pointer_offset)
            labels.append(pointed_name)
            break
        if length == 0: break
        labels.append(data[offset:offset+length].decode('utf-8')); offset += length
    return ".".join(labels), offset

class DNSQuestion:
    def __init__(self, name, type, q_class):
        self.name, self.type, self.q_class = name, type, q_class
    @classmethod
    def unpack(cls, data, offset):
        name, offset = decode_name(data, offset)
        type, q_class = struct.unpack('>HH', data[offset:offset+4]); offset += 4
        return cls(name, type, q_class), offset
    def pack(self):
        return encode_domain_name(self.name) + self.type.to_bytes(2, 'big') + self.q_class.to_bytes(2, 'big')

class DNSAnswer:
    def __init__(self, name, type, a_class, ttl, data):
        self.name, self.type, self.a_class, self.ttl, self.data = name, type, a_class, ttl, data
    def pack(self):
        packed = encode_domain_name(self.name)
        packed += struct.pack('>HHIH', self.type, self.a_class, self.ttl, len(self.data))
        packed += self.data
        return packed

def forward_request(request_packet, resolver_address):
    forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        forward_socket.sendto(request_packet, resolver_address)
        response, _ = forward_socket.recvfrom(512)
        return response
    finally:
        forward_socket.close()

def main():
    resolver_address = None
    if len(sys.argv) > 2 and sys.argv[1] == '--resolver':
        ip, port = sys.argv[2].split(':')
        resolver_address = (ip, int(port))
        print(f"DNS server will forward queries to {resolver_address}")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    print("DNS server is listening on port 2053...")

    while True:
        try:
            buf, source_address = udp_socket.recvfrom(512)
            if not resolver_address:
                print("No resolver configured. Dropping packet.")
                continue
            
            resolver_response = forward_request(buf, resolver_address)
            udp_socket.sendto(resolver_response, source_address)
        except Exception as e:
            print(f"An error occurred: {e}")
            break

if __name__ == "__main__":
    main()