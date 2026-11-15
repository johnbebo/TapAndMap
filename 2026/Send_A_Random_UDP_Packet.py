#!/usr/bin/python3

import socket
import random
import time

# Function to send a UDP packet to a random address
def send_udp_packet():
    # Generate a random IP address in the range 1.1.1.1 to 255.255.255.255
    random_ip = '.'.join(str(random.randint(1, 255)) for _ in range(4))
    
    # Random port number between 1024 and 65535
    random_port = random.randint(1024, 65535)

    # Define the message you want to send
    message = b"Hello, UDP!"

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Send the UDP packet to the random address and port
    sock.sendto(message, (random_ip, random_port))
    
    print(f"Sent packet to {random_ip}:{random_port}")
    
    # Close the socket
    sock.close()

# Call the function
send_udp_packet()
