import time

from scapy.all import srp
from scapy.layers.l2 import *
import logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',  # Specify the log message format
    handlers=[logging.StreamHandler()]  # This will output the logs to the console
)

# this script will use ARP requests to identify devices in the local network
# ARP (Address Resolution Protocol) maps IP addresses of a device to their MAC Address

def create_arp_request(ip_range):
    try:
        # Creates an ARP request for a specific IP address or range (pdst)
        arp_request = ARP(pdst = ip_range)
        return arp_request
    except ValueError as v_error:
        logging.error(f"Invalid IP range provided: {ip_range}. Details: {v_error}")
        return None
    except Exception as e:
        logging.error(f"Error in creating ARP request {e}")
        return None

def send_arp_request(packet):
    result = []
    tries = 0
    while len(result) == 0 and tries < 3:
        try:
            # Send ARP request and store result
            result = srp(packet, timeout=3, verbose=False)
            if len(result) == 0:
                logging.warning("No devices responded to the ARP request.")
                tries += 1
                print(f"{3 - tries} attempts remaining")
                time.sleep(5)
        except Exception as e:
            logging.error(f"Error im sending ARP request {e}")
            tries += 1
            print(f"{3 - tries} attempts remaining")
            time.sleep(5)
            return None

    if tries >= 3 and len(result) == 0:
        logging.warning("Failed to receive a response after 3 attempts")
        return None

    return result

def process_result(result):
    try:
        if result:
            for sent, received in result:
                # Prints IP and related MAC address
                print(f"IP Address: {received.psrc} | MAC Address: {received.hwsrc}")
        else:
            print("No response received.")
    except Exception as e:
        print(f"Error in processing result: {e}")


if __name__ == "__main__":
    ip_range = "10.0.2.0/24"
    arp_request = create_arp_request(ip_range)

    if arp_request:
        ether_request = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_request / arp_request #creates complete packet by combining ARP and ethernet frame
        result = send_arp_request(packet)

        if result:
            process_result(result)
        else:
            print("No devices found.")
    else:
        print("Failed to create ARP request.")