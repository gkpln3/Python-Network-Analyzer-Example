from tabnanny import check
from tracemalloc import stop
import pyshark
import pyshark.packet.packet_summary
import plac
import re
import multiprocessing as mp
import signal
import sys
import socket
import pickle
import json

def signal_handler(sig, frame):
		print('Stopping process...')
		sys.exit(0)
# Register signal to capture ctrl-c
signal.signal(signal.SIGINT, signal_handler)

def check_ip(ip):
	return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)
def check_port(port):
	try:
		port = int(port)
		return port < 2**16
	except:
		return False

def connect_to_server(server_ip, server_port):
	try:
		s = socket.socket()
		s.connect((server_ip, int(server_port)))
		return s
	except Exception as e:
		print(e)
		exit(-2)

# Placeholder to support multiprocessing, actual value is filled inside __main__
INTERFACES = []
if __name__ == "__main__":
	INTERFACES = pyshark.tshark.tshark.get_tshark_interfaces()

@plac.pos('interface', "Interface to capture from", choices=INTERFACES)
@plac.pos('server_ip', "IP address of the server")
@plac.pos('server_port', "Port on which the server runs on")
def main(interface, server_ip, server_port):
	print("Agent starting...")
	print(f"interface = {interface}")

	stop_event = mp.Event()

	if not check_ip(server_ip) or not check_port(server_port):
		print("Server IP address or port is invalid.")
		exit(-1)

	while True:
		server_socket = connect_to_server(server_ip, server_port)
		if server_socket is None:
			print("Failed connecting to remote server")
			exit(-2)

		# Only ip packets, filter packets sent from this agent to the server.
		bpf_filter = f"ip and not (dst host {server_ip} and dst port {server_port})"
		send_queue = mp.Queue()
		process = mp.Process(target=capture_process, args=(interface, bpf_filter, send_queue, stop_event, server_socket))
		process.start()
		process.join()
		print("Process exited, starting again...")


	# while not stop_event.is_set():
	# 	pkt = send_queue.get()
	# 	print(pkt)
	# print("After while on firt process")

def capture_process(interface: str, bpf_filter: str, send_queue: mp.Queue, stop_event: mp.Event, server_socket: socket.socket):
	# Start the live capture.
	cap = pyshark.LiveCapture(
		interface = interface,
		only_summaries=True, 
		# Filter out packet sent to the server by this agent.
		bpf_filter=bpf_filter
	)

	my_hostname = socket.gethostname()

	# Start sniffing...
	generator = cap.sniff_continuously()
	pkt: pyshark.packet.packet_summary.PacketSummary
	for pkt in generator:
		print("Send packet")
		serialized_pkt = json.dumps({"agent": my_hostname, "source": pkt.source, "dest": pkt.destination, "protocol": pkt.protocol})
		if len(serialized_pkt) > 4096:
			print("Error, packet is larger than 4KB")
			exit(-3)
		if server_socket.send(bytes(serialized_pkt, "utf8")) == 0:
			return
	print("After while on second process")

if __name__ == "__main__":
	plac.call(main)
