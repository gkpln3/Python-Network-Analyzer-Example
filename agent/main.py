from tabnanny import check
from tracemalloc import stop
import pyshark
import pyshark.packet.packet_summary
import plac
import re
import multiprocessing as mp
import signal
import sys

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

	# Only ip packets, filter packets sent from this agent to the server.
	bpf_filter = f"ip and not (dst host {server_ip} and dst port {server_port})"
	send_queue = mp.Queue()
	mp.Process(target=capture_process, args=(interface, bpf_filter, send_queue, stop_event)).start()

	while not stop_event.is_set():
		pkt = send_queue.get()
		print(pkt)
	print("After while on firt process")

def capture_process(interface: str, bpf_filter: str, send_queue: mp.Queue, stop_event: mp.Event):
	# Start the live capture.
	cap = pyshark.LiveCapture(
		interface = interface,
		only_summaries=True, 
		# Filter out packet sent to the server by this agent.
		bpf_filter=bpf_filter
	)

	pkt: pyshark.packet.packet_summary.PacketSummary
	generator = cap.sniff_continuously()
	for pkt in generator:
		send_queue.put(pkt)
	print("After while on second process")

if __name__ == "__main__":
	plac.call(main)
