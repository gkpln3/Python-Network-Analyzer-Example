from tabnanny import check
import pyshark
import pyshark.packet.packet_summary
import plac
import re
import multiprocessing as mp

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

	if not check_ip(server_ip) or not check_port(server_port):
		print("Server IP address or port is invalid.")
		exit(-1)

	# Start the live capture.
	cap = pyshark.LiveCapture(
		interface = interface,
		only_summaries=True, 
		# Filter out packet sent to the server by this agent.
		bpf_filter=f"ip and not (dst host {server_ip} and dst port {server_port})"
	)

	cap.sniff(packet_count=1)

	pkt: pyshark.packet.packet_summary.PacketSummary
	for pkt in cap:
		print(pkt.source, pkt.destination)


if __name__ == "__main__":
	plac.call(main)
