from ast import arg
import socket
import multiprocessing as mp
import json

def handle_connection(conn: socket.socket, packets_queue: mp.Queue):
	print(f"Starting to handle connection from {conn}")
	while True:
		try:
			msg = conn.recv(4096)
			if len(msg) == 0:
				print("Client closed socket, stopping...")
				return
			packets_queue.put(json.loads(msg))
		except Exception as e:
			print(e)
			return

def drawing_process(packets_queue: mp.Queue):
	while True:
		pkt = packets_queue.get()
		print(f"Got packet {pkt}")

if __name__ == "__main__":
	s = socket.socket()
	s.bind(("127.0.0.1", 1234))
	s.listen()

	packets_queue = mp.Queue()

	mp.Process(target=drawing_process, args=(packets_queue,)).start()
	while True:
		print("Listening for connections...")
		conn: socket.socket
		address: socket.AddressInfo
		conn, address = s.accept()

		print(f"Got connection from {address} with fd {conn}, starting handler process...")
		mp.Process(target=handle_connection, args=(conn, packets_queue)).start()