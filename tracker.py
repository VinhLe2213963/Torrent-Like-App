import random
import socket
import threading

import bencodepy

from util import (
    BUFFER_SIZE,
    MAX_RETURN_PEERS,
    MAX_PEERS,
    MessageType,
    get_ip_address,
)


bc = bencodepy.Bencode(encoding="utf-8")


class Tracker:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.tracker_id = "-TRACKER-" + "1234"

        self.running = True

        self.files_peers = (
            {}
        )  # A dictionary of files and their list of peers having that file
        self.lock = (
            threading.Lock()
        )  # A lock to control access to the files_peers dictionary

    def start(self):
        # Create a socket
        start_thread = threading.Thread(target=self.handle_start)
        start_thread.start()

    def handle_start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.ip, self.port))
        print(f"Start listening on {self.ip}:{self.port}...")

        # Listen for upto MAX_PEERS (10) queued connections
        server_socket.listen(MAX_PEERS)

        # Handle incomming client connections
        while self.running:
            try:
                # server_socket.settimeout(1)
                client_socket, address = server_socket.accept()
                print(f"Received connection from {address}")
                threading.Thread(
                    target=self.handle_client, args=(client_socket,)
                ).start()
            # except socket.timeout:
            #     continue
            except Exception as e:
                print(f"An exception occured while handling peer {address}: {e}")

        server_socket.close()

    def stop(self):
        self.running = False
        print(f"Tracker stopped")

    def send_message(self, sock, type, peers=[]):
        message = {}
        if type == MessageType.UPLOAD:
            message = {
                "tracker_id": self.tracker_id,
                "id": MessageType.UPLOAD.value,
                "payload": "Uploaded successfully",
            }
        elif type == MessageType.GET_PEERS:
            message = {
                "tracker_id": self.tracker_id,
                "id": MessageType.GET_PEERS.value,
                "payload": peers,
            }
        elif type == MessageType.FAILED:
            message = {
                "tracker_id": self.tracker_id,
                "failure reasson": "No peers available",
            }
        bencoded_message = bc.encode(message)
        sock.send(bencoded_message)

    def parse_message(self, message):
        message = bc.decode(message)
        return message

    def handle_client(self, client_socket):
        while self.running:
            try:
                message = client_socket.recv(BUFFER_SIZE)
                message = self.parse_message(message)
                if message["id"] == MessageType.UPLOAD.value:
                    self.handle_upload(client_socket, message)
                elif message["id"] == MessageType.GET_PEERS.value:
                    self.handle_get_peers(client_socket, message)
                elif message["id"] == MessageType.CLOSE.value:
                    self.handle_close(client_socket, message)
                    client_socket.close()
                    break
            except Exception as e:
                print(f"An exception occured while handling client: {e}")

    def handle_upload(self, client_socket, message):
        with self.lock:
            try:
                infohash = message["infohash"]
                if infohash not in self.files_peers:
                    self.files_peers[infohash] = []
                peer_ip = message["peer_ip"]
                peer_port = message["peer_port"]
                peer_id = message["peer_id"]
                completed = True
                content = [peer_id, peer_ip, peer_port, completed]
                for peer in self.files_peers[infohash]:
                    if peer[1] == peer_ip and peer[2] == peer_port:
                        peer[3] = 1
                        self.send_message(client_socket, MessageType.UPLOAD)
                        return
                self.files_peers[infohash].append(content)
                print(f"Current files_peers: {self.files_peers}")
                self.send_message(client_socket, MessageType.UPLOAD)
            except Exception as e:
                print(f"An exception occured while handling upload: {e}")
                return

    def handle_get_peers(self, client_socket, message):
        with self.lock:
            try:
                infohash = message["infohash"]
                if infohash not in self.files_peers:
                    self.send_message(client_socket, MessageType.GET_PEERS)
                    return
                peers = []
                completed_peers = [
                    peer for peer in self.files_peers[infohash] if peer[3] == True
                ]
                if len(completed_peers) < MAX_RETURN_PEERS:
                    incompleted_peers = [
                        peer for peer in self.files_peers[infohash] if peer[3] == False
                    ]
                    remaining_peers = MAX_RETURN_PEERS - len(completed_peers)
                    peers = completed_peers + random.choices(
                        incompleted_peers,
                        k=min(remaining_peers, len(incompleted_peers)),
                    )
                else:
                    peers = random.choice(completed_peers, k=MAX_RETURN_PEERS)
                if len(peers) == 0:
                    self.send_message(client_socket, MessageType.FAILED)
                    return
                self.send_message(client_socket, MessageType.GET_PEERS, peers=peers)
            except Exception as e:
                print(f"An exception occured while handling get_peers command: {e}")
                return
            
    def handle_close(self, client_socket, message):
        for infohash in self.files_peers:
            for peer in self.files_peers[infohash]:
                if peer[1] == message["peer_ip"] and peer[2] == message["peer_port"]:
                    self.files_peers[infohash].remove(peer)
                    break
        print(f"Current files_peers: {self.files_peers}")
        client_socket.close()


if __name__ == "__main__":
    server_host = get_ip_address()
    server_port = 22396

    server = Tracker(server_host, server_port)

    server.start()
    while True:
        command = input("Enter a command: ")
        if command == "stop":
            server.stop()
            break
