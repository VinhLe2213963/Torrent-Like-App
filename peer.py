import os
import random
import socket
import threading
from urllib.parse import urlencode


import bencodepy
from torf import Torrent
from util import (
    BLOCK_SIZE,
    BUFFER_SIZE,
    PIECE_SIZE,
    MessageType,
    create_torrent_file,
    find_file_and_offset,
    get_ip_address,
    zip_folder_with_name,
)

bc = bencodepy.Bencode(encoding="utf-8")


class Peer:
    def __init__(self, id, ip, port, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port

        self.peer_port = port

        self.ip = ip
        self.id = id

        self.running = True

        self.lock = threading.Lock()

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_socket.bind((self.ip, self.peer_port))

        self.files = {}

    @property
    def file_path(self):
        file_path = "files-" + self.id
        os.makedirs(file_path, exist_ok=True)
        file_path += "/"
        return file_path

    def init_folder(self):
        file_path = self.file_path
        for file in os.listdir(file_path):
            if file.endswith(".torrent"):
                continue
            path = os.path.join(file_path, file)
            tracker_url = f"http://{self.server_ip}:{self.server_port}/announce"
            torrent_file = create_torrent_file(path, tracker_url, file_path)
            torrent = Torrent.read(torrent_file)
            self.files[torrent.infohash] = {
                "path": path,
                "torrent": torrent,
                "pieces": [True for _ in range(torrent.pieces)],
            }

    def start(self):
        self.running = True
        self.init_folder()
        server_thread = threading.Thread(target=self.connect_server)
        server_thread.start()
        peer_thread = threading.Thread(target=self.listen_peer)
        peer_thread.start()

    def stop(self):
        message = {
            "id": MessageType.CLOSE.value,
            "peer_ip": self.ip,
            "peer_port": self.peer_port,
        }
        self.send_message(self.server_socket, message)
        self.running = False
        self.server_socket.close()
        self.peer_socket.close()
        print("Stopped the peer")

    def parse_message(self, message):
        return bc.decode(message)

    def send_message(self, sock, message):
        bencoded_message = bc.encode(message)
        sock.send(bencoded_message)

    def send_block(self, sock, message):
        bencoded_message = bencodepy.encode(message)
        sock.send(bencoded_message)

    def parse_block(self, message):
        return bencodepy.decode(message)

    def connect_server(self):
        try:
            self.server_socket.connect((self.server_ip, self.server_port))
        except Exception as e:
            print(f"An error occured while trying to connect to the server: {e}")
            self.stop()
            return

        while self.running:
            continue

    def upload(self, filename):
        torrent = Torrent.read(filename)
        infohash = torrent.infohash
        message = {
            "id": MessageType.UPLOAD.value,
            "infohash": infohash,
            "peer_id": self.id,
            "peer_port": self.peer_port,
            "peer_ip": self.ip,
        }

        self.send_message(self.server_socket, message)
        response = self.server_socket.recv(BUFFER_SIZE)
        print(f"Received response from server: {bc.decode(response)}")

    def get_peers(self, filename):
        torrent = Torrent.read(filename)
        infohash = torrent.infohash
        message = {
            "id": MessageType.GET_PEERS.value,
            "infohash": infohash,
            "peer_id": self.id,
        }

        self.send_message(self.server_socket, message)
        response = self.server_socket.recv(BUFFER_SIZE)
        decoded_response = self.parse_message(response)
        if "failure reason" in decoded_response:
            print(f"Failed to get peers: {decoded_response['failure reason']}")
            return
        print(f"Received response from server: {decoded_response}")
        return decoded_response["payload"]

    def listen_peer(self):
        self.peer_socket.listen(10)
        print(f"Start listening for peers on {self.ip}:{self.peer_port}")

        while self.running:
            try:
                peer_conn, peer_addr = self.peer_socket.accept()
                handle_peer = threading.Thread(
                    target=self.handle_peer, args=(peer_conn, peer_addr)
                )
                handle_peer.start()
            except Exception as e:
                print(f"An error occured while accepting a peer connection: {e}")

        self.peer_socket.close()
        print(f"Stopped listening for peers on {self.ip}:{self.peer_port}")

    def handle_peer(self, peer_conn, peer_addr):
        print(f"Handling peer connection from {peer_addr}")

        while self.running:
            try:
                message = peer_conn.recv(BUFFER_SIZE)
            except Exception as e:
                print(f"An error occured while receiving a message from peer: {e}")

            if not message:
                continue

            try:
                message = self.parse_message(message)
            except Exception as e:
                print(f"An error occured while parsing a message from peer: {e}")

            if message["id"] == MessageType.CLOSE.value:
                break
            elif message["id"] == MessageType.HANDSHAKE.value:
                self.handle_handshake(peer_conn, message)
            elif message["id"] == MessageType.INTERESTED.value:
                self.handle_interested(peer_conn)
            elif message["id"] == MessageType.REQUEST.value:
                infohash = message["infohash"]
                piece_idx = message["piece_index"]
                block_begin = message["block_begin"]
                block_length = message["block_length"]
                self.handle_download_piece(
                    peer_conn, infohash, piece_idx, block_begin, block_length
                )

        peer_conn.close()

    def handle_handshake(self, peer_conn, handshake_res):
        print("Handling handshake from peer")
        # print(f"Received handshake from peer: {handshake_res}")
        infohash = handshake_res["payload"][29:69]
        peer_id = handshake_res["payload"][69:]
        print(f"Peer infohash: {infohash}, peer id: {peer_id}")
        bitfield_res = {}
        if infohash not in self.files:
            bitfield_res = {
                "id": MessageType.BITFIELD.value,
                "payload": [],
            }
        else:
            bitfield_res = {
                "id": MessageType.BITFIELD.value,
                "payload": self.files[infohash]["pieces"],
            }
        self.send_message(peer_conn, bitfield_res)

    def handle_interested(self, peer_conn):
        print("Handling interested from peer")
        unchoke_res = {
            "id": MessageType.UNCHOKE.value,
            "payload": "Unchoke successful",
        }
        self.send_message(peer_conn, unchoke_res)
    
    def handle_download_piece(
        self, peer_conn, infohash, piece_idx, block_begin, block_length
    ):
        print("Handling download piece from peer")
        try:
            file_path = self.files[infohash]["path"]
            torrent = self.files[infohash]["torrent"]
            offset = piece_idx * torrent.metainfo["info"]["piece length"] + block_begin
            if "files" in torrent.metainfo["info"]:
                files = []
                for file in torrent.metainfo["info"]["files"]:
                    files.append({
                        "length": file["length"], 
                        "path": os.path.join(file_path, *file["path"])
                    })
                piece_offset = piece_idx * PIECE_SIZE + block_begin
                file_index, offset = find_file_and_offset(files, piece_offset)
                if file_index is None:
                    return None
                
                block_data = b""
                while len(block_data) < block_length and file_index < len(files):
                    file = files[file_index]
                    with open(file["path"], "rb") as f:
                        f.seek(offset)
                        block_data += f.read(min(block_length - len(block_data), file["length"] - offset))
                    offset = 0
                    file_index += 1
                response_res = {
                    "id": MessageType.RESPONSE.value,
                    "payload": block_data,
                }
                self.send_block(peer_conn, response_res)
                return
            else:
                with open(file_path, "rb") as file:
                    file.seek(offset)
                    payload = file.read(block_length)
                    response_res = {
                        "id": MessageType.RESPONSE.value,
                        "payload": payload,
                    }
                    self.send_block(peer_conn, response_res)
        except Exception as e:
            print(f"An error occured while handling download piece: {e}")
            return

    def download(self, filename):
        peers = self.get_peers(filename)
        if not peers:
            return
        torrent = Torrent.read(filename)
        total_pieces = torrent.pieces
        print(f"Total pieces: {total_pieces}")
        pieces_count = [{} for _ in range(total_pieces)]
        for peer in peers:
            peer_ip = peer[1]
            peer_port = peer[2]
            pieces_of_peer = self.get_pieces(peer_ip, peer_port, torrent)
            print(f"Peer {peer_ip}:{peer_port} has pieces: {pieces_of_peer}")
            for i in range(total_pieces):
                print(f"Checking piece {i}")
                piece = pieces_of_peer[i]
                if piece == False:
                    continue

                pieces_count[i] = {
                    "count": pieces_count[i].get("count", 0) + 1,
                    "piece_idx": i,
                    "peer": (
                        [] if "peer" not in pieces_count[i] else pieces_count[i]["peer"]
                    ),
                }
                pieces_count[i]["peer"].append((peer_ip, peer_port))

        pieces_count = sorted(pieces_count, key=lambda x: x.get("count", 0))
        self.files[torrent.infohash] = {
            "path": self.file_path + torrent.metainfo["info"]["name"],
            "torrent": torrent,
            "pieces": [False for _ in range(total_pieces)],
        }
        pieces_of_file = []
        
        def threaded_download_piece(piece, infohash, pieces_of_file):
            if piece["count"] == 0:
                return
            
            for i in range(len(piece["peer"])):
                if self.files[infohash]["pieces"][piece["piece_idx"]]:
                    break
                peer_ip, peer_port = piece["peer"][i]

                f = self.download_piece(peer_ip, peer_port, torrent, piece["piece_idx"])
                if not f:
                    continue
                with self.lock:
                    pieces_of_file.append(f)
                    self.files[infohash]["pieces"][piece["piece_idx"]] = True
        
        threads = []     
        for piece in pieces_count:
            thread = threading.Thread(target=threaded_download_piece, args=(piece, torrent.infohash, pieces_of_file))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()

        if len(pieces_of_file) < total_pieces:
            print("Download did not complete")
            return
        
        sorted_pieces = sorted(pieces_of_file)
        
        if "files" in torrent.metainfo["info"]:
            files = []
            for file in torrent.metainfo["info"]["files"]:
                files.append({
                    "length": file["length"], 
                    "path": os.path.join(self.file_path + torrent.metainfo["info"]["name"], *file["path"])
                })
            folder_path = self.file_path
            index, buffer = 0, b""
            for file in files:
                
                file_length, file_path = file["length"], file["path"]
                if not os.path.exists(os.path.dirname(file_path)):
                    os.makedirs(os.path.dirname(file_path))
                while len(buffer) < file_length:
                    piece_path = sorted_pieces[index]
                    with open(piece_path, "rb") as piece_file:
                        data = piece_file.read()
                        buffer += data
                    os.remove(piece_path)
                    index += 1
                with open(file_path, "ab") as f:
                    f.write(buffer[:file_length])

                # Update the buffer to contain the remainder
                buffer = buffer[file_length:]
            print(f"Downloaded {filename} successfully")
        else:
            folder_path = self.file_path
            path = folder_path + torrent.metainfo["info"]["name"]
            with open(path, "wb") as outfile:
                for piece in sorted_pieces:
                    with open(piece, "rb") as infile:
                        outfile.write(infile.read())
                    os.remove(piece)
            print(f"Downloaded {filename} successfully")
            self.upload(filename)

    def get_pieces(self, peer_ip, peer_port, torrent: Torrent):
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((peer_ip, peer_port))
        except Exception as e:
            print(f"An error occured while trying to connect to the peer: {e}")
            return

        self.handshake(torrent, peer_socket)

        try:
            bitfield_res = peer_socket.recv(BUFFER_SIZE)
            bitfield_res = self.parse_message(bitfield_res)
            assert bitfield_res["id"] == MessageType.BITFIELD.value
            if bitfield_res["payload"] == []:
                print("Peer does not have any pieces")
                peer_socket.close()
                return
            return bitfield_res["payload"]
        except Exception as e:
            print(f"An error occured while trying to receive bitfield from peer: {e}")
            peer_socket.close()
            return

    def download_piece(self, peer_ip, peer_port, torrent: Torrent, piece_idx):
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((peer_ip, peer_port))
        except Exception as e:
            print(f"An error occured while trying to connect to the peer: {e}")
            return

        try:
            interested_message = {
                "id": MessageType.INTERESTED.value,
            }
            self.send_message(peer_socket, interested_message)

            unchoke_res = peer_socket.recv(BUFFER_SIZE)
            unchoke_res = self.parse_message(unchoke_res)
            assert unchoke_res["id"] == MessageType.UNCHOKE.value
        except Exception as e:
            print(
                f"An error occured while trying to receive interested unchoke from peer: {e}"
            )
            peer_socket.close()
            return

        try:
            total_pieces = torrent.pieces
            piece_size = 0
            
            if piece_idx < total_pieces - 1:
                piece_size = torrent.metainfo["info"]["piece length"]
            elif "length" in torrent.metainfo["info"]:
                piece_size = torrent.metainfo["info"]["length"] % torrent.metainfo["info"]["piece length"]
            else:
                total_length = sum([file["length"] for file in torrent.metainfo["info"]["files"]])
                piece_size = total_length % torrent.metainfo["info"]["piece length"]   
                
            total_blocks = piece_size // BLOCK_SIZE
            folder_path = self.file_path
            file_path = (
                folder_path
                + torrent.metainfo["info"]["name"]
                + ".piece"
                + str(piece_idx)
            )
            output_file = open(file_path, "wb")
            for block_idx in range(total_blocks):
                request_message = {
                    "id": MessageType.REQUEST.value,
                    "infohash": torrent.infohash,
                    "piece_index": piece_idx,
                    "block_begin": block_idx * BLOCK_SIZE,
                    "block_length": BLOCK_SIZE,
                }
                self.send_message(peer_socket, request_message)

                try:
                    request_res = peer_socket.recv(BLOCK_SIZE * 2)
                    request_res = self.parse_block(request_res)
                    assert request_res[b"id"] == MessageType.RESPONSE.value
                    output_file.write(request_res[b"payload"])
                except Exception as e:
                    print(
                        f"An error occured while trying to receive block {block_idx * BLOCK_SIZE} from peer: {e}"
                    )
                    peer_socket.close()
                    return
            last_block_size = piece_size % BLOCK_SIZE
            if last_block_size:
                request_message = {
                    "id": MessageType.REQUEST.value,
                    "infohash": torrent.infohash,
                    "piece_index": piece_idx,
                    "block_begin": total_blocks * BLOCK_SIZE,
                    "block_length": last_block_size,
                }
                self.send_message(peer_socket, request_message)

                try:
                    request_res = peer_socket.recv(BLOCK_SIZE * 2)
                    request_res = self.parse_block(request_res)
                    assert request_res[b"id"] == MessageType.RESPONSE.value
                    output_file.write(request_res[b"payload"])
                except Exception as e:
                    print(
                        f"An error occured while trying to receive the last block from peer: {e}"
                    )
                    peer_socket.close()
                    return

            output_file.close()
            print(f"Downloaded piece {piece_idx} from peer {peer_ip}:{peer_port}")
            return file_path
        except Exception as e:
            print(
                f"An error occured while trying to download piece {piece_idx} from peer: {e}"
            )
            peer_socket.close()
            return

    def handshake(self, torrent: Torrent, peer_socket):
        pstrlen = "19"
        pstr = "BitTorrent protocol"
        reserved = "0" * 8
        infohash = torrent.infohash
        peer_id = self.id
        handshake = pstrlen + pstr + reserved + infohash + peer_id
        message = {
            "id": MessageType.HANDSHAKE.value,
            "payload": handshake,
        }
        self.send_message(peer_socket, message)


def main():
    id = "-PC000" + input("Enter the peer id: ") + "-"
    peer_port = random.randint(10000, 20000)
    peer_ip = get_ip_address()
    server_ip = "10.0.115.64"
    server_port = 22396
    peer = Peer(id, peer_ip, peer_port, server_ip, server_port)

    peer.start()

    threads = []
    while True:
        command = input("Enter a command: ")
        if command == "stop":
            peer.stop()
            break
        elif command == "upload":
            filename = input("Enter the filename: ")
            if not filename.endswith(".torrent"):
                print("Must be a .torrent file")
                continue
            upload_thread = threading.Thread(target=peer.upload, args=(filename,))
            threads.append(upload_thread)
            upload_thread.start()
        elif command == "peers":
            filename = input("Enter the filename: ")
            if not filename.endswith(".torrent"):
                print("Must be a .torrent file")
                continue
            get_peer_thread = threading.Thread(target=peer.get_peers, args=(filename,))
            threads.append(get_peer_thread)
            get_peer_thread.start()
        elif command == "download_piece":
            filename = input("Enter the filename: ")
            peer_ip = input("Enter the peer ip: ")
            peer_port = int(input("Enter the peer port: "))
            torrent = Torrent.read(filename)
            piece_idx = int(input("Enter the piece index: "))
            if not filename.endswith(".torrent"):
                print("Must be a .torrent file")
                continue
            download_piece_thread = threading.Thread(
                target=peer.download_piece,
                args=(peer_ip, peer_port, torrent, piece_idx),
            )
            threads.append(download_piece_thread)
            download_piece_thread.start()
        elif command == "download":
            filename = input("Enter the filename: ")
            if not filename.endswith(".torrent"):
                print("Must be a .torrent file")
                continue
            download_thread = threading.Thread(target=peer.download, args=(filename,))
            threads.append(download_thread)
            download_thread.start()


def test():
    torrent = Torrent.read("multi.torrent")
    files = []
    for path in torrent.metainfo["info"]["files"]:
        files.append({
            "length": path["length"], 
            "path": os.path.join("files", *path["path"])
        })
    print(torrent.metainfo["info"]["files"])


main()
