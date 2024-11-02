import hashlib
import logging
import os
import random
import socket
import string
from torf import Torrent
from enum import Enum

LOG = logging.getLogger("")

PEER_ID = "-PC0001-" + "".join(
    random.choice(string.ascii_lowercase + string.digits) for i in range(12)
)

PEER_ID_HASH = hashlib.sha1(PEER_ID.encode()).digest()

BLOCK_SIZE = 16 * 1024  # 10 * 1024

SERVER_HOST = "10.0.140.61"

SERVER_PORT = 22396

PIECE_SIZE = 80 * 1024  

MAX_PEERS = 10

BUFFER_SIZE = 1024

MAX_RETURN_PEERS = 5


class MessageType(Enum):
    HANDSHAKE = 1
    CLOSE = 2
    UPLOAD = 3
    DOWNLOAD = 4
    GET_PEERS = 5
    FAILED = 6
    BITFIELD = 7
    INTERESTED = 8
    UNCHOKE = 9
    REQUEST = 10
    RESPONSE = 11


FAKE_FILES_PEERS = {
    "file1": [
        {"peer": ("128.128.128.128", 1), "pieces": [1, 2]},
        {"peer": ("128.128.128.128", 2), "pieces": [1, 4]},
        {"peer": ("128.128.128.128", 3), "pieces": [1, 2, 3, 4]},
        {"peer": ("128.128.128.128", 4), "pieces": [3, 4]},
    ]
}


def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception as e:
        print(f"Exception: {e}")
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def create_torrent_file(filepath, tracker_url, destination, piece_size=PIECE_SIZE):
    torrent = Torrent(path=filepath, trackers=[tracker_url], piece_size=piece_size)
    torrent.generate()
    torrent_name = os.path.join(destination, os.path.basename(filepath) + ".torrent")
    torrent.write(torrent_name)
    return torrent_name
    