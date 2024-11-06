import hashlib
import logging
import os
import random
import shutil
import socket
import string
import zipfile
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
        s.connect(("10.255.255.255", 1))
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
    torrent.write(torrent_name, overwrite=True)
    return torrent_name


# def zip_folder(dir_name, output_filename):
#     # Creates a zip archive of the folder
#     shutil.make_archive(output_filename, 'zip', dir_name)


def zip_folder_with_name(folder_path, output_zip_path):
    folder_name = os.path.basename(folder_path)  # Get the folder's name

    with zipfile.ZipFile(output_zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                # Use relative path with folder name to keep the folder structure in the zip
                arcname = os.path.join(
                    folder_name, os.path.relpath(file_path, folder_path)
                )
                zipf.write(file_path, arcname)


def find_file_and_offset(files, global_offset):
    cumulative_offsets = [0]
    for f in files:
        cumulative_offsets.append(cumulative_offsets[-1] + f["length"])

    for i in range(len(cumulative_offsets) - 1):
        if cumulative_offsets[i] <= global_offset < cumulative_offsets[i + 1]:
            file_offset = global_offset - cumulative_offsets[i]
            return i, file_offset
    return None, None


def read_block(files, index, begin, length):
    global_offset = index * PIECE_SIZE + begin
    file_index, offset = find_file_and_offset(files, global_offset)
    if file_index is None:
        return None

    block_data = b""
    while len(block_data) < length and file_index < len(files):
        file = files[file_index]
        with open(file["path"], "rb") as f:
            f.seek(offset)
            block_data += f.read(min(length - len(block_data), file["length"] - offset))
        offset = 0
        file_index += 1

    return block_data


def combine_files(piece_source, files):
    print(f"Starting to combine files from {piece_source}")
    index, buffer = 0, b""
    for file in files:
        file_length, file_path = file["length"], file["path"]

        if not os.path.exists(os.path.dirname(file_path)):
            os.makedirs(os.path.dirname(file_path), 0o0766)

        while len(buffer) < file_length:
            piece_path = os.path.join(piece_source, f"{index}.part")
            with open(piece_path, "rb") as piece_file:
                data = piece_file.read()
                buffer += data

            os.remove(piece_path)  # Delete the piece after reading

            index += 1

        # Write the required amount to the file
        with open(file_path, "ab") as f:
            f.write(buffer[:file_length])

        # Update the buffer to contain the remainder
        buffer = buffer[file_length:]

        print(f"Finished writing {file_path}")

    os.removedirs(piece_source)  # Remove the directory after all files are written
