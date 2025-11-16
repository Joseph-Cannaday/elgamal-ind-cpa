#!/usr/bin/env python3

import random
import time
import secrets
import socket
import threading
from typing import Tuple

SLEEP_TIME = 1
N_CORRECT = 20
FLAG = "tkctf{ind-cpa_is_gr8!}"

# Types
PublicKey = Tuple[int,int,int]   # (p, g, h)
PrivateKey = Tuple[int,int,int]  # (p, g, x)
Ciphertext = Tuple[int,int]      # (c1, c2)


def keygen(p: int, g: int) -> Tuple[PublicKey, PrivateKey]:
    """
    Generate ElGamal keypair for group Z_p^*.
    - p: prime modulus
    - g: generator (primitive root modulo p)
    Returns (public_key, private_key).
    public_key = (p, g, h) where h = g^x mod p
    private_key = (p, g, x)
    """
    if p <= 2:
        raise ValueError("p must be prime > 2")
    # secret exponent x in [1, p-2]
    x = secrets.randbelow(p-2) + 1
    h = pow(g, x, p)
    return (p, g, h), (p, g, x)


def encrypt(pub: PublicKey, m: int) -> Ciphertext:
    """
    ElGamal encrypt a plaintext integer m in Z_p^*.
    - pub: (p, g, h)
    - m: integer, 1 <= m <= p-1
    Returns (c1, c2).
    """
    p, g, h = pub
    if not (1 <= m <= p-1):
        raise ValueError("Message must be in 1..p-1 (Z_p^*)")
    # ephemeral r in [1, p-2]
    r = secrets.randbelow(p-2) + 1
    c1 = pow(g, r, p)
    c2 = (m * pow(h, r, p)) % p
    return c1, c2


def decrypt(priv: PrivateKey, ct: Ciphertext) -> int:
    """
    ElGamal decrypt ciphertext ct = (c1, c2).
    - priv: (p, g, x)
    Returns plaintext integer m.
    """
    p, g, x = priv
    c1, c2 = ct
    # shared secret s = c1^x mod p
    s = pow(c1, x, p)
    # multiplicative inverse of s modulo p (Fermat's little theorem)
    s_inv = pow(s, p-2, p)
    m = (c2 * s_inv) % p
    # ensure non-zero representation (if 0, map to p)
    if m == 0:
        # In Z_p^* we normally disallow 0; if result is 0, something is off.
        # But mathematically (c2 * s_inv) % p can be 0 only if c2 == 0 mod p.
        pass
    return m

def bytes_to_group_element(b, p):
    n = int.from_bytes(b, "big")
    if n >= p:
        raise ValueError("Message too large for this p")
    return n

def int_to_bytes(n):
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")

def choose_bit():
    b = random.random()
    if b < 0.5:
        return 1
    else:
        return 0

def run_game_socketed(conn):
    conn.sendall(f"Lets play a game!\nChoose the correct answer {N_CORRECT} times to win a flag!\n".encode())
    # key secrets p(safe prime) and g(its generator)
    p = 10139066926858385756187484286364701599808424881450583134737150763581531347687325747959137390370884128287547987707988989053849804317255369695920315311209841
    g = 29
    pub_key,priv_key = keygen(p,g)
    correct_answers = 0

    m0 = b""
    m1 = b""

    while len(m0) < 1 :
        try:
            conn.sendall(b"Set message 0: ")
            m0 = conn.recv(4096).strip()
            m0_enc = bytes_to_group_element(m0, p)
        except:
            pass
    
    while len(m1) < 1:
        try:
            conn.sendall(b"Set message 1: ")
            m1 = conn.recv(4096).strip()
            m1_enc = bytes_to_group_element(m1, p)
        except:
            pass
    
    conn.sendall(f"p for ElGamal in Zp* is: {p} \n".encode())

    while True:
        time.sleep(SLEEP_TIME)
        b = choose_bit()
        if b:
            c = encrypt(pub_key, m1_enc)
        else:
            c = encrypt(pub_key, m0_enc)
        #c = int_to_bytes(decrypt(priv_key, c))
        conn.sendall(f"Here is your ciphertext: {c}\n".encode())
        conn.sendall(f"Choose 0 if this ciphertext is from message 0 or 1 for message 1:\n".encode())
        choice = conn.recv(4096).strip()
        try:
            if int(choice) == b:
                conn.sendall("Correct!\n".encode())
                correct_answers += 1
            else:
                conn.sendall("Wrong! Better luck next time!\n".encode())
                return
        except:
            conn.sendall("Wrong! Better luck next time!\n".encode())
            return
        if correct_answers == N_CORRECT:
            conn.sendall(f"You got {N_CORRECT} correct! Here's your flag: \n{FLAG}\n".encode())
            return

def handle_client(conn, addr):
    print(f"Connection from {addr}")
    try: 
        try:
            run_game_socketed(conn)
            conn.close()
            print(f"Closed connection from {addr}")
        except Exception as e:
            print(e)
            conn.close()
            print(f"Closed connection from {addr}")
    except:
        pass

if __name__ == "__main__":
    # TODO: add socket/thread handler that runs game and then closes socket on return
    HOST = "0.0.0.0"   # listen on all interfaces
    PORT = 9999
    print(f"[*] Listening on port {PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()

        while True:
            conn, addr = s.accept()
            # handle each client in a thread so multiple players can connect
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    #run_game()
