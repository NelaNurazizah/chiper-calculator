import streamlit as st
import pandas as pd
import base64
import binascii
import string

# Deteksi library base58
try:
    import base58
    HAS_BASE58 = True
except ImportError:
    HAS_BASE58 = False

# --- KONFIGURASI HALAMAN ---
st.set_page_config(page_title="Kalkulator Kripto & CTF", layout="wide")

# ==========================================
# BAGIAN 1: FUNGSI KRIPTOGRAFI KLASIK
# ==========================================

def caesar_cipher(text, shift, mode='Enkripsi'):
    result = ""; steps = []
    s = shift if mode == 'Enkripsi' else -shift
    for char in text.upper():
        if char.isalpha():
            p = ord(char) - 65
            c = (p + s) % 26
            res_char = chr(c + 65)
            steps.append(f"'{char}' ({p}) → ({p} {'+' if s>=0 else '-'} {abs(s)}) mod 26 = {c} → '{res_char}'")
            result += res_char
        else: result += char
    return result, steps

def vigenere_cipher(text, key, mode='Enkripsi'):
    result = ""; steps = []
    key = [ord(k) - 65 for k in key.upper() if k.isalpha()]
    key_idx = 0
    for char in text.upper():
        if char.isalpha():
            p = ord(char) - 65
            k = key[key_idx % len(key)]
            s = k if mode == 'Enkripsi' else -k
            c = (p + s) % 26
            res_char = chr(c + 65)
            steps.append(f"'{char}'({p}) & Key '{chr(k+65)}'({k}) → ({p} {'+' if mode=='Enkripsi' else '-'} {k}) mod 26 = {c} → '{res_char}'")
            result += res_char; key_idx += 1
        else: result += char
    return result, steps

def affine_cipher(text, a, b, mode='Enkripsi'):
    result = ""; steps = []
    try: a_inv = pow(a, -1, 26)
    except ValueError: return None, ["Error: 'a' harus koprima dengan 26."]
    
    for char in text.upper():
        if char.isalpha():
            x = ord(char) - 65
            if mode == 'Enkripsi':
                c = (a * x + b) % 26
                res_char = chr(c + 65)
                steps.append(f"({a} * {x} + {b}) mod 26 = {c} → '{res_char}'")
            else:
                c = (a_inv * (x - b)) % 26
                res_char = chr(c + 65)
                steps.append(f"{a_inv} * ({x} - {b}) mod 26 = {c} → '{res_char}'")
            result += res_char
        else: result += char
    return result, steps

def invert_matrix_2x2_mod26(K):
    det = (K[0][0]*K[1][1] - K[0][1]*K[1][0]) % 26
    try: det_inv = pow(det, -1, 26)
    except ValueError: return None
    return [[(K[1][1]*det_inv)%26, (-K[0][1]*det_inv)%26], [(-K[1][0]*det_inv)%26, (K[0][0]*det_inv)%26]]

def invert_matrix_3x3_mod26(M):
    det = (M[0][0]*(M[1][1]*M[2][2] - M[1][2]*M[2][1]) - M[0][1]*(M[1][0]*M[2][2] - M[1][2]*M[2][0]) + M[0][2]*(M[1][0]*M[2][1] - M[1][1]*M[2][0])) % 26
    try: det_inv = pow(det, -1, 26)
    except ValueError: return None
    adj = [
        [(M[1][1]*M[2][2] - M[1][2]*M[2][1]) % 26, -(M[0][1]*M[2][2] - M[0][2]*M[2][1]) % 26, (M[0][1]*M[1][2] - M[0][2]*M[1][1]) % 26],
        [-(M[1][0]*M[2][2] - M[1][2]*M[2][0]) % 26, (M[0][0]*M[2][2] - M[0][2]*M[2][0]) % 26, -(M[0][0]*M[1][2] - M[0][2]*M[1][0]) % 26],
        [(M[1][0]*M[2][1] - M[1][1]*M[2][0]) % 26, -(M[0][0]*M[2][1] - M[0][1]*M[2][0]) % 26, (M[0][0]*M[1][1] - M[0][1]*M[1][0]) % 26]
    ]
    return [[(adj[i][j] * det_inv) % 26 for j in range(3)] for i in range(3)]

def hill_cipher(text, matrix, mode='Enkripsi'):
    n = len(matrix)
    steps = []; text = "".join([c for c in text.upper() if c.isalpha()])
    while len(text) % n != 0: text += 'X'
    
    working_matrix = matrix
    if mode == 'Dekripsi':
        if n == 2: working_matrix = invert_matrix_2x2_mod26(matrix)
        elif n == 3: working_matrix = invert_matrix_3x3_mod26(matrix)
        if working_matrix is None: return None, ["Error: Matriks tidak memiliki invers modulo 26."]
        steps.append(f"Matriks Invers (Mod 26):"); steps.append(pd.DataFrame(working_matrix))

    result = ""
    for i in range(0, len(text), n):
        block = [ord(c)-65 for c in text[i:i+n]]; res_block = []
        for r in range(n):
            res_block.append(sum(working_matrix[r][c] * block[c] for c in range(n)) % 26)
        res_chars = "".join([chr(val+65) for val in res_block])
        steps.append(f"Blok {list(text[i:i+n])} → {block} × Matriks → {res_block} → '{res_chars}'")
        result += res_chars
    return result, steps

def playfair_cipher(text, key, mode='Enkripsi'):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key_string = "".join(dict.fromkeys(key.upper().replace("J", "I") + alphabet))
    matrix = [list(key_string[i:i+5]) for i in range(0, 25, 5)]
    def get_pos(char):
        for r in range(5):
            for c in range(5):
                if matrix[r][c] == char: return r, c

    text = "".join(filter(str.isalpha, text.upper().replace("J", "I"))); pairs = []; i = 0
    while i < len(text):
        a = text[i]; b = text[i+1] if i+1 < len(text) else 'X'
        if a == b: pairs.append(a + 'X'); i += 1
        else: pairs.append(a + b); i += 2

    result = ""; steps = ["Matriks Playfair (5x5):", pd.DataFrame(matrix)]
    for a, b in pairs:
        r1, c1 = get_pos(a); r2, c2 = get_pos(b)
        if r1 == r2:
            s = 1 if mode == 'Enkripsi' else -1
            res = matrix[r1][(c1+s)%5] + matrix[r1][(c2+s)%5]
        elif c1 == c2:
            s = 1 if mode == 'Enkripsi' else -1
            res = matrix[(r1+s)%5][c1] + matrix[(r2+s)%5][c2]
        else: res = matrix[r1][c2] + matrix[r2][c1]
        steps.append(f"Pasangan [{a},{b}] → '{res}'"); result += res
    return result, steps


# ==========================================
# BAGIAN 2: ANTARMUKA (UI) STREAMLIT
# ==========================================

st.title("🔐 Multi-Tools Kriptografi")

with st.sidebar:
    st.header("⚙️ Navigasi Utama")
    app_mode = st.selectbox("Pilih Mode Aplikasi", ["1. Kriptografi Klasik", "2. CTF & Encoding Tools"])
    st.markdown("---")

# ------------------------------------------
# MODE 1: KRIPTOGRAFI KLASIK
# ------------------------------------------
if app_mode == "1. Kriptografi Klasik":
    st.subheader("📚 Kalkulator Klasik (Edukatif)")
    
    with st.sidebar:
        algo = st.selectbox("Pilih Algoritma", ["Caesar", "Vigenère", "Affine", "Hill Cipher", "Playfair"])
        mode = st.radio("Mode", ["Enkripsi", "Dekripsi"])

    input_text = st.text_area("Input Teks", "SERANG SEKARANG")
    res_text, res_steps = "", []

    if algo == "Caesar":
        key = st.number_input("Shift (1-25)", min_value=1, max_value=25, value=3)
        if st.button("Proses"): res_text, res_steps = caesar_cipher(input_text, key, mode)

    elif algo == "Vigenère":
        key = st.text_input("Kata Kunci", "KEY")
        if st.button("Proses"): res_text, res_steps = vigenere_cipher(input_text, key, mode)

    elif algo == "Affine":
        col1, col2 = st.columns(2)
        a = col1.number_input("Nilai a (ganjil & koprima 26)", value=5)
        b = col2.number_input("Nilai b", value=8)
        if st.button("Proses"): res_text, res_steps = affine_cipher(input_text, a, b, mode)

    elif algo == "Hill Cipher":
        size = st.radio("Ukuran Matriks", ["2x2", "3x3"])
        if size == "2x2":
            c1, c2 = st.columns(2)
            k11 = c1.number_input("K[0,0]", value=3); k12 = c2.number_input("K[0,1]", value=3)
            k21 = c1.number_input("K[1,0]", value=2); k22 = c2.number_input("K[1,1]", value=5)
            matrix = [[k11, k12], [k21, k22]]
        else:
            c1, c2, c3 = st.columns(3)
            k11 = c1.number_input("K[0,0]", value=6); k12 = c2.number_input("K[0,1]", value=24); k13 = c3.number_input("K[0,2]", value=1)
            k21 = c1.number_input("K[1,0]", value=13); k22 = c2.number_input("K[1,1]", value=16); k23 = c3.number_input("K[1,2]", value=10)
            k31 = c1.number_input("K[2,0]", value=20); k32 = c2.number_input("K[2,1]", value=17); k33 = c3.number_input("K[2,2]", value=15)
            matrix = [[k11, k12, k13], [k21, k22, k23], [k31, k32, k33]]
            
        if st.button("Proses"): res_text, res_steps = hill_cipher(input_text, matrix, mode)

    elif algo == "Playfair":
        key = st.text_input("Kata Kunci", "MONARCHY")
        if st.button("Proses"): res_text, res_steps = playfair_cipher(input_text, key, mode)

    # Output Klasik
    if res_text:
        st.success(res_text)
        with st.expander("Lihat Langkah Perhitungan"):
            for step in res_steps:
                if isinstance(step, pd.DataFrame): st.dataframe(step, use_container_width=True)
                else: st.write(step)
    elif res_text is None: st.error(res_steps[0])

# ------------------------------------------
# MODE 2: CTF & ENCODING TOOLS
# ------------------------------------------
elif app_mode == "2. CTF & Encoding Tools":
    st.subheader("🚩 Tools CTF (Encoding, XOR, Esoteric)")
    
    with st.sidebar:
        kategori_ctf = st.selectbox("Pilih Tools", ["Encoding (Base/Hex/Bin)", "XOR Cipher", "Atbash Cipher", "Baconian Cipher"])
        mode_ctf = st.radio("Aksi", ["Encode / Encrypt", "Decode / Decrypt"])

    input_data = st.text_area("Input Text / Data", height=150)

    if kategori_ctf == "Encoding (Base/Hex/Bin)":
        tipe_enc = st.selectbox("Tipe Encoding", ["Base64", "Base32", "Base58", "Hexadecimal", "Binary / ASCII"])
        if st.button("Jalankan"):
            try:
                if mode_ctf == "Encode / Encrypt":
                    enc_bytes = input_data.encode('utf-8')
                    if tipe_enc == "Base64": res = base64.b64encode(enc_bytes).decode('utf-8')
                    elif tipe_enc == "Base32": res = base64.b32encode(enc_bytes).decode('utf-8')
                    elif tipe_enc == "Base58": res = base58.b58encode(enc_bytes).decode('utf-8') if HAS_BASE58 else "Install base58 dulu (pip install base58)"
                    elif tipe_enc == "Hexadecimal": res = enc_bytes.hex()
                    elif tipe_enc == "Binary / ASCII": res = ' '.join(format(ord(x), '08b') for x in input_data)
                    st.success(res)
                else:
                    if tipe_enc == "Base64": res = base64.b64decode(input_data).decode('utf-8')
                    elif tipe_enc == "Base32": res = base64.b32decode(input_data).decode('utf-8')
                    elif tipe_enc == "Base58": res = base58.b58decode(input_data).decode('utf-8') if HAS_BASE58 else "Install base58 dulu (pip install base58)"
                    elif tipe_enc == "Hexadecimal": res = bytes.fromhex(input_data).decode('utf-8')
                    elif tipe_enc == "Binary / ASCII": res = "".join([chr(int(b, 2)) for b in input_data.split()])
                    st.success(res)
            except Exception as e: st.error(f"Error format: {e}")

    elif kategori_ctf == "XOR Cipher":
        key_xor = st.text_input("Key (String)", value="key")
        if st.button("Jalankan"):
            try:
                data = bytes.fromhex(input_data) if (mode_ctf == "Decode / Decrypt" and all(c in '0123456789abcdefABCDEF' for c in input_data) and len(input_data)%2==0) else input_data.encode('utf-8')
                kb = key_xor.encode('utf-8')
                xored = bytes([data[i] ^ kb[i % len(kb)] for i in range(len(data))])
                st.write("**Hasil Text:**"); st.code(xored.decode('utf-8', errors='ignore'))
                st.write("**Hasil Hex:**"); st.code(xored.hex())
            except Exception as e: st.error(f"Error: {e}")

    elif kategori_ctf == "Atbash Cipher":
        if st.button("Jalankan"):
            norm = string.ascii_uppercase + string.ascii_lowercase
            rev = string.ascii_uppercase[::-1] + string.ascii_lowercase[::-1]
            st.success(input_data.translate(str.maketrans(norm, rev)))

    elif kategori_ctf == "Baconian Cipher":
        bacon_dict = {'A':'AAAAA', 'B':'AAAAB', 'C':'AAABA', 'D':'AAABB', 'E':'AABAA', 'F':'AABAB', 'G':'AABBA', 'H':'AABBB', 'I':'ABAAA', 'J':'ABAAB', 'K':'ABABA', 'L':'ABABB', 'M':'ABBAA', 'N':'ABBAB', 'O':'ABBBA', 'P':'ABBBB', 'Q':'BAAAA', 'R':'BAAAB', 'S':'BAABA', 'T':'BAABB', 'U':'BABAA', 'V':'BABAB', 'W':'BABBA', 'X':'BABBB', 'Y':'BBAAA', 'Z':'BBAAB'}
        if st.button("Jalankan"):
            if mode_ctf == "Encode / Encrypt":
                st.success("".join([bacon_dict.get(c, c) + " " for c in input_data.upper()]))
            else:
                inv_bacon = {v: k for k, v in bacon_dict.items()}
                clean = "".join([c for c in input_data.upper() if c in ['A', 'B']])
                st.success("".join([inv_bacon.get(clean[i:i+5], "?") for i in range(0, len(clean), 5)]))