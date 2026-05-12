import streamlit as st
import pandas as pd

# --- KONFIGURASI HALAMAN ---
st.set_page_config(page_title="Kalkulator Kripto Edukatif", layout="wide")

st.title("🔐 Kalkulator Kriptografi Klasik")
st.markdown("Alat bantu belajar proses enkripsi dan dekripsi algoritma klasik untuk persiapan ujian.")

# --- FUNGSI HELPER & ALGORITMA ---

def caesar_cipher(text, shift, mode='Enkripsi'):
    result = ""
    steps = []
    s = shift if mode == 'Enkripsi' else -shift
    for char in text.upper():
        if char.isalpha():
            p = ord(char) - 65
            c = (p + s) % 26
            res_char = chr(c + 65)
            steps.append(f"'{char}' ({p}) → ({p} {'+' if s>=0 else '-'} {abs(s)}) mod 26 = {c} → '{res_char}'")
            result += res_char
        else:
            result += char
    return result, steps

def vigenere_cipher(text, key, mode='Enkripsi'):
    result = ""
    steps = []
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
            result += res_char
            key_idx += 1
        else:
            result += char
    return result, steps

def affine_cipher(text, a, b, mode='Enkripsi'):
    result = ""
    steps = []
    try:
        a_inv = pow(a, -1, 26)
    except ValueError:
        return None, ["Error: 'a' harus koprima dengan 26 (tidak punya invers modulo)."]
    
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
        else:
            result += char
    return result, steps

# Fungsi pembantu untuk invers Hill Cipher 2x2
def invert_matrix_2x2_mod26(K):
    det = (K[0][0]*K[1][1] - K[0][1]*K[1][0]) % 26
    try: det_inv = pow(det, -1, 26)
    except ValueError: return None
    return [
        [(K[1][1]*det_inv)%26, (-K[0][1]*det_inv)%26],
        [(-K[1][0]*det_inv)%26, (K[0][0]*det_inv)%26]
    ]

# Fungsi pembantu untuk invers Hill Cipher 3x3
def invert_matrix_3x3_mod26(M):
    det = (M[0][0]*(M[1][1]*M[2][2] - M[1][2]*M[2][1]) -
           M[0][1]*(M[1][0]*M[2][2] - M[1][2]*M[2][0]) +
           M[0][2]*(M[1][0]*M[2][1] - M[1][1]*M[2][0])) % 26
    try: det_inv = pow(det, -1, 26)
    except ValueError: return None
    # Menghitung matriks adjoin mod 26
    adj = [
        [(M[1][1]*M[2][2] - M[1][2]*M[2][1]) % 26, -(M[0][1]*M[2][2] - M[0][2]*M[2][1]) % 26, (M[0][1]*M[1][2] - M[0][2]*M[1][1]) % 26],
        [-(M[1][0]*M[2][2] - M[1][2]*M[2][0]) % 26, (M[0][0]*M[2][2] - M[0][2]*M[2][0]) % 26, -(M[0][0]*M[1][2] - M[0][2]*M[1][0]) % 26],
        [(M[1][0]*M[2][1] - M[1][1]*M[2][0]) % 26, -(M[0][0]*M[2][1] - M[0][1]*M[2][0]) % 26, (M[0][0]*M[1][1] - M[0][1]*M[1][0]) % 26]
    ]
    return [[(adj[i][j] * det_inv) % 26 for j in range(3)] for i in range(3)]

def hill_cipher(text, matrix, mode='Enkripsi'):
    n = len(matrix)
    steps = []
    text = "".join([c for c in text.upper() if c.isalpha()])
    while len(text) % n != 0: text += 'X' # Padding
    
    working_matrix = matrix
    if mode == 'Dekripsi':
        if n == 2: working_matrix = invert_matrix_2x2_mod26(matrix)
        elif n == 3: working_matrix = invert_matrix_3x3_mod26(matrix)
        
        if working_matrix is None:
            return None, ["Error: Matriks tidak memiliki invers modulo 26 (Determinan 0 atau genap)."]
        steps.append(f"Matriks Invers (Mod 26) ditemukan:")
        steps.append(pd.DataFrame(working_matrix))

    result = ""
    for i in range(0, len(text), n):
        block = [ord(c)-65 for c in text[i:i+n]]
        res_block = []
        for r in range(n):
            val = sum(working_matrix[r][c] * block[c] for c in range(n)) % 26
            res_block.append(val)
        
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

    text = "".join(filter(str.isalpha, text.upper().replace("J", "I")))
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        if a == b: pairs.append(a + 'X'); i += 1
        else: pairs.append(a + b); i += 2

    result = ""
    steps = []
    steps.append("Matriks Playfair (5x5):")
    steps.append(pd.DataFrame(matrix))

    for a, b in pairs:
        r1, c1 = get_pos(a)
        r2, c2 = get_pos(b)
        if r1 == r2:
            s = 1 if mode == 'Enkripsi' else -1
            res = matrix[r1][(c1+s)%5] + matrix[r1][(c2+s)%5]
        elif c1 == c2:
            s = 1 if mode == 'Enkripsi' else -1
            res = matrix[(r1+s)%5][c1] + matrix[(r2+s)%5][c2]
        else:
            res = matrix[r1][c2] + matrix[r2][c1]
        steps.append(f"Pasangan [{a},{b}] → '{res}'")
        result += res
    return result, steps

# --- SIDEBAR & INPUT ---
with st.sidebar:
    st.header("Pengaturan")
    algo = st.selectbox("Pilih Algoritma", ["Caesar", "Vigenère", "Affine", "Hill Cipher", "Playfair"])
    mode = st.radio("Mode", ["Enkripsi", "Dekripsi"])

input_text = st.text_area("Input Teks", "SERANG SEKARANG")

# --- DINAMIS INPUT SESUAI ALGORITMA ---
res_text, res_steps = "", []

if algo == "Caesar":
    key = st.number_input("Shift (1-25)", min_value=1, max_value=25, value=3)
    if st.button("Proses"):
        res_text, res_steps = caesar_cipher(input_text, key, mode)

elif algo == "Vigenère":
    key = st.text_input("Kata Kunci", "KEY")
    if st.button("Proses"):
        res_text, res_steps = vigenere_cipher(input_text, key, mode)

elif algo == "Affine":
    col1, col2 = st.columns(2)
    a = col1.number_input("Nilai a (harus ganjil & koprima dgn 26)", value=5)
    b = col2.number_input("Nilai b", value=8)
    if st.button("Proses"):
        res_text, res_steps = affine_cipher(input_text, a, b, mode)

elif algo == "Hill Cipher":
    size = st.radio("Ukuran Matriks", ["2x2", "3x3"])
    st.write("Masukkan Elemen Matriks Kunci:")
    
    if size == "2x2":
        c1, c2 = st.columns(2)
        k11 = c1.number_input("K[0,0]", value=3, key="k11_2")
        k12 = c2.number_input("K[0,1]", value=3, key="k12_2")
        k21 = c1.number_input("K[1,0]", value=2, key="k21_2")
        k22 = c2.number_input("K[1,1]", value=5, key="k22_2")
        matrix = [[k11, k12], [k21, k22]]
    else:
        c1, c2, c3 = st.columns(3)
        k11 = c1.number_input("K[0,0]", value=6, key="k11_3")
        k12 = c2.number_input("K[0,1]", value=24, key="k12_3")
        k13 = c3.number_input("K[0,2]", value=1, key="k13_3")
        k21 = c1.number_input("K[1,0]", value=13, key="k21_3")
        k22 = c2.number_input("K[1,1]", value=16, key="k22_3")
        k23 = c3.number_input("K[1,2]", value=10, key="k23_3")
        k31 = c1.number_input("K[2,0]", value=20, key="k31_3")
        k32 = c2.number_input("K[2,1]", value=17, key="k32_3")
        k33 = c3.number_input("K[2,2]", value=15, key="k33_3")
        matrix = [[k11, k12, k13], [k21, k22, k23], [k31, k32, k33]]
        
    if st.button("Proses"):
        res_text, res_steps = hill_cipher(input_text, matrix, mode)

elif algo == "Playfair":
    key = st.text_input("Kata Kunci", "MONARCHY")
    if st.button("Proses"):
        res_text, res_steps = playfair_cipher(input_text, key, mode)

# --- OUTPUT ---
if res_text:
    st.subheader(f"Hasil {mode}")
    st.success(res_text)
    
    with st.expander("Lihat Langkah Perhitungan (Edukatif)"):
        for step in res_steps:
            if isinstance(step, pd.DataFrame):
                st.dataframe(step, use_container_width=True)
            else:
                st.write(step)
elif res_text is None:
    st.error(res_steps[0])