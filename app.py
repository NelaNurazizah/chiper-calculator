import streamlit as st
import pandas as pd

# --- KONFIGURASI HALAMAN ---
st.set_page_config(page_title="Kalkulator Kripto Edukatif", layout="wide")

st.title("🔐 Kalkulator Kriptografi Klasik")
st.markdown("Alat bantu belajar proses enkripsi dan dekripsi algoritma klasik.")

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

def hill_cipher_2x2(text, matrix, mode='Enkripsi'):
    steps = []
    text = "".join([c for c in text.upper() if c.isalpha()])
    if len(text) % 2 != 0: text += 'X'
    
    k11, k12, k21, k22 = matrix
    if mode == 'Dekripsi':
        det = (k11 * k22 - k12 * k21) % 26
        try:
            det_inv = pow(det, -1, 26)
            k11, k12, k21, k22 = (k22*det_inv)%26, (-k12*det_inv)%26, (-k21*det_inv)%26, (k11*det_inv)%26
            steps.append(f"Matriks Invers Modulo 26 ditemukan.")
        except ValueError:
            return None, ["Error: Matriks tidak memiliki invers (Determinan 0 atau genap)."]

    result = ""
    for i in range(0, len(text), 2):
        p1, p2 = ord(text[i]) - 65, ord(text[i+1]) - 65
        c1 = (k11 * p1 + k12 * p2) % 26
        c2 = (k21 * p1 + k22 * p2) % 26
        res_pair = chr(c1 + 65) + chr(c2 + 65)
        steps.append(f"Blok [{text[i]},{text[i+1]}] → [{p1},{p2}] × Matriks → [{c1},{c2}] → '{res_pair}'")
        result += res_pair
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
    algo = st.selectbox("Pilih Algoritma", ["Caesar", "Vigenère", "Affine", "Hill (2x2)", "Playfair"])
    mode = st.radio("Mode", ["Enkripsi", "Dekripsi"])

input_text = st.text_area("Input Teks", "HELLO WORLD")

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
    a = col1.number_input("Nilai a (harus ganjil & bukan 13)", value=5)
    b = col2.number_input("Nilai b", value=8)
    if st.button("Proses"):
        res_text, res_steps = affine_cipher(input_text, a, b, mode)

elif algo == "Hill (2x2)":
    st.write("Matriks Kunci:")
    c1, c2 = st.columns(2)
    k11 = c1.number_input("K[0,0]", value=3)
    k12 = c2.number_input("K[0,1]", value=3)
    k21 = c1.number_input("K[1,0]", value=2)
    k22 = c2.number_input("K[1,1]", value=5)
    if st.button("Proses"):
        res_text, res_steps = hill_cipher_2x2(input_text, [k11, k12, k21, k22], mode)

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
                st.table(step)
            else:
                st.write(step)