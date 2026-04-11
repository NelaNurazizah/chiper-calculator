import streamlit as st

# --- Konfigurasi Halaman ---
# Gunakan layout="wide" agar kolom bisa berdampingan dengan luas
st.set_page_config(page_title="Cipher Lab: Side-by-Side", layout="wide")

# --- Fungsi Logika dengan Penjelasan ---

def get_caesar_explanation(text, shift):
    steps = []
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('a') if char.islower() else ord('A')
            old_pos = ord(char) - start
            new_pos = (old_pos + shift) % 26
            new_char = chr(new_pos + start)
            steps.append(f"**{char}** ({old_pos}) → **{new_char}** ({new_pos})")
            result += new_char
        else:
            result += char
            steps.append(f"**'{char}'** (Tetap)")
    return result, steps

def get_vigenere_explanation(text, key):
    steps = []
    result = ""
    key = key.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            start = ord('a') if char.islower() else ord('A')
            k_char = key[key_index % len(key)]
            shift = ord(k_char) - ord('a')
            new_char = chr((ord(char) - start + shift) % 26 + start)
            steps.append(f"**{char}** + Key **'{k_char}'** (shift {shift}) → **{new_char}**")
            result += new_char
            key_index += 1
        else:
            result += char
            steps.append(f"**'{char}'** (Tetap)")
    return result, steps

# --- Antarmuka (UI) Streamlit ---
st.title("🔐 Kalkulator Kriptografi Berantai")
st.markdown("Proses enkripsi dari **Caesar Cipher** akan langsung diteruskan ke **Vigenère Cipher**.")

# --- INPUT UTAMA (Di Bagian Atas) ---
with st.container():
    st.subheader("1. Konfigurasi Awal")
    col_input1, col_input2 = st.columns([2, 1])
    with col_input1:
        plaintext = st.text_input("Masukkan Plaintext:", value="Contoh: secret, kunci, dll.")
    with col_input2:
        shift_val = st.number_input("Shift Caesar:", min_value=0, max_value=25, value=5)

st.divider()

# --- LAYOUT BERDAMPINGAN ---
col1, col2 = st.columns(2, gap="medium")

# Variabel penampung hasil Caesar untuk dioper ke Vigenere
caesar_res = ""

# --- KOLOM 1: CAESAR ---
with col1:
    st.subheader("🛠️ Langkah 1: Caesar Cipher")
    if plaintext:
        caesar_res, caesar_steps = get_caesar_explanation(plaintext, shift_val)
        
        with st.expander("Lihat Detail Pergeseran", expanded=True):
            for s in caesar_steps:
                st.caption(s)
        
        st.success(f"Output Caesar: `{caesar_res}`")
    else:
        st.info("Masukkan plaintext untuk memulai.")

# --- KOLOM 2: VIGENERE ---
with col2:
    st.subheader("🛠️ Langkah 2: Vigenère Cipher")
    v_key = st.text_input("Masukkan Key Vigenère:", placeholder="Contoh: secret, kunci, dll.")

    if not v_key:
        st.warning("⚠️ Masukkan Key untuk memproses hasil dari Caesar Cipher.")
    elif caesar_res:
        vig_res, vig_steps = get_vigenere_explanation(caesar_res, v_key)
        
        with st.expander("Lihat Detail Perhitungan Key", expanded=True):
            for vs in vig_steps:
                st.caption(vs)
        
        st.info(f"Hasil Akhir (Ciphertext): **{vig_res}**")
        st.balloons()

# --- RINGKASAN (Di Bagian Bawah) ---
if v_key and plaintext:
    st.divider()
    st.markdown(f"""
    ### 📝 Ringkasan Alur:
    Teks Asli: `{plaintext}`  
    Langkah 1 (Caesar +{shift_val}): `{caesar_res}`  
    Langkah 2 (Vigenère Key '{v_key}'): **{vig_res}**
    
    $$ {plaintext} \\xrightarrow{{Caesar}} {caesar_res} \\xrightarrow{{Vigenere}} {vig_res} $$
    """)