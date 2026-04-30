import streamlit as st
import binascii
from crypto_utils import aes_encrypt, aes_decrypt, xor_encrypt_decrypt, generate_secure_xor_key
from password_utils import calculate_entropy, analyze_password, get_strength_color
from network_utils import safe_port_scan, ALLOWED_HOSTS, COMMON_PORTS

# ---- Page Config ----
st.set_page_config(
    page_title="Cybersecurity & Cryptography Toolkit",
    page_icon="🔐",
    layout="wide"
)

# ---- Sidebar Navigation ----
st.sidebar.title("🔐 Cybersec Toolkit")
st.sidebar.markdown("Senior Full-Stack + Cybersecurity Portfolio Project")
tool = st.sidebar.radio(
    "Select Tool:",
    ["Cryptography Sandbox", "Password Strength Analyzer", "Educational Port Scanner"]
)
st.sidebar.markdown("---")
st.sidebar.warning("**Disclaimer**: For educational use only. Do not use on networks/systems without permission.")

# ---- Main UI ----
st.title("Cybersecurity & Cryptography Toolkit")
st.caption("Built with Python, Streamlit, and the `cryptography` library")

# ==================== 1. CRYPTOGRAPHY SANDBOX ====================
if tool == "Cryptography Sandbox":
    st.header("1. Cryptography Sandbox")
    st.write("Encrypt/Decrypt text using AES-256 or XOR with cryptographically secure keys.")

    tab1, tab2 = st.tabs(["AES-256 (Password-Based)", "XOR (Secure Random Key)"])

    with tab1:
        st.subheader("AES-256 with PBKDF2 Key Derivation")
        col1, col2 = st.columns(2)

        with col1:
            aes_action = st.radio("Action", ["Encrypt", "Decrypt"], key="aes_action")
            aes_text = st.text_area("Text", height=150, key="aes_text",
                                    placeholder="Enter plaintext to encrypt or base64 ciphertext to decrypt")
            aes_password = st.text_input("Password", type="password", key="aes_pass",
                                         help="Used to derive AES-256 key via PBKDF2. Min 8 chars recommended.")

            if st.button("Run AES", key="run_aes"):
                if not aes_text or not aes_password:
                    st.error("Text and password are required.")
                elif len(aes_password) < 4:
                    st.error("Password too short. Use at least 4 characters for demo.")
                else:
                    try:
                        if aes_action == "Encrypt":
                            result = aes_encrypt(aes_text, aes_password)
                            st.success("Encryption successful!")
                            st.code(result, language="text")
                        else:
                            result = aes_decrypt(aes_text, aes_password)
                            st.success("Decryption successful!")
                            st.code(result, language="text")
                    except Exception as e:
                        st.error(f"Operation failed: {str(e)}")
                        st.info("Common cause: Wrong password or corrupted ciphertext.")

        with col2:
            st.markdown("**How it works**")
            st.markdown("""
            1. **Salt**: 16 random bytes generated per encryption
            2. **PBKDF2-HMAC-SHA256**: 100,000 iterations to derive 32-byte AES key
            3. **AES-256-GCM**: Authenticated encryption. Prevents tampering.
            4. **Output**: `salt + nonce + ciphertext + tag`, all base64 encoded

            This is industry-standard password-based encryption.
            """)

    with tab2:
        st.subheader("XOR with Cryptographically Secure Random Key")
        col1, col2 = st.columns(2)

        with col1:
            xor_action = st.radio("Action", ["Encrypt", "Decrypt"], key="xor_action")
            xor_text = st.text_area("Text", height=150, key="xor_text",
                                    placeholder="Enter plaintext to encrypt or hex ciphertext to decrypt")

            if xor_action == "Encrypt":
                key_length = st.slider("Random Key Length (bytes)", 8, 64, 16,
                                       help="Longer = stronger. Must equal message length for perfect secrecy.")
                if st.button("Generate Key & Encrypt"):
                    if not xor_text:
                        st.error("Text is required.")
                    else:
                        try:
                            key = generate_secure_xor_key(key_length)
                            result = xor_encrypt_decrypt(xor_text.encode(), key)
                            st.success("Encryption successful!")
                            st.text("Generated Key (hex):")
                            st.code(binascii.hexlify(key).decode(), language="text")
                            st.text("Ciphertext (hex):")
                            st.code(binascii.hexlify(result).decode(), language="text")
                            st.session_state['last_xor_key'] = binascii.hexlify(key).decode()
                        except Exception as e:
                            st.error(f"Encryption failed: {str(e)}")
            else:
                xor_key_hex = st.text_input("Key (hex)", key="xor_key_hex",
                                            value=st.session_state.get('last_xor_key', ''),
                                            help="Must be same key used to encrypt")
                if st.button("Decrypt"):
                    if not xor_text or not xor_key_hex:
                        st.error("Ciphertext and key are required.")
                    else:
                        try:
                            key = binascii.unhexlify(xor_key_hex)
                            ciphertext = binascii.unhexlify(xor_text)
                            result = xor_encrypt_decrypt(ciphertext, key)
                            st.success("Decryption successful!")
                            st.code(result.decode('utf-8', errors='replace'), language="text")
                        except Exception as e:
                            st.error(f"Decryption failed: {str(e)}")
                            st.info("Check that key is valid hex and matches encryption key.")

        with col2:
            st.markdown("**True XOR Security**")
            st.markdown("""
            XOR is only secure if:
            1. **Key is truly random** - We use `secrets.token_bytes()`, not `random`
            2. **Key never reused** - One-time pad principle
            3. **Key length >= message length** - For perfect secrecy

            Alphabetical strings like "SECRET" are NOT secure keys.
            We force cryptographically secure bytes and show them as hex so you see the actual masking.
            """)

# ==================== 2. PASSWORD STRENGTH ANALYZER ====================
elif tool == "Password Strength Analyzer":
    st.header("2. Password Strength Analyzer")
    st.write("Check entropy and get actionable feedback. Uses `zxcvbn` + custom checks.")

    password = st.text_input("Enter Password", type="password", key="pass_input",
                             placeholder="Type to analyze in real-time")

    if password:
        entropy, score, feedback, crack_time = analyze_password(password)
        color = get_strength_color(score)

        col1, col2 = st.columns([2, 3])

        with col1:
            st.metric("Entropy", f"{entropy:.2f} bits")
            st.metric("Estimated Crack Time", crack_time)
            st.progress(score / 4.0) # zxcvbn score is 0-4
            st.markdown(f"**Strength:** :{color}[{['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'][score]}]")

        with col2:
            st.subheader("Actionable Tips")
            if not feedback:
                st.success("Great password! No major vulnerabilities detected.")
            else:
                for tip in feedback:
                    st.warning(tip)

            st.markdown("**Basic Checks**")
            checks = calculate_entropy(password)
            st.write(f"- Length: {len(password)} chars")
            st.write(f"- Has Lowercase: {'✅' if checks['has_lower'] else '❌'}")
            st.write(f"- Has Uppercase: {'✅' if checks['has_upper'] else '❌'}")
            st.write(f"- Has Digit: {'✅' if checks['has_digit'] else '❌'}")
            st.write(f"- Has Symbol: {'✅' if checks['has_symbol'] else '❌'}")
    else:
        st.info("Enter a password above to see analysis.")

# ==================== 3. EDUCATIONAL PORT SCANNER ====================
else:
    st.header("3. Educational Port Scanner")
    st.error("**Legal/Safety Notice**: This tool ONLY scans localhost `127.0.0.1` or `scanme.nmap.org` to prevent abuse. Never scan networks without explicit permission.")

    col1, col2 = st.columns(2)

    with col1:
        host = st.selectbox("Target Host", ALLOWED_HOSTS,
                            help="Restricted for portfolio safety")
        ports_to_scan = st.multiselect("Ports to Check", COMMON_PORTS, default=[22, 80, 443],
                                       help="Select from common ports")
        timeout = st.slider("Timeout (seconds)", 0.1, 2.0, 0.5, 0.1)

        if st.button("Run Scan"):
            if not ports_to_scan:
                st.error("Select at least one port.")
            else:
                with st.spinner(f"Scanning {host}..."):
                    try:
                        results = safe_port_scan(host, ports_to_scan, timeout)
                        st.session_state['scan_results'] = results
                        st.session_state['scanned_host'] = host
                    except Exception as e:
                        st.error(f"Scan failed: {str(e)}")

    with col2:
        st.subheader("Results")
        if 'scan_results' in st.session_state:
            st.write(f"**Host:** `{st.session_state['scanned_host']}`")
            for port, status in st.session_state['scan_results'].items():
                if status == "Open":
                    st.success(f"Port {port}: {status}")
                else:
                    st.write(f"Port {port}: {status}")
        else:
            st.info("Run a scan to see results.")

        st.markdown("**What this means**")
        st.markdown("""
        - **Open**: Service is listening and accepted connection
        - **Closed**: Host responded but no service on port
        - **Filtered**: No response. Likely firewall drop

        Port 22 = SSH, 80 = HTTP, 443 = HTTPS, 3306 = MySQL
        """)

# ---- Footer ----
st.markdown("---")
st.caption("Built for portfolio demo. Code is modular with error handling. | github.com/yourname/cybersec-toolkit")