# ══════════════════════════════════════════════════════════════════
#   CyberRecon X  —  Configuration File
#   Edit this file to set your own login credentials.
# ══════════════════════════════════════════════════════════════════

# Login Credentials
# Format:  "username": "password"
# You can add multiple users — one per line.
#
USERS = {
    "admin":   "cyberrecon2025",   # ← change this password
    "analyst": "recon@123",        # ← optional second user
}

# Secret key — use a long random string in production
# Generate one: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY = "cyberreconx_secret_2025"
