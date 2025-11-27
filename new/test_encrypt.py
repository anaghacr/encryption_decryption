import tkinter as tk
import tempfile
import os
from main import AppUI

# Create a hidden Tk root so AppUI helpers work
root = tk.Tk()
root.withdraw()
app = AppUI(root)

# Create a temporary file with sample content
tf = tempfile.NamedTemporaryFile(delete=False)
try:
    tf.write(b'This is a test file for encryption.\nLine 2.\n')
    tf.flush()
    tf.close()
    in_path = tf.name

    enc_path = in_path + '.enc'
    dec_path = in_path + '.dec'

    password = 'secret123'

    # Encrypt (with compression)
    app._encrypt_file(in_path, enc_path, password, compress=True)

    # Decrypt
    app._decrypt_file(enc_path, dec_path, password)

    # Verify
    with open(in_path, 'rb') as f:
        orig = f.read()
    with open(dec_path, 'rb') as f:
        dec = f.read()

    print('match', orig == dec)

finally:
    for p in (in_path, enc_path, dec_path):
        try:
            os.remove(p)
        except Exception:
            pass
