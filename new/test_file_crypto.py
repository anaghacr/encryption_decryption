import tkinter as tk
from main import AppUI
import os

r = tk.Tk()
r.withdraw()
app = AppUI(r)

p = 'tmp_test_file.txt'
with open(p, 'wb') as f:
    f.write(b'Hello world from test')

enc = app.compress_and_encrypt(p, 'secretcode')
dec = app.decrypt_and_decompress(enc, 'secretcode')

print('MATCH' if dec == open(p, 'rb').read() else 'MISMATCH')

os.remove(p)
r.destroy()
