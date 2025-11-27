#!/usr/bin/env python3
"""
Flask app: File upload → compress (gzip) → XOR-encrypt (SHA256-derived key) → download.
Also supports decrypt + decompress.

Single-file app. Uses Bootstrap for a simple clean UI similar to the screenshot.

Sample image included from the conversation (path used as demo):
    /mnt/data/983c54ff-aa90-4d90-8da7-e253df1adc74.png
"""

import os
import gzip
import hashlib
import uuid
from flask import Flask, request, render_template_string, redirect, url_for, send_from_directory, flash
from werkzeug.utils import secure_filename

# ---------- Configuration ----------
UPLOAD_DIR = "uploads"
OUTPUT_DIR = "outputs"
ALLOWED_EXTENSIONS = None  # allow all files
SAMPLE_FILE = "/mnt/data/983c54ff-aa90-4d90-8da7-e253df1adc74.png"  # dev-provided sample

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB limit (adjust if needed)


# ---------- Utility functions ----------
def derive_key(password: str) -> bytes:
    """Derive fixed-length key bytes from password using SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).digest()


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR a bytes object with a repeated key."""
    klen = len(key)
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ key[i % klen]
    return bytes(out)


def compress_bytes(raw: bytes) -> bytes:
    """Gzip-compress in-memory bytes and return compressed bytes."""
    return gzip.compress(raw)


def decompress_bytes(compressed: bytes) -> bytes:
    """Gzip-decompress in-memory bytes."""
    return gzip.decompress(compressed)


def human_size(n_bytes: int) -> str:
    """Pretty print bytes to KB/MB."""
    if n_bytes < 1024:
        return f"{n_bytes} B"
    if n_bytes < 1024**2:
        return f"{n_bytes / 1024:.2f} KB"
    return f"{n_bytes / 1024**2:.2f} MB"


# ---------- Routes & templates ----------
BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>File Encryptor (Compress + XOR)</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
  body { padding-top: 36px; background:#f7f9fc; }
  .card { box-shadow: 0 6px 18px rgba(0,0,0,0.06); }
  .small-muted { font-size:0.9rem; color:#6c757d; }
  .center-img { max-width:320px; max-height:240px; object-fit:contain; }
</style>
</head>
<body>
<div class="container">
  <h2 class="mb-3">File Compression & Encryption</h2>
  <div class="row">
    <div class="col-md-7">
      <div class="card mb-3">
        <div class="card-body">
          <h5 class="card-title">Encrypt (compress → encrypt)</h5>
          <form method="post" action="{{ url_for('encrypt') }}" enctype="multipart/form-data">
            <div class="mb-3">
              <label class="form-label">Choose file (or use Sample below)</label>
              <input class="form-control" type="file" name="file">
            </div>
            <div class="mb-3">
              <label class="form-label">Password / Code</label>
              <input class="form-control" type="password" name="password" required placeholder="Enter password to encrypt">
              <div class="form-text">We derive a 32-byte key from this password via SHA-256 and XOR the gzip-compressed content.</div>
            </div>
            <button type="submit" class="btn btn-primary">Encrypt & Show Result</button>
          </form>
        </div>
      </div>

      <div class="card mb-3">
        <div class="card-body">
          <h5 class="card-title">Decrypt (upload .enc)</h5>
          <form method="post" action="{{ url_for('decrypt') }}" enctype="multipart/form-data">
            <div class="mb-3">
              <label class="form-label">Encrypted file (.enc)</label>
              <input class="form-control" type="file" name="file" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Password used to encrypt</label>
              <input class="form-control" type="password" name="password" required placeholder="password">
            </div>
            <button class="btn btn-success" type="submit">Decrypt & Download</button>
          </form>
        </div>
      </div>

      {% with messages = get_flashed_messages() %}
        {% if messages %}
          <div class="alert alert-info">
            {% for msg in messages %}
              <div>{{ msg }}</div>
            {% endfor %}
          </div>
        {% endif %}
      {% endwith %}

    </div>

    <div class="col-md-5">
      <div class="card mb-3 text-center p-3">
        <div class="card-body">
          <h6>Sample file (demo)</h6>
          {% if sample_exists %}
            <img src="{{ url_for('serve_sample') }}" alt="sample" class="center-img mb-2 border" />
            <div class="small-muted">Path: {{ sample_path }}</div>
            <form method="post" action="{{ url_for('encrypt_sample') }}">
              <input class="form-control mt-2" type="password" name="password" required placeholder="Password for sample file">
              <button class="btn btn-outline-primary mt-2">Encrypt Sample</button>
            </form>
          {% else %}
            <div class="small-muted">No sample file found on server.</div>
          {% endif %}
        </div>
      </div>

      {% if result %}
        <div class="card">
          <div class="card-body">
            <h6 class="card-title">Result</h6>

            <div class="mb-2"><strong>Original filename:</strong> {{ result.orig_name }}</div>
            <div class="mb-2"><strong>Original size:</strong> {{ result.orig_size }}</div>
            <div class="mb-2"><strong>Compressed size (gzip):</strong> {{ result.compressed_size }}</div>
            <div class="mb-2"><strong>Encrypted file size:</strong> {{ result.encrypted_size }}</div>
            <div class="mb-2"><strong>Compression ratio:</strong> {{ result.compression_ratio }}</div>
            <div class="mb-2"><strong>Encrypted file:</strong> <a href="{{ url_for('download_file', filename=result.encrypted_filename) }}" class="btn btn-sm btn-link">Download</a></div>
          </div>
        </div>
      {% endif %}
    </div>
  </div>

  <footer class="mt-4 small-muted">Note: This example uses fast XOR encryption (NOT a modern authenticated cipher). For production use, use AES-GCM or libsodium.</footer>
</div>
</body>
</html>
"""


@app.route("/")
def index():
    sample_exists = os.path.exists(SAMPLE_FILE)
    return render_template_string(BASE_TEMPLATE, sample_exists=sample_exists, sample_path=SAMPLE_FILE, result=None)


@app.route("/serve-sample")
def serve_sample():
    """
    Serve the developer-provided sample file.
    Because the file is at an absolute path, we will try to serve it via send_from_directory.
    If the file is not under the Flask app directory, we serve it by reading bytes.
    """
    if not os.path.exists(SAMPLE_FILE):
        return "Sample not found", 404

    # If SAMPLE_FILE is inside current dir or a subdir, use send_from_directory
    abspath = os.path.abspath(SAMPLE_FILE)
    dirname, fname = os.path.split(abspath)
    try:
        return send_from_directory(dirname, fname)
    except Exception:
        # fallback: stream bytes
        return (open(abspath, "rb").read(), 200, {
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': f'inline; filename="{fname}"'
        })


@app.route("/encrypt-sample", methods=["POST"])
def encrypt_sample():
    password = request.form.get("password", "")
    if not password:
        flash("Please provide a password for the sample file.")
        return redirect(url_for("index"))

    return _handle_encrypt_from_path(SAMPLE_FILE, password)


@app.route("/encrypt", methods=["POST"])
def encrypt():
    uploaded = request.files.get("file")
    password = request.form.get("password", "")
    if not password:
        flash("Password is required")
        return redirect(url_for("index"))

    if uploaded and uploaded.filename:
        fname = secure_filename(uploaded.filename)
        save_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}_{fname}")
        uploaded.save(save_path)
        return _handle_encrypt_from_path(save_path, password)
    else:
        flash("No file uploaded")
        return redirect(url_for("index"))


def _handle_encrypt_from_path(filepath: str, password: str):
    # Read raw file
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
    except Exception as e:
        flash(f"Failed to read file: {e}")
        return redirect(url_for("index"))

    orig_size = len(raw)
    compressed = compress_bytes(raw)
    compressed_size = len(compressed)

    key = derive_key(password)
    encrypted = xor_bytes(compressed, key)
    encrypted_size = len(encrypted)

    # Save encrypted output
    basefn = os.path.basename(filepath)
    out_name = f"{uuid.uuid4().hex}_{basefn}.enc"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    try:
        with open(out_path, "wb") as outf:
            outf.write(encrypted)
    except Exception as e:
        flash(f"Failed to save encrypted file: {e}")
        return redirect(url_for("index"))

    # Compute compression ratio (percentage of size saved)
    if orig_size > 0:
        ratio = 100.0 * (1.0 - (compressed_size / orig_size))
    else:
        ratio = 0.0

    result = {
        "orig_name": basefn,
        "orig_size": human_size(orig_size),
        "compressed_size": human_size(compressed_size),
        "encrypted_size": human_size(encrypted_size),
        "compression_ratio": f"{ratio:.2f}%",
        "encrypted_filename": out_name
    }

    sample_exists = os.path.exists(SAMPLE_FILE)
    return render_template_string(BASE_TEMPLATE, sample_exists=sample_exists, sample_path=SAMPLE_FILE, result=result)


@app.route("/download/<path:filename>")
def download_file(filename):
    # Secure the path by exact match in outputs folder
    safe_path = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(safe_path):
        return "File not found", 404
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)


@app.route("/decrypt", methods=["POST"])
def decrypt():
    uploaded = request.files.get("file")
    password = request.form.get("password", "")
    if not uploaded or not uploaded.filename:
        flash("Upload an encrypted (.enc) file to decrypt.")
        return redirect(url_for("index"))
    if not password:
        flash("Password required for decryption.")
        return redirect(url_for("index"))

    fname = secure_filename(uploaded.filename)
    save_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}_{fname}")
    uploaded.save(save_path)

    try:
        with open(save_path, "rb") as f:
            encrypted_bytes = f.read()
    except Exception as e:
        flash(f"Failed to read uploaded file: {e}")
        return redirect(url_for("index"))

    key = derive_key(password)
    try:
        compressed = xor_bytes(encrypted_bytes, key)
        recovered = decompress_bytes(compressed)
    except Exception as e:
        flash("Decryption or decompression failed — wrong password or corrupted file.")
        return redirect(url_for("index"))

    # Save recovered file and send to user
    # Attempt to remove the trailing ".enc" if present
    orig_name_guess = fname
    if orig_name_guess.endswith(".enc"):
        orig_name_guess = orig_name_guess[:-4]
    out_name = f"recovered_{uuid.uuid4().hex}_{orig_name_guess}"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    with open(out_path, "wb") as of:
        of.write(recovered)

    flash("Decryption successful — recovered file ready for download.")
    return redirect(url_for("download_file", filename=out_name))


# ---------- Run ----------
if __name__ == "__main__":
    # Helpful console message
    print("Starting Flask app. Open http://127.0.0.1:5000 in your browser.")
    app.run(debug=True)


