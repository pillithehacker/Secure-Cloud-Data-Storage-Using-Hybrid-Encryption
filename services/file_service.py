import os
import uuid

from werkzeug.utils import secure_filename


def save_uploaded_file(file_storage, upload_folder):
    original_name = secure_filename(file_storage.filename)
    ext = os.path.splitext(original_name)[1]
    safe_name = f"{uuid.uuid4().hex}{ext}"
    path = os.path.join(upload_folder, safe_name)
    file_storage.save(path)
    return safe_name, original_name, path


def encrypted_file_path(encrypted_folder, source_name):
    base = os.path.splitext(source_name)[0]
    return os.path.join(encrypted_folder, f"{base}.enc")


def decrypted_file_path(upload_folder, source_name):
    base, ext = os.path.splitext(source_name)
    return os.path.join(upload_folder, f"{base}_decrypted{ext}")
