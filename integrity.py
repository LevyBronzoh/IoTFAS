import hashlib
import logging

def verify_data_integrity(file_path):
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logging.error(f"Integrity check failed for {file_path}: {e}")
        return "ERROR"