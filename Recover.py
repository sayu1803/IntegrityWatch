import hashlib
import os
import time
from twilio.rest import Client
import tkinter as tk
from tkinter import messagebox, simpledialog
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import threading
import pyautogui
from datetime import datetime

class FileIntegrityMonitor:
    def __init__(self, directory_path, manager_phone, twilio_account_sid, twilio_auth_token, twilio_phone_number, aws_access_key_id, aws_secret_access_key, s3_bucket_name):
        self.directory_path = directory_path
        self.manager_phone = manager_phone
        self.twilio_account_sid = twilio_account_sid
        self.twilio_auth_token = twilio_auth_token
        self.twilio_phone_number = twilio_phone_number
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.s3_bucket_name = s3_bucket_name
        self.expected_hashes = self.calculate_hashes()
        self.root = tk.Tk()
        self.root.withdraw()
        self.log_file = "integrity_monitor_logs.txt"
        self.s3_client = self.create_s3_client()
        self.screen_frozen = False
        self.auth_password = "your_secure_password_here"  # Set a secure password

    def create_s3_client(self):
        return boto3.client(
            's3',
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key
        )

    def calculate_hashes(self):
        hashes = {}
        for root, _, files in os.walk(self.directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                try:
                    with open(file_path, 'rb') as file:
                        hasher = hashlib.sha256()
                        buffer = file.read(65536)
                        while len(buffer) > 0:
                            hasher.update(buffer)
                            buffer = file.read(65536)
                        file_hash = hasher.hexdigest()
                        last_modified = os.path.getmtime(file_path)
                        hashes[file_path] = (file_hash, last_modified)
                except Exception as e:
                    print(f"Error processing file: {file_path}: {e}")
        return hashes

    def get_local_files(self):
        local_files = {}
        for root, _, files in os.walk(self.directory_path):
            for file in files:
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, self.directory_path)
                local_files[relative_path] = {
                    'size': os.path.getsize(full_path),
                    'mtime': os.path.getmtime(full_path)
                }
        return local_files

    def get_s3_files(self):
        s3_files = {}
        paginator = self.s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=self.s3_bucket_name, Prefix='backup/'):
            if 'Contents' in page:
                for obj in page['Contents']:
                    key = obj['Key']
                    if key.startswith('backup/'):
                        relative_key = key[7:]  # Remove 'backup/' prefix
                        s3_files[relative_key] = {
                            'size': obj['Size'],
                            'mtime': obj['LastModified'].timestamp()
                        }
        return s3_files

    def synchronize_s3_backup(self):
        print("Synchronizing S3 backup with current directory...")
        
        local_files = self.get_local_files()
        s3_files = self.get_s3_files()

        files_to_delete_from_s3 = set(s3_files.keys()) - set(local_files.keys())
        files_to_upload_to_s3 = set(local_files.keys()) - set(s3_files.keys())
        files_to_update = set(local_files.keys()) & set(s3_files.keys())

        for file_to_delete in files_to_delete_from_s3:
            s3_key = f"backup/{file_to_delete}"
            try:
                self.s3_client.delete_object(Bucket=self.s3_bucket_name, Key=s3_key)
                print(f"Deleted {s3_key} from S3")
            except Exception as e:
                print(f"Error deleting {s3_key} from S3: {e}")

        for file_to_upload in files_to_upload_to_s3:
            local_path = os.path.join(self.directory_path, file_to_upload)
            s3_key = f"backup/{file_to_upload}"
            self.upload_to_s3(local_path, s3_key)

        for file_to_check in files_to_update:
            local_info = local_files[file_to_check]
            s3_info = s3_files[file_to_check]
            if local_info['size'] != s3_info['size'] or abs(local_info['mtime'] - s3_info['mtime']) > 1:
                local_path = os.path.join(self.directory_path, file_to_check)
                s3_key = f"backup/{file_to_check}"
                self.upload_to_s3(local_path, s3_key)

        print("S3 backup synchronization complete.")

    def upload_to_s3(self, file_path, s3_key):
        try:
            self.s3_client.upload_file(file_path, self.s3_bucket_name, s3_key)
            print(f"Uploaded {file_path} to S3")
        except NoCredentialsError:
            print("AWS credentials not available")
        except Exception as e:
            print(f"Error uploading to S3: {e}")

    def download_from_s3(self, s3_key, local_path):
        try:
            self.s3_client.download_file(self.s3_bucket_name, s3_key, local_path)
            print(f"Downloaded {s3_key} from S3")
        except NoCredentialsError:
            print("AWS credentials not available")
        except Exception as e:
            print(f"Error downloading from S3: {e}")

    def freeze_screen(self):
        self.screen_frozen = True
        freeze_window = tk.Toplevel(self.root)
        freeze_window.attributes('-fullscreen', True)
        freeze_window.attributes('-topmost', True)
        freeze_window.configure(bg='black')
        label = tk.Label(freeze_window, text="Screen Frozen - Multiple File Modifications Detected", fg="white", bg="black", font=("Arial", 24))
        label.pack(expand=True)
        freeze_window.update()

        def unfreeze():
            password = simpledialog.askstring("Authentication", "Enter password to unfreeze:", show='*')
            if password == self.auth_password:
                self.screen_frozen = False
                freeze_window.destroy()
            else:
                messagebox.showerror("Error", "Incorrect password")

        threading.Thread(target=unfreeze, daemon=True).start()

    def handle_modifications(self, modified_files):
        if len(modified_files) > 1:
            self.freeze_screen()
            while self.screen_frozen:
                time.sleep(1)

        proceed = messagebox.askyesno("File Modifications", "Proceed with the changes?")
        if proceed:
            for file_path in modified_files:
                relative_path = os.path.relpath(file_path, self.directory_path)
                s3_key = f"backup/{relative_path}"
                self.upload_to_s3(file_path, s3_key)
            messagebox.showinfo("Backup Complete", "Changes have been backed up to S3")
        else:
            for file_path in modified_files:
                relative_path = os.path.relpath(file_path, self.directory_path)
                s3_key = f"backup/{relative_path}"
                self.download_from_s3(s3_key, file_path)
            messagebox.showinfo("Restore Complete", "Files have been restored from S3 backup")

    def monitor_integrity(self):
        if not self.check_s3_backup_exists():
            print("No existing S3 backup found. Creating initial backup...")
            self.synchronize_s3_backup()
        else:
            print("Existing S3 backup found. Synchronizing...")
            self.synchronize_s3_backup()

        while True:
            current_hashes = self.calculate_hashes()
            modified_files = []
            deleted_files = []
            new_files = []

            for file_path, (current_hash, current_timestamp) in current_hashes.items():
                if file_path not in self.expected_hashes:
                    new_files.append(file_path)
                elif current_hash != self.expected_hashes[file_path][0]:
                    modified_files.append(file_path)

            for file_path in self.expected_hashes:
                if file_path not in current_hashes:
                    deleted_files.append(file_path)

            if modified_files or deleted_files or new_files:
                self.handle_modifications(modified_files + deleted_files + new_files)

            self.expected_hashes = current_hashes
            self.log_events(modified_files, deleted_files, new_files)
            time.sleep(30)

    def check_s3_backup_exists(self):
        try:
            self.s3_client.head_object(Bucket=self.s3_bucket_name, Key='backup/')
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                return False
            else:
                raise

    def send_sms(self, body):
        client = Client(self.twilio_account_sid, self.twilio_auth_token)
        try:
            message = client.messages.create(
                body=body,
                from_=self.twilio_phone_number,
                to=self.manager_phone
            )
            print(f"SMS alert sent successfully. SID: {message.sid}")
        except Exception as e:
            print(f"Failed to send SMS alert: {e}")

    def log_events(self, modified_files, deleted_files, new_files):
        with open(self.log_file, "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"Timestamp: {timestamp}\n")
            if modified_files:
                f.write("Modified Files:\n")
                for file_path in modified_files:
                    f.write(f"{file_path}\n")
            if deleted_files:
                f.write("Deleted Files:\n")
                for file_path in deleted_files:
                    f.write(f"{file_path}\n")
            if new_files:
                f.write("Newly Added Files:\n")
                for file_path in new_files:
                    f.write(f"{file_path}\n")
            f.write("="*50 + "\n\n")

    def run(self):
        self.monitor_integrity()

if __name__ == "__main__":
    directory_path = "path/to/monitor_directory"
    manager_phone = "manager_phone_number"
    twilio_account_sid = "your_twilio_account_sid"
    twilio_auth_token = "your_twilio_auth_token"
    twilio_phone_number = "your_twilio_phone_number"
    aws_access_key_id = "your_aws_access_key_id"
    aws_secret_access_key = "your_aws_secret_access_key"
    s3_bucket_name = "your_s3_bucket_name"

    monitor = FileIntegrityMonitor(directory_path, manager_phone, twilio_account_sid, twilio_auth_token, twilio_phone_number, aws_access_key_id, aws_secret_access_key, s3_bucket_name)
    monitor.run()
