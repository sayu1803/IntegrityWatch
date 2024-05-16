import hashlib
import os
import time
from twilio.rest import Client
import tkinter as tk
from tkinter import messagebox
import shutil
from datetime import datetime

class FileIntegrityMonitor:
    def __init__(self, directory_path, backup_directory_path, manager_phone, twilio_account_sid, twilio_auth_token, twilio_phone_number):
        self.directory_path = directory_path
        self.backup_directory_path = backup_directory_path
        self.expected_hashes = self.calculate_hashes()
        self.manager_phone = manager_phone
        self.twilio_account_sid = twilio_account_sid
        self.twilio_auth_token = twilio_auth_token
        self.twilio_phone_number = twilio_phone_number
        self.root = tk.Tk()
        self.root.withdraw()  # Hide the main window
        self.log_file = r"C:\Users\splsj\OneDrive\Desktop\Report\Logs.txt"

    def calculate_hashes(self):
        """Calculate the SHA-256 hash and last modification time of each file in the directory."""
        hashes = {}
        for root, _, files in os.walk(self.directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                try:
                    with open(file_path, 'rb') as file:
                        hasher = hashlib.sha256()
                        buffer = file.read(65536)  # Read the file in 64 KB blocks
                        while len(buffer) > 0:
                            hasher.update(buffer)
                            buffer = file.read(65536)
                        file_hash = hasher.hexdigest()
                        last_modified = os.path.getmtime(file_path)
                        hashes[file_path] = (file_hash, last_modified)
                except Exception as e:
                    print(f"Error processing file: {file_path}: {e}")
        return hashes

    def monitor_integrity(self):
        """Monitor the integrity of files in the directory."""
        messagebox.showinfo("Monitoring Started",
                            "File integrity monitoring has started.\nHashes and timestamps have been collected.")
        while True:
            current_hashes = self.calculate_hashes()

            # Identify altered, deleted, and newly added files
            altered_files = []
            deleted_files = []
            new_files = []
            for file_path, (current_hash, current_timestamp) in current_hashes.items():
                if file_path not in self.expected_hashes:
                    # File is new
                    new_files.append(file_path)
                elif current_hash != self.expected_hashes[file_path][0]:
                    # File hash has changed
                    altered_files.append((file_path, self.expected_hashes[file_path][1], current_timestamp))

            for file_path in self.expected_hashes:
                if file_path not in current_hashes:
                    # File was present previously but is no longer present
                    deleted_files.append(file_path)

            # Check if any altered, deleted, or new files exist
            if altered_files:
                self.alert_altered_files(altered_files)
            if deleted_files:
                self.alert_deleted_files(deleted_files)
            if new_files:
                self.delete_new_files(new_files)

            # Update expected hashes for existing files
            self.expected_hashes = current_hashes

            # Log the events
            self.log_events(altered_files, deleted_files, new_files)

            time.sleep(30)  # Check every 30 seconds

    def send_sms(self, body):
        """Send an SMS alert to the manager's phone."""
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

    def alert_altered_files(self, altered_files):
        """Send an SMS alert for altered files and restore from backup if available."""
        message = "File Integrity Alert - Altered Files\n\n"
        for file_path, expected_timestamp, current_timestamp in altered_files:
            message += f"{file_path}\nExpected Timestamp: {expected_timestamp}\nCurrent Timestamp: {current_timestamp}\n\n"
            backup_path = os.path.join(self.backup_directory_path, os.path.relpath(file_path, self.directory_path))
            if os.path.exists(backup_path):
                # Backup file exists, replace altered file with backup
                try:
                    shutil.copy(backup_path, file_path)
                    message += f"File has been restored from backup.\n\n"
                except Exception as e:
                    message += f"Failed to restore file from backup: {e}\n\n"
            else:
                message += f"No backup file found for restoration.\n\n"
        self.send_sms(message)

    def alert_deleted_files(self, deleted_files):
        """Send an SMS alert for deleted files and restore from backup if available."""
        message = "File Integrity Alert - Deleted Files\n\n"
        for file_path in deleted_files:
            message += f"{file_path}\n"
            backup_path = os.path.join(self.backup_directory_path, os.path.relpath(file_path, self.directory_path))
            if os.path.exists(backup_path):
                # Backup file exists, restore deleted file from backup
                try:
                    shutil.copy(backup_path, file_path)
                    message += f"File has been restored from backup.\n\n"
                except Exception as e:
                    message += f"Failed to restore file from backup: {e}\n\n"
            else:
                message += f"No backup file found for restoration.\n\n"
        self.send_sms(message)

    def delete_new_files(self, new_files):
        """Delete newly added files."""
        message = "File Integrity Alert - New Files Detected and Deleted\n\n"
        for file_path in new_files:
            message += f"{file_path}\n"
            try:
                os.remove(file_path)
                message += f"File has been deleted.\n\n"
            except Exception as e:
                message += f"Failed to delete file: {e}\n\n"
        self.send_sms(message)

    def log_events(self, altered_files, deleted_files, new_files):
        """Log the events in a text file."""
        with open(self.log_file, "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"Timestamp: {timestamp}\n")
            if altered_files:
                f.write("Altered Files:\n")
                for file_path, expected_timestamp, current_timestamp in altered_files:
                    f.write(f"{file_path}\nExpected Timestamp: {expected_timestamp}\nCurrent Timestamp: {current_timestamp}\n\n")
            if deleted_files:
                f.write("Deleted Files:\n")
                for file_path in deleted_files:
                    f.write(f"{file_path}\n\n")
            if new_files:
                f.write("Newly Added Files:\n")
                for file_path in new_files:
                    f.write(f"{file_path}\n\n")
            f.write("="*50 + "\n\n")

    def run(self):
        """Start monitoring file integrity."""
        self.monitor_integrity()

if __name__ == "__main__":
    # Directory to monitor
    directory_path = "path/to/monitor_directory"  # Update this path to the directory you want to monitor
    # Backup directory
    backup_directory_path = "path/to/backup_directory"  # Update this path to the backup directory
    # Manager phone number
    manager_phone = "manager_phone_number"  # Update this to the manager's phone number
    # Twilio details
    twilio_account_sid = "your_twilio_account_sid"  # Update this with your Twilio account SID
    twilio_auth_token = "your_twilio_auth_token"  # Update this with your Twilio auth token
    twilio_phone_number = "your_twilio_phone_number"  # Update this with your Twilio phone number

    monitor = FileIntegrityMonitor(directory_path, backup_directory_path, manager_phone, twilio_account_sid, twilio_auth_token, twilio_phone_number)
    monitor.run()
