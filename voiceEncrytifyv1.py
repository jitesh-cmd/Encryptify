import PySimpleGUI as sg
import os
import hashlib
import zipfile
import speech_recognition as sr
from cryptography.fernet import Fernet

KEY_FILE = "encryption_key.key"

def generate_key():
    return Fernet.generate_key()

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as key_file:
            return key_file.read()
    else:
        key = generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        return key

def create_cipher_suite(key):
    return Fernet(key)

def encrypt_decrypt_file(file_path, cipher_suite, operation):
    with open(file_path, 'rb') as file:
        data = file.read()
        processed_data = cipher_suite.encrypt(data) if operation == "encrypt" else cipher_suite.decrypt(data)
    with open(file_path, 'wb') as file:
        file.write(processed_data)

def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(65536), b''):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def scan_file(file_path, keyword="malware,document.txt.exe,"):
    with open(file_path, 'r') as file:
        content = file.read()
        if keyword in content:
            return f"File contains the keyword '{keyword}'. Potential threat detected!"
        return "No threats found."

def recognize_speech():
    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        sg.popup("Say 'encrypt' or 'decrypt'")
        try:
            audio = recognizer.listen(source, timeout=10)
            command = recognizer.recognize_google(audio).lower()
            return command
        except sr.UnknownValueError:
            return None
        except sr.RequestError as e:
            sg.popup(f"Google API request failed; {e}")
            return None

def encrypt_decrypt_folder(folder_path, cipher_suite, operation):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_decrypt_file(file_path, cipher_suite, operation)

def encrypt_decrypt_zip(zip_file, cipher_suite, operation):
    with zipfile.ZipFile(zip_file, 'r') as zipf:
        for file_info in zipf.infolist():
            with zipf.open(file_info) as file:
                data = file.read()
                processed_data = cipher_suite.encrypt(data) if operation == "encrypt" else cipher_suite.decrypt(data)
            with zipf.open(file_info, 'w') as file:
                file.write(processed_data)

def main():
    key = load_key()
    cipher_suite = create_cipher_suite(key)

    sg.theme("DarkGrey5")

    layout = [
        [sg.Text("Select a file, folder, or zip archive:")],
        [sg.InputText(key="path"), sg.FileBrowse("File"), sg.FolderBrowse("Folder"), sg.Button("Encrypt/Decrypt"), sg.Button("Calculate Hash"), sg.Button("Scan File")],
        [sg.Output(size=(60, 10), key="-OUTPUT-")]
    ]

    window = sg.Window("Encryptify by Shalini and Jitesh", layout)

    while True:
        event, values = window.read()

        if event in (sg.WINDOW_CLOSED, "Exit"):
            if window is not None:
                window.close()
            break

        file_path = values["path"]

        if event == "Encrypt/Decrypt":
            voice_command = recognize_speech()
            if voice_command is None:
                sg.popup("Voice command not recognized.")
                continue

            print(f"Recognized voice command: {voice_command}")
            if "encrypt" in voice_command:
                operation = "encrypt"
            elif "decrypt" in voice_command:
                operation = "decrypt"
            else:
                sg.popup("Invalid command. Please say 'encrypt' or 'decrypt'.")
                continue

            if os.path.isfile(file_path):
                encrypt_decrypt_file(file_path, cipher_suite, operation)
                sg.popup(f"{operation.capitalize()}ion complete.")
            elif os.path.isdir(file_path):
                encrypt_decrypt_folder(file_path, cipher_suite, operation)
                sg.popup(f"Folder {operation}ion complete.")
            elif zipfile.is_zipfile(file_path):
                encrypt_decrypt_zip(file_path, cipher_suite, operation)
                sg.popup(f"Zip file {operation}ion complete.")
            else:
                sg.popup("Invalid file path.")

        elif event == "Calculate Hash":
            if os.path.isfile(file_path):
                hash_value = calculate_hash(file_path)
                sg.popup(f"SHA-256 hash of the file: {hash_value}")
            else:
                sg.popup("Invalid file path.")

        elif event == "Scan File":
            if os.path.isfile(file_path):
                result = scan_file(file_path)
                sg.popup(result)
            else:
                sg.popup("Invalid file path.")

    window.close()

if __name__ == "__main__":
    main()
