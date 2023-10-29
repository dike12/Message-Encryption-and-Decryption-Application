from tkinter import *
from tkinter import messagebox
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def reset():
    code.set("")
    text1.delete(1.0, END)

def generate_key():
    key = os.urandom(32)  # Generate a random 32-byte key
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Generate and save the key (do this once)
generate_key()

def load_key():
    return open("secret.key", "rb").read()

def aes_encrypt(key, message):
    iv = os.urandom(16)  # Generate IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_message).decode()  # Convert to Base64 and prepend IV

def aes_decrypt(key, encrypted_message):
    encrypted_message_bytes = base64.b64decode(encrypted_message)
    iv = encrypted_message_bytes[:16]  # Extract the IV from the beginning
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_message_bytes[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    return decrypted_message.decode()


def encrypt():
    password = code.get()

    if password == "1234":
        screen1 = Toplevel(screen)
        screen1.title("encryption")
        screen1.geometry("400x200")
        screen1.configure(bg="#ed3833")

        message = text1.get(1.0, END)
        encrypted_message = aes_encrypt(key, message.strip())

        Label(screen1, text="ENCRYPT", font="arial", fg="white", bg="#ed3833").place(x=10,y=0)
        text2 = Text(screen1, font="Robote 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10,y=40,width=380,height=150)

        text2.insert(END, encrypted_message)
    elif password == "":
        messagebox.showerror("encryption", "Input Password")
    else:
        messagebox.showerror("encryption", "Invalid password")

def decrypt():
    password = code.get()

    if password == "1234":
        screen2 = Toplevel(screen)
        screen2.title("decryption")
        screen2.geometry("400x200")
        screen2.configure(bg="#00bd56")

        message = text1.get(1.0, END).strip()
        decrypted_message = aes_decrypt(key, message)

        Label(screen2, text="DECRYPT", font="arial", fg="white", bg="#00bd56").place(x=10,y=0)
        text2 = Text(screen2, font="Robote 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
        text2.place(x=10,y=40,width=380,height=150)

        text2.insert(END, decrypted_message)
    elif password == "":
        messagebox.showerror("encryption", "Input Password")
    else:
        messagebox.showerror("encryption", "Invalid password")

def main_screen():
    global screen
    global code
    global text1
    global key

    screen = Tk()
    screen.geometry("375x398")

    key = load_key()

    image_icon = PhotoImage(file = "keys.png")
    screen.iconphoto(False, image_icon)
    screen.title("Security")

    Label(text="Enter text for encryption and decreption", fg= "black", font=("calibri", 13)).place(x=10,y=10)
    text1 = Text(font="Robote 20", bg="white", relief=GROOVE,wrap=WORD, bd=0)
    text1.place(x=10,y=50, width=355, height=100)

    Label(text="Enter secret key for encryption and decryption", fg="black", font=("calibri, 13")).place(x=10, y=170)
    code=StringVar()
    Entry(textvariable=code,width=19, bd=0,font=("arial", 25), show="*").place(x=10, y=200)

    Button(text="ENCRYPT", height="2", width=23, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10,y=250)
    Button(text="DECRYPT", height="2", width=23, bg="#00BD56",bd=0, command=decrypt).place(x=200, y=250)
    Button(text="RESET", height="2", width=50, bg="#1089ff", fg="white", bd=0, command=reset).place(x=10,y=300)

    screen.mainloop()

main_screen()
