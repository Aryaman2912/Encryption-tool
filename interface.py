# Import required packages and modules

import tkinter as tk
from tkinter import font,messagebox
from tkinter.filedialog import asksaveasfilename, askopenfilename
from tkinter.simpledialog import askinteger, askstring
from algorithms.vigenere import vigenere_decrypt, vigenere_encrypt, vigenere_key_gen
from algorithms.des import des_encrypt, des_decrypt, get_subkeys, des_key_gen
from algorithms.rsa import rsa_key_gen, rsa_decrypt, rsa_encrypt
from algorithms.utils import *

# function that will be executed when "Upload" button is pressed
def open_file():
    filepath = askopenfilename(
        filetypes = [("Text Files","*.txt"), ("All Files","*.*")]
    )
    if not filepath:
        return
    txt_edit.delete("1.0", tk.END)
    with open(filepath,"r") as input_file:
        text = input_file.read()
        txt_edit.insert(tk.END, text)
    window.title(f"Text Editor - {filepath}")

# function that will be executed when "Download" button is pressed
def save_file():
    filepath = asksaveasfilename(
        defaultextension = '.txt',
        filetypes = [("Text Files","*.txt"), ("All Files","*.*")],
    )
    if not filepath:
        return
    with open(filepath,"w") as output_file:
        text = txt_edit.get(1.0, tk.END)
        output_file.write(text)
    window.title(f'Text Editor - {filepath}')

# function that will be executed when encrypt button is pressed
def encrypt():
    
    plaintext = txt_edit.get("1.0",tk.END).strip().replace("\n","")
    window.title('Encryptor')
    def vigenere():
        key = askstring("Key", "Please enter the key for encryption")
        ciphertext = vigenere_encrypt(plaintext, key)
        txt_edit.delete("1.0", tk.END)
        txt_edit.insert("1.0", ciphertext)
    
    def rsa():
        e = askinteger("Input the public key","Enter the value of e")
        n = askinteger("Input the public key","Enter the value of n")
        ciphertext = rsa_encrypt((e,n),plaintext)
        txt_edit.delete("1.0",tk.END)
        txt_edit.insert("1.0",ciphertext)

    
    def des():
        key = askstring("Key", "Please enter the 16 bit hexadecimal key for encryption")
        subkeys = get_subkeys(hex_to_binary(key))
        ciphertext = des_encrypt(plaintext, subkeys)
        txt_edit.delete("1.0",tk.END)
        txt_edit.insert("1.0",ciphertext)

    popup = tk.Toplevel()
    popup.rowconfigure(1,minsize=60,weight=1)
    popup.columnconfigure(0,minsize=200,weight=1)

    vigenere = tk.Button(master=popup,text='Vigenere',command=vigenere)
    vigenere.grid(row = 0, column=0,sticky='nsew', padx=5, pady=5)
    des = tk.Button(master=popup, text='DES',command=des)
    des.grid(row=1, column=0, sticky='nsew',padx=5,pady=5)
    rsa = tk.Button(master=popup, text='RSA', command=rsa)
    rsa.grid(row = 2, column=0,sticky='nsew', padx=5, pady=5)
    popup.mainloop()
    

# function that will be executed when decrypt button is pressed
def decrypt():
    ciphertext = txt_edit.get("1.0",tk.END).strip().replace("\n","")
    window.title("Decryptor")
    def vigenere():
        key = askstring("Key", "Please enter the key for decryption")
        plaintext = vigenere_decrypt(ciphertext, key)
        txt_edit.delete("1.0",tk.END)
        txt_edit.insert("1.0",plaintext)
    
    def rsa():
        d = askinteger("Input the private key","Enter the value of d")
        n = askinteger("Input the private key","Enter the value of n")
        plaintext = rsa_decrypt((d,n),int(ciphertext))
        txt_edit.delete("1.0",tk.END)
        txt_edit.insert("1.0",plaintext)

    def des():
        key = askstring("Key", "Please enter the 16 bit hexadecimal key for encryption")
        subkeys = get_subkeys(hex_to_binary(key))
        plaintext = des_decrypt(ciphertext, subkeys[::-1])
        txt_edit.delete("1.0",tk.END)
        txt_edit.insert("1.0",plaintext)

    popup = tk.Toplevel()
    popup.rowconfigure(1,minsize=60,weight=1)
    popup.columnconfigure(0,minsize=200,weight=1)

    vigenere = tk.Button(master=popup,text='Vigenere',command=vigenere)
    vigenere.grid(row = 0, column=0,sticky='nsew', padx=5, pady=5)
    des = tk.Button(master=popup, text='DES',command=des)
    des.grid(row=1, column=0, sticky='nsew',padx=5,pady=5)
    rsa = tk.Button(master=popup, text='RSA', command=rsa)
    rsa.grid(row = 2, column=0,sticky='nsew', padx=5, pady=5)
    popup.mainloop()

def generate_keys():
    def vigenere():
        key = vigenere_key_gen()
        print(key)
    def des():
        key = des_key_gen()
        messagebox.showinfo("Key for DES:",key)
    def rsa():
        key_pair = rsa_key_gen()
    popup = tk.Toplevel()
    popup.rowconfigure(1,minsize=60,weight=1)
    popup.columnconfigure(0,minsize=200,weight=1)

    vigenere = tk.Button(master=popup,text='Vigenere',command=vigenere)
    vigenere.grid(row = 0, column=0,sticky='nsew', padx=5, pady=5)
    des = tk.Button(master=popup, text='DES',command=des)
    des.grid(row=1, column=0, sticky='nsew',padx=5,pady=5)
    rsa = tk.Button(master=popup, text='RSA', command=rsa)
    rsa.grid(row = 2, column=0,sticky='nsew', padx=5, pady=5)
    popup.mainloop()

# define window, and set its configurations
window = tk.Tk()
window.title("Encrypt")
window.rowconfigure(0, minsize=800, weight=1)
window.columnconfigure(1, minsize=800, weight=1)

txt_edit = tk.Text(window)

fr_buttons = tk.Frame(window)

# add upload, download, encrypt and decrypt buttons
btn_open = tk.Button(fr_buttons, text="Upload", command=open_file)
btn_open.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

btn_save = tk.Button(fr_buttons, text="Download", command=save_file)
btn_save.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

btn_encrypt = tk.Button(fr_buttons, text="Encrypt", command=encrypt)
btn_encrypt.grid(row=2,column=0,sticky="ew",padx=5, pady=5)

btn_encrypt = tk.Button(fr_buttons, text="Decrypt", command=decrypt)
btn_encrypt.grid(row=3,column=0,sticky="ew",padx=5, pady=5)

btn_keygen = tk.Button(fr_buttons, text="Generate keys", command=generate_keys)
btn_keygen.grid(row=4,column=0,sticky="ew",padx=5, pady=5)
fr_buttons.grid(row=0, column=0,sticky="ns")
txt_edit.grid(row=0, column=1, sticky="nsew")

# Font_tuple = ("Comic Sans MS", 20)
# txt_edit.configure(font=Font_tuple)

window.mainloop()