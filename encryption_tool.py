import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, PhotoImage, Menu, Toplevel, Label
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import os

# Placeholder imports for encryption libraries
# from cryptography.fernet import Fernet
# from Crypto.Cipher import AES, DES
# from Crypto.PublicKey import RSA

class EncryptionTool:
    def __init__(self, root):
        self.root = root
        self.root.title('Encryption Tool')
        self.root.geometry('650x500')
        self.is_dark = False
        self.set_icon()
        self.set_theme()
        self.create_menu()
        self.create_widgets()
        self.create_status_bar()

    def set_icon(self):
        try:
            self.icon = PhotoImage(file='lock_icon.png')  # Place a lock_icon.png in the same directory
            self.root.iconphoto(False, self.icon)
        except Exception:
            pass  # If icon not found, skip

    def set_theme(self):
        if self.is_dark:
            self.bg = '#181c24'  # deep blue-gray
            self.fg = '#f8f8f2'
            self.frame_bg = '#23283a'
            self.button_bg = '#3a3f4b'
            self.button_fg = '#f8f8f2'
            self.active_bg = '#44475a'
            self.entry_bg = '#23283a'
            self.entry_fg = '#f8f8f2'
            self.label_fg = '#8be9fd'
            self.accent = '#ff79c6'  # pink accent
            self.title_fg = '#50fa7b'  # green accent
        else:
            self.bg = '#f7fafc'  # light blue-gray
            self.fg = '#22223b'
            self.frame_bg = '#e3e9f7'
            self.button_bg = '#5e60ce'  # vibrant blue
            self.button_fg = 'white'
            self.active_bg = '#3a0ca3'
            self.entry_bg = 'white'
            self.entry_fg = '#22223b'
            self.label_fg = '#3a0ca3'
            self.accent = '#f72585'  # pink accent
            self.title_fg = '#4361ee'  # blue accent
        self.root.configure(bg=self.bg)

    def toggle_dark_mode(self):
        self.is_dark = not self.is_dark
        self.set_theme()
        for widget in self.root.winfo_children():
            widget.destroy()
        self.create_widgets()

    def create_menu(self):
        menubar = Menu(self.root)
        helpmenu = Menu(menubar, tearoff=0)
        helpmenu.add_command(label='About', command=self.show_about)
        menubar.add_cascade(label='Help', menu=helpmenu)
        self.root.config(menu=menubar)

    def show_about(self):
        about = Toplevel(self.root)
        about.title('About')
        about.geometry('350x180')
        about.configure(bg=self.bg)
        Label(about, text='Encryption Tool', font=('Montserrat Black', 18, 'bold'), bg=self.bg, fg='#ffb300').pack(pady=(18, 5))
        Label(about, text='A simple tool for AES, DES, and RSA encryption/decryption.', font=('Segoe UI', 11), bg=self.bg, fg=self.fg).pack(pady=2)
        Label(about, text='Created with Python & Tkinter', font=('Segoe UI', 10), bg=self.bg, fg=self.fg).pack(pady=2)
        Label(about, text='© 2024', font=('Segoe UI', 9), bg=self.bg, fg=self.fg).pack(pady=(10, 0))

    def create_status_bar(self):
        self.status = tk.StringVar()
        self.status.set('Ready')
        self.status_bar = tk.Label(self.root, textvariable=self.status, bd=1, relief='sunken', anchor='w', font=('Segoe UI', 9), bg=self.frame_bg, fg=self.fg)
        self.status_bar.pack(side='bottom', fill='x')

    def set_status(self, msg):
        self.status.set(msg)
        self.root.update_idletasks()

    def create_widgets(self):
        # Title
        title = tk.Label(self.root, text='Encryption Tool', font=('Poppins Black', 36, 'bold'), bg=self.bg, fg=self.title_fg)
        title.pack(pady=(18, 8))

        # Minimalist dark mode toggle (small icon, no background box)
        icon = '🌙' if not self.is_dark else '☀️'
        dark_btn = tk.Button(self.root, text=icon, command=self.toggle_dark_mode, bg=self.bg, fg=self.button_bg, font=('Poppins', 14, 'bold'), relief='flat', cursor='hand2', activebackground=self.bg, activeforeground=self.accent, bd=0, highlightthickness=0)
        dark_btn.place(relx=1.0, x=-30, y=22, anchor='ne', width=28, height=28)
        self.add_tooltip(dark_btn, 'Toggle dark/light mode')

        # Input Frame
        input_frame = tk.LabelFrame(self.root, text='Input', font=('Poppins', 14, 'bold'), bg=self.frame_bg, fg=self.label_fg, bd=2, relief='groove', labelanchor='nw')
        input_frame.pack(fill='x', padx=32, pady=(5, 0), ipady=2)

        self.input_type = tk.StringVar(value='text')
        tk.Radiobutton(input_frame, text='Text', variable=self.input_type, value='text', bg=self.frame_bg, fg=self.fg, font=('Poppins', 11), selectcolor=self.bg, activebackground=self.frame_bg).grid(row=0, column=0, sticky='w', padx=7, pady=7)
        tk.Radiobutton(input_frame, text='File', variable=self.input_type, value='file', bg=self.frame_bg, fg=self.fg, font=('Poppins', 11), selectcolor=self.bg, activebackground=self.frame_bg).grid(row=0, column=1, sticky='w', padx=7, pady=7)

        self.text_input = scrolledtext.ScrolledText(input_frame, width=62, height=4, font=('Fira Mono', 11), bg=self.entry_bg, fg=self.entry_fg, insertbackground=self.entry_fg, borderwidth=1, relief='solid')
        self.text_input.grid(row=1, column=0, columnspan=4, padx=7, pady=7)

        self.file_path = tk.StringVar()
        tk.Entry(input_frame, textvariable=self.file_path, width=44, font=('Poppins', 11), bg=self.entry_bg, fg=self.entry_fg, borderwidth=1, relief='solid').grid(row=2, column=0, padx=7, pady=7, columnspan=2, sticky='w')
        tk.Button(input_frame, text='Browse', command=self.browse_file, bg=self.accent, fg='white', font=('Poppins', 11, 'bold'), relief='flat', cursor='hand2', activebackground=self.active_bg).grid(row=2, column=2, padx=7, pady=7)

        # Options Frame
        options_frame = tk.LabelFrame(self.root, text='Options', font=('Poppins', 14, 'bold'), bg=self.frame_bg, fg=self.label_fg, bd=2, relief='groove', labelanchor='nw')
        options_frame.pack(fill='x', padx=32, pady=(10, 0), ipady=2)

        tk.Label(options_frame, text='Encryption Type:', bg=self.frame_bg, fg=self.fg, font=('Poppins', 11)).grid(row=0, column=0, sticky='w', padx=7, pady=7)
        self.enc_type = tk.StringVar(value='AES')
        tk.OptionMenu(options_frame, self.enc_type, 'AES', 'DES', 'RSA').grid(row=0, column=1, sticky='w', padx=7, pady=7)

        self.key_label = tk.Label(options_frame, text='Key/Password:', bg=self.frame_bg, fg=self.fg, font=('Poppins', 11))
        self.key_label.grid(row=0, column=2, sticky='w', padx=7, pady=7)
        self.key_entry = tk.Entry(options_frame, show='*', width=22, font=('Poppins', 11), bg=self.entry_bg, fg=self.entry_fg, borderwidth=1, relief='solid')
        self.key_entry.grid(row=0, column=3, padx=7, pady=7)

        # Action Buttons Frame
        action_frame = tk.Frame(self.root, bg=self.bg)
        action_frame.pack(fill='x', padx=32, pady=15)

        encrypt_btn = tk.Button(action_frame, text='Encrypt', command=self.encrypt, bg='#43a047' if not self.is_dark else '#388e3c', fg='white', font=('Poppins', 12, 'bold'), relief='flat', width=14, cursor='hand2', activebackground='#2e7031')
        encrypt_btn.pack(side='left', padx=12)
        self.add_tooltip(encrypt_btn, 'Encrypt the input text or file')
        decrypt_btn = tk.Button(action_frame, text='Decrypt', command=self.decrypt, bg='#e53935' if not self.is_dark else '#b71c1c', fg='white', font=('Poppins', 12, 'bold'), relief='flat', width=14, cursor='hand2', activebackground='#8a1f1f')
        decrypt_btn.pack(side='left', padx=12)
        self.add_tooltip(decrypt_btn, 'Decrypt the input text or file')
        save_btn = tk.Button(action_frame, text='Save Output', command=self.save_output, bg=self.accent, fg='white', font=('Poppins', 12, 'bold'), relief='flat', width=14, cursor='hand2', activebackground=self.active_bg)
        save_btn.pack(side='right', padx=12)
        self.add_tooltip(save_btn, 'Save the output to a file')

        # Output Frame
        output_frame = tk.LabelFrame(self.root, text='Output', font=('Poppins', 14, 'bold'), bg=self.frame_bg, fg=self.label_fg, bd=2, relief='groove', labelanchor='nw')
        output_frame.pack(fill='both', expand=True, padx=32, pady=(0, 10))

        self.output = scrolledtext.ScrolledText(output_frame, width=80, height=7, font=('Fira Mono', 11), bg=self.entry_bg, fg=self.entry_fg, insertbackground=self.entry_fg, borderwidth=1, relief='solid')
        self.output.pack(fill='both', expand=True, padx=7, pady=7)

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def get_input_data(self):
        if self.input_type.get() == 'text':
            return self.text_input.get('1.0', tk.END).strip().encode()
        else:
            path = self.file_path.get()
            if not os.path.isfile(path):
                messagebox.showerror('Error', 'File not found!')
                return None
            with open(path, 'rb') as f:
                return f.read()

    def set_output_data(self, data, is_binary=False):
        if is_binary:
            # Show as base64 for display
            data = base64.b64encode(data).decode()
        self.output.delete('1.0', tk.END)
        self.output.insert(tk.END, data)

    def encrypt(self):
        self.set_status('Encrypting...')
        try:
            data = self.get_input_data()
            if data is None:
                return
            enc_type = self.enc_type.get()
            key = self.key_entry.get().encode()
            if enc_type == 'AES':
                result = self.encrypt_aes(data, key)
            elif enc_type == 'DES':
                result = self.encrypt_des(data, key)
            elif enc_type == 'RSA':
                result = self.encrypt_rsa(data)
            self.set_output_data(result, is_binary=True)
            self.set_status('Encryption complete.')
        except Exception as e:
            self.set_status(f'Error: {e}')
            messagebox.showerror('Encryption Error', str(e))
            raise

    def decrypt(self):
        self.set_status('Decrypting...')
        try:
            data = self.get_input_data()
            if data is None:
                return
            enc_type = self.enc_type.get()
            key = self.key_entry.get().encode()
            if enc_type == 'AES':
                result = self.decrypt_aes(base64.b64decode(data), key)
            elif enc_type == 'DES':
                result = self.decrypt_des(base64.b64decode(data), key)
            elif enc_type == 'RSA':
                result = self.decrypt_rsa(base64.b64decode(data))
            self.set_output_data(result.decode(errors='ignore'))
            self.set_status('Decryption complete.')
        except Exception as e:
            self.set_status(f'Error: {e}')
            messagebox.showerror('Decryption Error', str(e))
            raise

    # AES (CBC mode, PKCS7 padding)
    def encrypt_aes(self, data, key):
        key = self.pad_key(key, 32)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(self.pkcs7_pad(data, 16))
        return iv + ct_bytes

    def decrypt_aes(self, data, key):
        key = self.pad_key(key, 32)
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        return self.pkcs7_unpad(pt)

    # DES (CBC mode, PKCS7 padding)
    def encrypt_des(self, data, key):
        key = self.pad_key(key, 8)
        iv = get_random_bytes(8)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(self.pkcs7_pad(data, 8))
        return iv + ct_bytes

    def decrypt_des(self, data, key):
        key = self.pad_key(key, 8)
        iv = data[:8]
        ct = data[8:]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        return self.pkcs7_unpad(pt)

    # RSA (OAEP)
    def encrypt_rsa(self, data):
        # Generate or load RSA key pair
        key_file = 'rsa_key.pem'
        if not os.path.exists(key_file):
            key = RSA.generate(2048)
            with open(key_file, 'wb') as f:
                f.write(key.export_key('PEM'))
        else:
            with open(key_file, 'rb') as f:
                key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(key.publickey())
        return cipher.encrypt(data)

    def decrypt_rsa(self, data):
        key_file = 'rsa_key.pem'
        if not os.path.exists(key_file):
            raise Exception('RSA key not found!')
        with open(key_file, 'rb') as f:
            key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(data)

    # Utility functions
    def pkcs7_pad(self, data, block_size):
        pad_len = block_size - len(data) % block_size
        return data + bytes([pad_len] * pad_len)

    def pkcs7_unpad(self, data):
        pad_len = data[-1]
        return data[:-pad_len]

    def pad_key(self, key, length):
        return key.ljust(length, b'0')[:length]

    def save_output(self):
        self.set_status('Saving output...')
        try:
            data = self.output.get('1.0', tk.END).strip()
            if not data:
                messagebox.showerror('Error', 'No output to save!')
                self.set_status('Error: No output to save!')
                return
            path = filedialog.asksaveasfilename(defaultextension='.txt')
            if path:
                with open(path, 'w') as f:
                    f.write(data)
                messagebox.showinfo('Saved', f'Output saved to {path}')
                self.set_status('Output saved.')
        except Exception as e:
            self.set_status(f'Error: {e}')
            messagebox.showerror('Save Error', str(e))
            raise

    # Tooltip helper
    def add_tooltip(self, widget, text):
        tooltip = tk.Toplevel(widget)
        tooltip.withdraw()
        tooltip.overrideredirect(True)
        label = tk.Label(tooltip, text=text, bg='#333', fg='white', font=('Segoe UI', 9), bd=1, relief='solid', padx=5, pady=2)
        label.pack()
        def enter(event):
            x = event.x_root + 10
            y = event.y_root + 10
            tooltip.geometry(f'+{x}+{y}')
            tooltip.deiconify()
        def leave(event):
            tooltip.withdraw()
        widget.bind('<Enter>', enter)
        widget.bind('<Leave>', leave)

if __name__ == '__main__':
    root = tk.Tk()
    app = EncryptionTool(root)
    root.mainloop() 