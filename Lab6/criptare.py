import tkinter as tk
from tkinter import ttk
from atbash import atbash_encrypt, atbash_decrypt
from cezar import cezar_encrypt, cezar_decrypt
from columnar import columnar_encrypt, columnar_decrypt

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Criptografie")
        self.root.geometry("600x400") 
        self.root.configure(bg="#f4f4f4")  
        self.style = ttk.Style()
        self.configure_styles()
        self.main_menu()

    def configure_styles(self):
        self.style.configure("TButton", font=("Arial", 12), padding=6, relief="flat", background="#4CAF50", foreground="#4287f5")
        self.style.map("TButton", background=[("active", "#45a049")])
        self.style.configure("TLabel", font=("Arial", 14), background="#f4f4f4", foreground="#333")
        self.style.configure("TEntry", font=("Arial", 12), padding=6, relief="flat", background="#fff", foreground="#333")
        self.style.configure("TFrame", background="#f4f4f4")
        
    def main_menu(self):
        self.clear_window()

        ttk.Label(self.root, text="Alege un algoritm", font=("Arial", 20), foreground="#333").pack(pady=30)
        ttk.Button(self.root, text="Cifrul lui Cezar", command=self.cezar_page).pack(pady=10)
        ttk.Button(self.root, text="Cifrul Atbash", command=self.atbash_page).pack(pady=10)
        ttk.Button(self.root, text="Cifrul Columnar", command=self.columnar_page).pack(pady=10)

    
    def cezar_page(self):
        self.clear_window()
        ttk.Label(self.root, text="Cifrul lui Cezar", font=("Arial", 20), foreground="#333").pack(pady=10)

        frame = ttk.Frame(self.root)
        frame.pack(expand=True, fill='both', padx=10, pady=10)

        left_frame = ttk.Frame(frame)
        left_frame.pack(side='left', expand=True, fill='both', padx=10)

        right_frame = ttk.Frame(frame)
        right_frame.pack(side='right', expand=True, fill='both', padx=10)

        ttk.Label(left_frame, text="Criptare").pack(pady=10)
        input_text = ttk.Entry(left_frame, width=30)
        input_text.pack(pady=5)

        ttk.Label(left_frame, text="Deplasare:").pack(pady=5)
        shift_entry = ttk.Entry(left_frame, width=10)
        shift_entry.pack(pady=5)

        output_text_enc = ttk.Entry(left_frame, width=30, state='readonly')
        output_text_enc.pack(pady=5)

        ttk.Button(left_frame, text="Criptează", command=lambda: output_text_enc.config(state='normal') or output_text_enc.delete(0, tk.END) or output_text_enc.insert(0, cezar_encrypt(input_text.get(), shift_entry.get())) or output_text_enc.config(state='readonly')).pack(pady=10)

        ttk.Label(right_frame, text="Decriptare").pack(pady=10)
        output_text = ttk.Entry(right_frame, width=30)
        output_text.pack(pady=5)

        ttk.Label(right_frame, text="Deplasare:").pack(pady=5)
        shift_entry_dec = ttk.Entry(right_frame, width=10)
        shift_entry_dec.pack(pady=5)

        output_text_dec = ttk.Entry(right_frame, width=30, state='readonly')
        output_text_dec.pack(pady=5)

        ttk.Button(right_frame, text="Decriptează", command=lambda: output_text_dec.config(state='normal') or output_text_dec.delete(0, tk.END) or output_text_dec.insert(0, cezar_decrypt(output_text.get(), shift_entry_dec.get())) or output_text_dec.config(state='readonly')).pack(pady=10)

        ttk.Button(self.root, text="Înapoi", command=self.main_menu).pack(pady=10)

    def atbash_page(self):
        self.clear_window()
        ttk.Label(self.root, text="Cifrul Atbash", font=("Arial", 20), foreground="#333").pack(pady=10)

        frame = ttk.Frame(self.root)
        frame.pack(expand=True, fill='both', padx=10, pady=10)

        left_frame = ttk.Frame(frame)
        left_frame.pack(side='left', expand=True, fill='both', padx=10)

        right_frame = ttk.Frame(frame)
        right_frame.pack(side='right', expand=True, fill='both', padx=10)

        ttk.Label(left_frame, text="Criptare").pack(pady=10)
        input_text = ttk.Entry(left_frame, width=30)
        input_text.pack(pady=5)

        output_text_enc = ttk.Entry(left_frame, width=30, state='readonly')
        output_text_enc.pack(pady=5)

        ttk.Button(left_frame, text="Criptează", command=lambda: output_text_enc.config(state='normal') or output_text_enc.delete(0, tk.END) or output_text_enc.insert(0, atbash_encrypt(input_text.get())) or output_text_enc.config(state='readonly')).pack(pady=10)

        ttk.Label(right_frame, text="Decriptare").pack(pady=10)
        output_text = ttk.Entry(right_frame, width=30)
        output_text.pack(pady=5)

        output_text_dec = ttk.Entry(right_frame, width=30, state='readonly')
        output_text_dec.pack(pady=5)

        ttk.Button(right_frame, text="Decriptează", command=lambda: output_text_dec.config(state='normal') or output_text_dec.delete(0, tk.END) or output_text_dec.insert(0, atbash_decrypt(output_text.get())) or output_text_dec.config(state='readonly')).pack(pady=10)

        ttk.Button(self.root, text="Înapoi", command=self.main_menu).pack(pady=10)

    def columnar_page(self):
        self.clear_window()
        ttk.Label(self.root, text="Cifrul Columnar", font=("Arial", 20), foreground="#333").pack(pady=10)

        frame = ttk.Frame(self.root)
        frame.pack(expand=True, fill='both', padx=10, pady=10)

        left_frame = ttk.Frame(frame)
        left_frame.pack(side='left', expand=True, fill='both', padx=10)

        right_frame = ttk.Frame(frame)
        right_frame.pack(side='right', expand=True, fill='both', padx=10)

        ttk.Label(left_frame, text="Criptare").pack(pady=10)
        input_text = ttk.Entry(left_frame, width=30)
        input_text.pack(pady=5)

        output_text_enc = ttk.Entry(left_frame, width=30, state='readonly')
        output_text_enc.pack(pady=5)

        ttk.Button(left_frame, text="Criptează", command=lambda: output_text_enc.config(state='normal') or output_text_enc.delete(0, tk.END) or output_text_enc.insert(0, columnar_encrypt(input_text.get())) or output_text_enc.config(state='readonly')).pack(pady=10)

        ttk.Label(right_frame, text="Decriptare").pack(pady=10)
        output_text = ttk.Entry(right_frame, width=30)
        output_text.pack(pady=5)

        output_text_dec = ttk.Entry(right_frame, width=30, state='readonly')
        output_text_dec.pack(pady=5)

        ttk.Button(right_frame, text="Decriptează", command=lambda: output_text_dec.config(state='normal') or output_text_dec.delete(0, tk.END) or output_text_dec.insert(0, columnar_decrypt(output_text.get())) or output_text_dec.config(state='readonly')).pack(pady=10)

        ttk.Button(self.root, text="Înapoi", command=self.main_menu).pack(pady=10)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
