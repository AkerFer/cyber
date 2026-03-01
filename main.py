import tkinter as tk
from tkinter import messagebox, filedialog
import base64
import hashlib
import datetime
from tkinter import ttk
import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

current_data_bytes = None
current_signature = None
issue_date = None
expire_date = None
fingerprint_cert = None
fingerprint_key = None
serial_number = None


def create_signature():
    global issue_date, expire_date
    global fingerprint_cert, fingerprint_key, serial_number
    global current_data_bytes, current_signature

    name = entry_name.get()
    organization = entry_org.get()
    city = entry_city.get()
    country = entry_country.get()

    if not name or not organization or not city or not country:
        messagebox.showerror("Ошибка", "Заполните все поля!")
        return

    data_block = (
    f"Имя: {name}\n"
    f"Организация: {organization}\n"
    f"Страна: {country}")

    current_data_bytes = data_block.encode("utf-8")

    issue_date = datetime.datetime.now()
    expire_date = issue_date + datetime.timedelta(days=365)
    serial_number = hex(random.getrandbits(64))[2:].upper()
    fingerprint_cert = hashlib.sha256(current_data_bytes).hexdigest().upper()
    pub_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint_key = hashlib.sha256(pub_bytes).hexdigest().upper()

    current_signature = private_key.sign(
        current_data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    sign_text = base64.b64encode(current_signature).decode("utf-8")

    text_signature.delete("1.0", tk.END)
    text_signature.insert(tk.END, sign_text)

    pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    text_public.delete("1.0", tk.END)
    text_public.insert(tk.END, pub)

    status_label.config(text="Подпись создана👍")

def save_certificate():
    if not issue_date:
        messagebox.showerror("Ошибка", "Сначала создайте подпись!")
        return
    
    path = filedialog.asksaveasfilename(defaultextension=".txt")

    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(generate_certificate_text())
        messagebox.showinfo("Готово", "Сертификат сохранен😎")

def verify_from_file():
    path = filedialog.askopenfilename()
    if not path:
        return

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    try:
        start = content.index("-----BEGIN SIGNED DATA-----") + len("-----BEGIN SIGNED DATA-----")
        end = content.index("-----END SIGNED DATA-----")
        data_block = content[start:end]
        data_block = data_block.lstrip("\n").rstrip("\n")  
        s_start = content.index("-----BEGIN SIGNATURE-----") + len("-----BEGIN SIGNATURE-----")
        s_end = content.index("-----END SIGNATURE-----")
        signature_block = content[s_start:s_end]
        signature_block = "".join(signature_block.split())  

        k_start = content.index("-----BEGIN PUBLIC KEY-----")
        k_end = content.index("-----END PUBLIC KEY-----") + len("-----END PUBLIC KEY-----")
        public_key_text = content[k_start:k_end]

        data_bytes = data_block.encode("utf-8")
        signature = base64.b64decode(signature_block)

        loaded_public_key = serialization.load_pem_public_key(
            public_key_text.encode("utf-8")
        )
        loaded_public_key.verify(
            signature,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        messagebox.showinfo("Проверка", "Подпись верная 😎")
    except Exception as e:
        messagebox.showerror("Проверка", "Подпись испорчена 💔")

def format_base64(text, line_length=64):
    return "\n".join([text[i:i+line_length] for i in range(0, len(text), line_length)])

def show_details():
    details_window = tk.Toplevel(root)
    details_window.title("Сведения о сертификате")
    details_window.geometry("600x500")

    text = tk.Text(details_window)
    text.pack(fill="both", expand=True, padx=15, pady=15)

    text.insert("1.0", generate_certificate_text())
    text.config(state="disabled")

def generate_certificate_text():
    formatted_issue = issue_date.strftime("%A, %d %B %Y %H:%M:%S")
    formatted_expire = expire_date.strftime("%A, %d %B %Y %H:%M:%S")

    data_block = current_data_bytes.decode("utf-8")

    signature_b64 = base64.b64encode(current_signature).decode("utf-8")
    signature_formatted = "\n".join(
        [signature_b64[i:i+64] for i in range(0, len(signature_b64), 64)]
    )

    public_key_text = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    private_key_text = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    cert_text = (
        "===== СВЕДЕНИЯ О СЕРТИФИКАТЕ =====\n\n"

        "-----BEGIN SIGNED DATA-----\n"
        f"{data_block}\n"
        "-----END SIGNED DATA-----\n\n"

        "Кем выдан:\n\n"
        "   Самоподписанный сертификат\n"
        "   Local Certification Authority\n\n"

        "Срок действия:\n\n"
        f"   Дата выдачи: {formatted_issue}\n"
        f"   Действителен до: {formatted_expire}\n\n"

        "Серийный номер:\n\n"
        f"   {serial_number}\n\n"

        "Цифровые отпечатки (SHA-256):\n\n"
        f"   Сертификат:\n   {fingerprint_cert}\n\n"
        f"   Открытый ключ:\n   {fingerprint_key}\n\n"

        f"{public_key_text}\n"

        "-----BEGIN SIGNATURE-----\n"
        f"{signature_formatted}\n"
       "-----END SIGNATURE-----\n\n"
        f"{private_key_text}\n")
    
    

    return cert_text

def generate_many_sertifications():
    path = filedialog.askdirectory()
    if not path:
        return

    count = 5 

    issuer = x509.Name([
    x509.NameAttribute(
        NameOID.COUNTRY_NAME,
        (entry_country.get()[:2].upper() if entry_country.get() else "JP")
    ),
    x509.NameAttribute(
        NameOID.ORGANIZATION_NAME,
        entry_org.get() or "Local CA"
    ),
    x509.NameAttribute(
        NameOID.COMMON_NAME,
        "Local Certification Authority"
    ),
])

    for i in range(1, count + 1):
        user_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        user_pub = user_priv.public_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, entry_country.get() or "JP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, entry_org.get() or "User Org"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, entry_city.get() or "Tokio"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{entry_name.get() or 'User'}-{i}"),
        ])

        now = datetime.datetime.utcnow()

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(user_pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(private_key=private_key, algorithm=hashes.SHA256())
        )

        cert_path = f"{path}/user_{i}.crt"
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        key_path = f"{path}/user_{i}.key"
        with open(key_path, "wb") as f:
            f.write(user_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    messagebox.showinfo("Готово", f"Создано {count} сертификатов и ключей ")

# гуи
root = tk.Tk()
root.title("Программа цифровой подписи")
root.geometry("900x650")

notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

main_tab = tk.Frame(notebook)
docs_tab = tk.Frame(notebook)

notebook.add(main_tab, text="Цифровая подпись")
notebook.add(docs_tab, text="Документация")

top_frame = tk.Frame(main_tab)
top_frame.pack(pady=10)

tk.Label(top_frame, text="Имя:").grid(row=0, column=0)
entry_name = tk.Entry(top_frame, width=30)
entry_name.grid(row=0, column=1)

tk.Label(top_frame, text="Организация:").grid(row=1, column=0)
entry_org = tk.Entry(top_frame, width=30)
entry_org.grid(row=1, column=1)

tk.Label(top_frame, text="Город:").grid(row=2, column=0)
entry_city = tk.Entry(top_frame, width=30)
entry_city.grid(row=2, column=1)

tk.Label(top_frame, text="Страна:").grid(row=3, column=0)
entry_country = tk.Entry(top_frame, width=30)
entry_country.grid(row=3, column=1)

tk.Button(top_frame, text="Создать подпись🟢",
          command=create_signature).grid(
    row=4, column=0, columnspan=2, pady=5
)
tk.Button(top_frame, text="Сохранить сертификат❗",
          command=save_certificate).grid(
    row=5, column=0, columnspan=2, pady=5
)
tk.Button(top_frame, text="Загрузить и проверить❓",
          command=verify_from_file).grid(
    row=6, column=0, columnspan=2, pady=5
)
tk.Button(main_tab, text="Подробнее",
          command=show_details).pack(pady=5)

tk.Button(top_frame, text="Создать сертификаты в X.509 формате",
          command=generate_many_sertifications).grid(
    row=7, column=0, columnspan=2, pady=5
)

bottom_frame = tk.Frame(main_tab)
bottom_frame.pack(fill="both", expand=True)

left_frame = tk.Frame(bottom_frame)
left_frame.pack(side="left", expand=True, fill="both", padx=5)

tk.Label(left_frame, text="Подпись:").pack()
text_signature = tk.Text(left_frame)
text_signature.pack(fill="both", expand=True)

right_frame = tk.Frame(bottom_frame)
right_frame.pack(side="right", expand=True, fill="both", padx=5)

tk.Label(right_frame, text="Публичный ключ:").pack()
text_public = tk.Text(right_frame)
text_public.pack(fill="both", expand=True)

status_label = tk.Label(main_tab, text="")
status_label.pack(pady=5)

docs_text = tk.Text(docs_tab, wrap="word")
docs_text.pack(fill="both", expand=True, padx=15, pady=15)

documentation_content = """
ДОКУМЕНТАЦИЯ ПРОГРАММЫ

Назначение:
Программа предназначена для создания и проверки цифровой подписи
на основе алгоритма RSA-2048 и хеш-функции SHA-256.

Принцип работы:
1. Пользователь вводит данные.
2. Формируется блок SIGNED DATA.
3. Вычисляется хеш SHA-256.
4. Создаётся цифровая подпись.
5. Формируется сертификат.
6. Возможна проверка целостности файла.

Используемые технологии:
- Python 3
- Библиотека cryptography
- Tkinter (графический интерфейс)
- RSA-PSS
- SHA-256

Важно:
Изменение подписанного блока данных приведёт
к ошибке проверки цифровой подписи.
"""
docs_text.insert("1.0", documentation_content)
docs_text.config(state="disabled")

root.mainloop()