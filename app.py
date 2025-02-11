import tkinter as tk
from tkinter import messagebox, scrolledtext
import paramiko
import threading

# Variável global para armazenar a conexão SSH ativa
ssh_client = None

def attempt_login():
    """Tenta estabelecer conexão SSH com o host remoto usando as credenciais fornecidas."""
    global ssh_client
    user = login_user_entry.get().strip()
    pwd = login_password_entry.get().strip()
    srv = login_srv_entry.get().strip()  # Host fixo conforme a especificação

    if not user or not pwd:
        messagebox.showerror("Erro", "Por favor, informe usuário e senha.")
        return

    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=srv, username=user, password=pwd)
        
        messagebox.showinfo("Login", "Conexão SSH estabelecida com sucesso!")

        # Esconde a tela de login e mostra a tela de configuração do IMAPSync
        login_frame.pack_forget()
        imapsync_frame.pack(padx=10, pady=10, fill="both", expand=True)

    except Exception as e:
        messagebox.showerror("Erro no Login", f"Falha ao conectar via SSH:\n{e}")

def execute_imapsync():
    """Executa o comando imapsync via SSH e exibe os logs na interface."""
    if ssh_client is None:
        messagebox.showerror("Erro", "Conexão SSH não estabelecida.")
        return

    # Obtendo os dados do usuário
    host1 = host1_entry.get().strip()
    user1 = user1_entry.get().strip()
    password1 = pass1_entry.get().strip()
    
    host2 = host2_entry.get().strip()
    user2 = user2_entry.get().strip()
    password2 = pass2_entry.get().strip()

    if not (host1 and user1 and password1 and host2 and user2 and password2):
        messagebox.showerror("Erro", "Preencha todos os campos para iniciar a migração.")
        return

    # Comando imapsync a ser executado via SSH
    command = f"imapsync --host1 {host1} --user1 {user1} --password1 {password1} --ssl1 --host2 {host2} --user2 {user2} --password2 {password2} --ssl2"

    try:
        stdin, stdout, stderr = ssh_client.exec_command(command)

        # Exibir os logs em tempo real na interface
        log_text.config(state=tk.NORMAL)
        log_text.delete(1.0, tk.END)  # Limpa logs anteriores
        for line in iter(stdout.readline, ""):
            log_text.insert(tk.END, line)
            log_text.yview(tk.END)  # Rolar para o final

        # Capturar erros, se houver
        err = stderr.read().decode('utf-8')
        if err:
            log_text.insert(tk.END, f"\nErro: {err}\n")
            log_text.yview(tk.END)

        log_text.config(state=tk.DISABLED)

    except Exception as e:
        messagebox.showerror("Erro", f"Falha ao executar imapsync:\n{e}")

def start_imapsync():
    """Cria uma nova thread para rodar o imapsync sem travar a UI."""
    thread = threading.Thread(target=execute_imapsync)
    thread.start()

def on_closing():
    """Fecha a conexão SSH ao fechar a aplicação."""
    global ssh_client
    if ssh_client:
        ssh_client.close()
    root.destroy()

# --- Configuração da Interface Gráfica ---
root = tk.Tk()
root.title("IMAPSync - Migração de E-mails")
root.geometry("870x500")
root.configure(bg="#2C2F33")  # Fundo escuro

# --- Tela de Login SSH ---
login_frame = tk.Frame(root, padx=10, pady=120, bg=root["bg"])
login_frame.pack()

tk.Label(login_frame, text="Login SSH", font=("Helvetica", 16, "bold"), bg=root["bg"], fg="green").grid(row=0, column=0, columnspan=2, pady=10)

tk.Label(login_frame, text="Servidor:", font=("Helvetica", 12, "bold"), bg=root["bg"], fg="green").grid(row=1, column=0, sticky="e", pady=5)
login_srv_entry = tk.Entry(login_frame, width=20)
login_srv_entry.grid(row=1, column=1, pady=5)

tk.Label(login_frame, text="Usuário:", font=("Helvetica", 12, "bold"), bg=root["bg"], fg="green").grid(row=2, column=0, sticky="e", pady=5)
login_host_entry = tk.Entry(login_frame, width=20)
login_host_entry.grid(row=2, column=1, pady=5)

tk.Label(login_frame, text="Usuário:", font=("Helvetica", 12, "bold"), bg=root["bg"], fg="green").grid(row=2, column=0, sticky="e", pady=5)
login_user_entry = tk.Entry(login_frame, width=20)
login_user_entry.grid(row=2, column=1, pady=5)

tk.Label(login_frame, text="Senha:", font=("Helvetica", 12, "bold"), bg=root["bg"], fg="green").grid(row=3, column=0, sticky="e", pady=5)
login_password_entry = tk.Entry(login_frame, show="*", width=20)
login_password_entry.grid(row=3, column=1, pady=5)

login_button = tk.Button(login_frame, text="Conectar", command=attempt_login)
login_button.grid(row=4, column=0, columnspan=2, pady=10)

# --- Tela de Configuração do IMAPSync ---
imapsync_frame = tk.Frame(root, padx=10, pady=10, bg=root["bg"])

tk.Label(imapsync_frame, text="Migração de E-mails", font=("Helvetica", 16, "bold"), bg=root["bg"], fg="green").grid(row=0, column=0, columnspan=2, pady=10)

# Configuração da Conta 1
tk.Label(imapsync_frame, text="Host E-mail Remetente:", font=("Helvetica", 12, "bold"), bg=root["bg"], fg="green").grid(row=1, column=0, sticky="e", pady=5)
host1_entry = tk.Entry(imapsync_frame, width=30)
host1_entry.grid(row=1, column=1, pady=5)

tk.Label(imapsync_frame, text="E-mail Remetente:", font=("Helvetica", 12, "bold"), bg=root["bg"], fg="green").grid(row=2, column=0, sticky="e", pady=5)
user1_entry = tk.Entry(imapsync_frame, width=30)
user1_entry.grid(row=2, column=1, pady=5)

tk.Label(imapsync_frame, text="Senha do Remetente:", font=("Helvetica", 12, "bold"), bg=root["bg"], fg="green").grid(row=3, column=0, sticky="e", pady=5)
pass1_entry = tk.Entry(imapsync_frame, show="*", width=30)
pass1_entry.grid(row=3, column=1, pady=5)

# Configuração da Conta 2
tk.Label(imapsync_frame, text="Host E-mail Destinatário:", font=("Helvetica", 12, "bold"), bg=root["bg"], fg="green").grid(row=4, column=0, sticky="e", pady=5)
host2_entry = tk.Entry(imapsync_frame, width=30)
host2_entry.grid(row=4, column=1, pady=5)

tk.Label(imapsync_frame, text="E-mail Destinatário:", font=("Helvetica", 12, "bold"), bg=root["bg"], fg="green").grid(row=5, column=0, sticky="e", pady=5)
user2_entry = tk.Entry(imapsync_frame, width=30)
user2_entry.grid(row=5, column=1, pady=5)

tk.Label(imapsync_frame, text="Senha do Destinatário:", font=("Helvetica", 12, "bold"), bg=root["bg"], fg="green").grid(row=6, column=0, sticky="e", pady=5)
pass2_entry = tk.Entry(imapsync_frame, show="*", width=30)
pass2_entry.grid(row=6, column=1, pady=5)

# Botão para iniciar a migração
start_button = tk.Button(imapsync_frame, text="Iniciar Migração", command=start_imapsync)
start_button.grid(row=7, column=0, columnspan=2, pady=10)

# Área de Log
log_text = scrolledtext.ScrolledText(imapsync_frame, width=100, height=10, state=tk.DISABLED)
log_text.grid(row=8, column=0, columnspan=2, pady=5)

# Configura o fechamento correto da aplicação
root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()
