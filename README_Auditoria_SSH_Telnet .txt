
# 🔐 Auditoría SSH/Telnet LATAM

**Auditoría SSH/Telnet LATAM** es una herramienta educativa y de uso ético para la auditoría de servicios SSH y Telnet expuestos en internet. Utiliza la API de Shodan para detectar dispositivos accesibles y permite probar combinaciones de credenciales a través de una interfaz gráfica amigable desarrollada en Python con Tkinter.

> ⚠️ Esta herramienta es solo para fines académicos. El uso indebido o sin autorización puede constituir una violación legal.

---

## 🧰 Funcionalidades

- ✅ Interfaz gráfica intuitiva (Tkinter)
- 🌎 Búsqueda en Shodan filtrada por país y puerto (SSH y Telnet)
- 📂 Carga de archivos de IPs, usuarios y contraseñas
- 🔐 Pruebas de credenciales SSH en paralelo (multithreading)
- 📋 Registros de accesos exitosos y errores
- ❌ Detección de servicios SSH sin autenticación
- 💾 Guardado automático de resultados:
  - `ips_ssh.txt` y `ips_telnet.txt`
  - `vulnerabilidades_detectadas.txt`
  - `errores_conexion.txt`

---

## 🧪 Requisitos

- Python 3.7+
- [Shodan API Key](https://account.shodan.io/)
- Librerías necesarias:

```bash
pip install shodan paramiko
```

---

## 🚀 Cómo usar

1. **Reemplaza tu API Key**  
   Abre el archivo y reemplaza la línea:

   ```python
   API_KEY = "Fw0T216dIv6gMU81Ft5buP0zTQQSu7GE"
   ```

   con tu propia clave de API de Shodan.

2. **Ejecuta la aplicación**

   ```bash
   python SSHTELNET.py
   ```

3. **Aceptar la advertencia de uso ético.**

4. **Carga los archivos** desde la interfaz:
   - Lista de IPs (formato: `ip:puerto`, uno por línea)
   - Lista de usuarios
   - Lista de contraseñas

5. **Opcional**: Buscar IPs usando Shodan y generar listas automáticamente.

6. **Iniciar auditoría**  
   El sistema comenzará a probar combinaciones de usuario/contraseña y mostrará los resultados en pantalla.

---

## 📁 Formato de Archivos

- **IPs (`ips_ssh.txt`)**
  ```
  192.168.1.1:22
  10.0.0.1:2222
  ```

- **Usuarios (`usuarios.txt`)**
  ```
  root
  admin
  ```

- **Contraseñas (`passwords.txt`)**
  ```
  123456
  admin
  ```

---

## 📌 Resultados

- Los resultados se muestran en tiempo real en la interfaz.
- Los accesos válidos se guardan en `vulnerabilidades_detectadas.txt`
- Los errores se registran en `errores_conexion.txt`

---

## 🛑 Advertencia Legal

Este software es solo para **uso académico** o en entornos **controlados con autorización previa**. No está permitido el uso para atacar, auditar o interactuar con sistemas sin consentimiento del propietario.

---

## 👤 Autor

Desarrollado como parte de un proyecto académico en ciberseguridad.  
*Con fines educativos y de concienciación sobre seguridad en LATAM.*
