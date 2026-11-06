import socket
import platform
import subprocess
from typing import Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


# Constante con puertos de servicios comunes
COMMOM_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
}


def get_ip() -> str:
    """Función para obtener la IP local"""

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]

    except:
        ip = "192.168.1.1"

    finally:
        s.close()

    return ip


def ping_ip(ip: str) -> Optional[tuple[str, str]]:
    """Función que hace ping a un numero de ip local"""

    param = "-n" if platform.system().lower() == "windows" else "-c"
    cmd = ["ping", param, "1", ip]

    res = subprocess.run(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        capture_output=False)

    if res.returncode == 0:
        # Intentar resolver nombre del host
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]

        except:
            hostname = "Desconocido"

        return ip, hostname


def scan_network() -> set[tuple[str, str]]:
    """Función que escanea la red usando un pool de hilos"""

    # Obtengo la ip local
    ip = get_ip()

    tmp = ip.split(".")
    tmp = ".".join(tmp[:-1])

    ip_range = [ f"{tmp}.{i}" for i in range(1, 255) ]
    # La descarto en el escaneo
    ip_range.remove(ip)

    with ThreadPoolExecutor(max_workers=50) as ex:
        hosts = set(ex.map(ping_ip, ip_range))
        hosts.discard(None)

        return hosts


def scan_ip(ip: str, port: int) -> Optional[tuple[int, str, str]]:
    """Función que escanea los puertos abiertos de una ip"""

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
                
        res = s.connect_ex((ip, port))

        if res == 0:
            banner = "Sin banner"

            try:
                s.settimeout(1)

                if data := s.recv(1024).decode(errors='ignore').strip():
                    banner = data.split('\n')[0]
            except:
                pass

            service = COMMOM_SERVICES.get(port, "Desconocido")
            s.close()

            return (port, service, banner)

    except:
        return None

    finally:
        s.close()


def scan_port(file, hosts: set[tuple[str, str]]) -> None:
    """Función que escanea los puertos de una lista de hosts"""

    for ip, _ in hosts:
        with ThreadPoolExecutor(max_workers=100) as ex:
            res = ex.map(lambda p: scan_ip(ip, p), COMMOM_SERVICES.keys())

            for r in res:
                if r:
                    file.writelines([
                        f"{ip}\n", "-" * 80 + "\n"])  
                    file.writelines([
                        f"Puerto {r[0]:>73}\n", f"Servicio {r[1]:>71}\n", f"Banner {r[2]:>73}\n"])


def main() -> None:
    """Punto de entrada del script"""

    # Tomo el dia corriente
    now = datetime.now()

    with open(f"reporte_{now.strftime('%Y%m%d')}.txt", "w") as file:
        print("- Escaneando red con Ping")

        hosts = scan_network()

        file.writelines([
            "Reporte de Escaneo\n",
            f"Fecha: {now.strftime('%d-%m-%Y %H:%M:%S')}\n\n",
            "=" * 80 + "\n", "Dispositivos\n", "=" * 80 + "\n\n"
        ] + [ f"{str(ip):<16} {hostname:>63}\n" for ip, hostname in hosts ] +
        ["=" * 80 + "\n"])

        print("-")
        print("- Escaneando puertos")

        scan_port(file, hosts)

    print("Reporte Generado.")


if __name__ == "__main__":
    main()
