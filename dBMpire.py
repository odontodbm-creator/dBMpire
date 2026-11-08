import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import threading
import flet as ft

assets_dir="assets"
SVG_ICON_PATH = "my_icon.svg"

# Porte TCP principali da scansionare per ogni host attivo
COMMON_PORTS = [21, 22, 80, 443, 445, 3389, 8080, 8443]


# --- HELPER DI COMPATIBILITÀ PER TUTTE LE VERSIONI DI FLET ---

def get_padding(left=0, top=0, right=0, bottom=0):
    """Gestisce il padding in modo sicuro per qualsiasi versione di Flet."""
    if hasattr(ft, "Padding"):
        try:
            return ft.Padding(left, top, right, bottom)
        except Exception:
            pass
    if hasattr(ft, "padding") and hasattr(ft.padding, "only"):
        try:
            return ft.padding.only(left=left, top=top, right=right, bottom=bottom)
        except Exception:
            pass
    return 20


def get_border_radius(top_left=0, top_right=0, bottom_left=0, bottom_right=0):
    """Gestisce il border radius in modo sicuro per qualsiasi versione di Flet."""
    if hasattr(ft, "BorderRadius"):
        try:
            return ft.BorderRadius(top_left, top_right, bottom_left, bottom_right)
        except Exception:
            pass
    if hasattr(ft, "border_radius") and hasattr(ft.border_radius, "only"):
        try:
            return ft.border_radius.only(
                top_left=top_left,
                top_right=top_right,
                bottom_left=bottom_left,
                bottom_right=bottom_right,
            )
        except Exception:
            pass
    return 8


def get_border_all(width=1, color="outlineVariant"):
    """Crea un bordo completo per tutti i lati compatibile con ogni versione."""
    if hasattr(ft, "Border") and hasattr(ft.Border, "all"):
        try:
            return ft.Border.all(width, color)
        except Exception:
            pass
    if hasattr(ft, "border") and hasattr(ft.border, "all"):
        try:
            return ft.border.all(width, color)
        except Exception:
            pass
    return None


def get_border_bottom(width=1, color="outlineVariant"):
    """Crea un bordo inferiore compatibile con ogni versione."""
    side = ft.BorderSide(width, color) if hasattr(ft, "BorderSide") else None
    if hasattr(ft, "Border") and hasattr(ft.Border, "only"):
        try:
            return ft.Border.only(bottom=side)
        except Exception:
            pass
    if hasattr(ft, "border") and hasattr(ft.border, "only"):
        try:
            return ft.border.only(bottom=side)
        except Exception:
            pass
    return None


def create_button(text: str, icon_name: str, on_click, bgcolor="blue600", color="white"):
    """Crea un pulsante compatibile sia con le vecchie che con le nuove versioni di Flet."""
    if hasattr(ft, "Button"):
        return ft.Button(content=ft.Text(text), icon=icon_name, on_click=on_click, bgcolor=bgcolor, color=color)
    elif hasattr(ft, "ElevatedButton"):
        return ft.ElevatedButton(content=ft.Text(text), icon=icon_name, on_click=on_click,bgcolor=bgcolor, color=color)
    elif hasattr(ft, "FilledButton"):
        return ft.FilledButton(content=ft.Text(text), icon=icon_name, on_click=on_click, bgcolor=bgcolor, color=color)
    else:
        return ft.TextButton(content=ft.Text(text), icon=icon_name, on_click=on_click, bgcolor=bgcolor, color=color)


# --- FUNZIONI DI RETE ---

def get_local_ip() -> str:
    """Ottiene l'indirizzo IP locale della scheda di rete attiva."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_mac_from_arp(ip: str) -> str:
    """Legge l'indirizzo MAC dalla tabella ARP di sistema."""
    try:
        current_os = platform.system().lower()
        cmd = ["arp", "-a", ip] if current_os == "windows" else ["arp", "-n", ip]

        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode(
            "utf-8", errors="ignore"
        )
        mac_re = re.search(
            r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})",
            output,
        )
        if mac_re:
            return mac_re.group(1).upper()
    except Exception:
        pass
    return "N/D (Privato/Mobile)"


def get_hostname(ip: str) -> str:
    """Tenta di risolvere il nome host con un timeout massimo di 0.4 secondi."""
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(0.4)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return "Sconosciuto"
    finally:
        socket.setdefaulttimeout(original_timeout)


def scan_ports(ip: str, ports: list = COMMON_PORTS) -> str:
    """Scansiona in parallelo le porte TCP principali dell'host."""
    open_ports = []

    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.25)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(str(port))
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports)) as executor:
        executor.map(check_port, ports)

    if open_ports:
        return ", ".join(sorted(open_ports, key=int))
    return "Nessuna"


def ping_host(ip_str: str):
    """Verifica se l'host è attivo e raccoglie Info (IP, Nome, MAC e Porte)."""
    ip_str = str(ip_str)
    current_os = platform.system().lower()

    cmd = (
        ["ping", "-n", "1", "-w", "400", ip_str]
        if current_os == "windows"
        else ["ping", "-c", "1", "-W", "1", ip_str]
    )

    is_active = False
    try:
        res = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if res.returncode == 0:
            is_active = True
    except Exception:
        pass

    # Fallback con socket TCP Probe su porta 80/443/135 se il ping ICMP è bloccato
    if not is_active:
        for port in (80, 443, 135):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.2)
                    if s.connect_ex((ip_str, port)) == 0:
                        is_active = True
                        break
            except Exception:
                pass

    if is_active:
        ports_str = scan_ports(ip_str)
        return {
            "ip": ip_str,
            "name": get_hostname(ip_str),
            "mac": get_mac_from_arp(ip_str),
            "ports": ports_str,
        }

    return None


# --- INTERFACCIA GRAFICA ---

def main(page: ft.Page):
    page.title = "dBMpire"
    page.theme_mode = ft.ThemeMode.SYSTEM
    page.padding = 10
    page.window.width = 700
    page.window.height = 800
    page.window.min_width = 700
    page.window.min_height = 450

    local_ip = get_local_ip()
    network_prefix = ".".join(local_ip.split(".")[:-1]) + ".0/24"

    ip_input = ft.TextField(
        label="Subnet da scansionare",
        value=network_prefix,
        expand=True,
        autofocus=True,
    )
    status_label = ft.Text(f"Avvia scansione per cercare i dispotivi", color="grey400")
    progress_bar = ft.ProgressBar(visible=False)

    # --- INTESTAZIONE FISSA (Sticky Header) ---
    table_header = ft.Container(
        content=ft.Row([
            ft.Text("Nome Dispositivo", weight=ft.FontWeight.BOLD, expand=3),
            ft.Text("Indirizzo IP", weight=ft.FontWeight.BOLD, expand=2),
            ft.Text("Indirizzo MAC", weight=ft.FontWeight.BOLD, expand=3),
            ft.Text("Porte Aperte", weight=ft.FontWeight.BOLD, expand=2),
        ]),
        bgcolor="surfaceContainerHigh",
        padding=get_padding(left=15, right=15, top=12, bottom=12),
        border_radius=get_border_radius(top_left=8, top_right=8),
    )

    # --- LISTA RIGHE SCORREVOLE ---
    devices_listview = ft.ListView(
        expand=True,
        spacing=0,
    )

    def start_scan(e):
        scan_btn.disabled = True
        scan_btn.bgcolor = "grey400"
        progress_bar.visible = True
        status_label.value = "Scansione rete e porte in corso..."
        devices_listview.controls.clear()
        page.update()

        def run_scan():
            try:
                net = ipaddress.ip_network(ip_input.value, strict=False)
                hosts = list(net.hosts())
            except ValueError:
                status_label.value = "Formato Subnet non valido!"
                progress_bar.visible = False
                scan_btn.disabled = False
                scan_btn.bgcolor = "blue600"
                page.update()
                return

            found_devices = []

            # Scansione concorrente su 50 worker
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                future_to_ip = {executor.submit(ping_host, str(ip)): ip for ip in hosts}

                for future in concurrent.futures.as_completed(future_to_ip):
                    res = future.result()
                    if res:
                        found_devices.append(res)

                        # Zebra Striping (Righe Alternate)
                        is_even = len(devices_listview.controls) % 2 == 0
                        row_bg = "surfaceContainerHighest" if is_even else "transparent"
                        ports_color = (
                            "green400" if res["ports"] != "Nessuna" else "grey500"
                        )
                        
                        # Colore IP: Verde scuro se corrisponde all'IP locale
                        ip_color = "green800" if res["ip"] == local_ip else None

                        device_row = ft.Container(
                            content=ft.Row([
                                ft.Text(res["name"], expand=3),
                                ft.Text(
                                    res["ip"],
                                    expand=2,
                                    weight=ft.FontWeight.W_500,
                                    color=ip_color,
                                ),
                                ft.Text(res["mac"], expand=3),
                                ft.Text(
                                    res["ports"],
                                    expand=2,
                                    color=ports_color,
                                    weight=ft.FontWeight.BOLD
                                    if res["ports"] != "Nessuna"
                                    else ft.FontWeight.NORMAL,
                                ),
                            ]),
                            bgcolor=row_bg,
                            padding=get_padding(
                                left=15, right=15, top=10, bottom=10
                            ),
                            border=get_border_bottom(1, "outlineVariant"),
                        )

                        devices_listview.controls.append(device_row)
                        page.update()

            status_label.value = (
                f"Completato. Trovati {len(found_devices)} dispositivi attivi."
            )
            progress_bar.visible = False
            scan_btn.disabled = False
            scan_btn.bgcolor = "blue600"
            page.update()

        threading.Thread(target=run_scan, daemon=True).start()

    scan_btn = create_button(
        "Avvia Scansione",
        "search_rounded",
        start_scan,
    )

    page.add(
    ft.Row(
    controls=[
       # Icona SVG nell'intestazione della pagina
                ft.Image(
                    src=SVG_ICON_PATH,
                    width=100,
                    height=100,
                ),
        ft.Text(
            spans=[
                ft.TextSpan(
                    "dBMpire - Network & Port Scanner  ",
                    ft.TextStyle(size=22, weight=ft.FontWeight.BOLD),
                ),
                ft.TextSpan(
                    f"(IP locale: {local_ip})",
                    ft.TextStyle(size=14, color="green"),
                ),
            ]
        ),
    ],
    vertical_alignment=ft.CrossAxisAlignment.CENTER,  # Centra verticalmente l'icona rispetto al testo
    spacing=8,                                        # Spazio tra l'icona e il testo
    ),
        ft.Row([ip_input, scan_btn]),
        status_label,
        progress_bar,
        ft.Divider(),
        table_header,
        ft.Container(
            content=devices_listview,
            expand=True,
            border=get_border_all(1, "outlineVariant"),
            border_radius=get_border_radius(bottom_left=8, bottom_right=8),
        ),
    )


if __name__ == "__main__":
    ft.run(main, assets_dir="assets")