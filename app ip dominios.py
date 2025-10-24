import os
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog  # Añadí filedialog aquí
import json
from datetime import datetime
import shutil
import threading
import subprocess
import re

# Lista de puertos comunes
# lista original y la uno con el rango 1-200 para obtener los ~200 puertos más comunes.
puertos_comunes_original = [21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 137, 138, 139, 143, 161, 162, 389, 443, 445, 514, 587, 636, 993, 995, 1080, 1433, 1521, 1723, 1812, 1813, 2082, 2083, 2086, 2087, 2095, 2096, 2222, 2444, 2483, 2484, 25565, 27017, 27018, 28017, 3000, 3306, 8001, 8008, 8080, 8081, 8088, 8181, 8282, 8443, 8888, 9000, 9001, 9090, 9091, 9200, 9418, 9999, 10000, 10080, 10081, 10082, 10083, 10084, 10085, 10086, 10087, 10088, 10089, 10090, 10091, 10092, 10093, 10094, 10095, 10096, 10097, 10098, 10099, 10100]
# Crear la lista ampliada (1..200) y unir con la original, eliminando duplicados y ordenando.
puertos_comunes = sorted(set(puertos_comunes_original).union(set(range(1, 201))))
# Lista de 100 puertos más comunes — usar puertos 1..100 exactamente
puertos_100 = list(range(1, 101))

# Control del escaneo encapsulado en una clase para evitar globals


class ScanController:
    def __init__(self):
        self.current_scan_proc = None
        self.scan_lock = threading.Lock()
        self.cancel_event = threading.Event()

    def run_nmap_subprocess_scan(self, ip, ports):
        """Método similar a la función anterior, pero usando el estado del objeto.
        Retorna la lista de puertos abiertos.
        """
        # Verificar que el binario nmap esté disponible en PATH
        if shutil.which('nmap') is None:
            try:
                text_output.insert(tk.END, tr('nmap_missing') + "\n")
            except (tk.TclError, RuntimeError):
                pass
            return []

        def ports_to_str(pcoll):
            if isinstance(pcoll, range):
                start = pcoll.start
                end = pcoll.stop - 1
                return f"{start}-{end}"
            try:
                lst = list(pcoll)
            except TypeError:
                return str(pcoll)
            if not lst:
                return ''
            lst_sorted = sorted(set(lst))
            if len(lst_sorted) > 50 and all(b - a == 1 for a, b in zip(lst_sorted, lst_sorted[1:])):
                return f"{lst_sorted[0]}-{lst_sorted[-1]}"
            return ",".join(str(p) for p in lst_sorted)

        ports_str = ports_to_str(ports)

        # Construir args base
        base_args = ['nmap', '-Pn', '-sS', '-n', '-oG', '-', ip]

        # Determinar lista de puertos y si es escaneo de muchos puertos
        try:
            ports_list = list(ports) if not isinstance(ports, (list, tuple)) else list(ports)
        except TypeError:
            ports_list = [ports]
        many_ports = len(ports_list) > 20

        # Evaluar si el usuario pidió modo rápido global
        try:
            fast_user = ('fast_mode_var' in globals() and fast_mode_var is not None and fast_mode_var.get())
        except (tk.TclError, RuntimeError):
            fast_user = False

        # Helper que ejecuta nmap con los args dados y retorna (lines, open_ports, cancelled)
        def _execute_nmap(args_list):
            open_ports_local = []
            all_lines_local = []
            try:
                with self.scan_lock:
                    self.cancel_event.clear()
                    self.current_scan_proc = subprocess.Popen(args_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                for line in self.current_scan_proc.stdout:
                    if self.cancel_event.is_set():
                        break
                    try:
                        text_output.insert(tk.END, line)
                        text_output.see(tk.END)
                    except (tk.TclError, RuntimeError):
                        pass
                    all_lines_local.append(line)
                    m = re.search(r"Ports:\s*(.+)$", line)
                    if m:
                        ports_field = m.group(1).strip()
                        entries = [p.strip() for p in ports_field.split(',')]
                        for entry in entries:
                            parts = entry.split('/')
                            if len(parts) >= 2:
                                try:
                                    port_num = int(parts[0])
                                except ValueError:
                                    continue
                                state = parts[1]
                                if state == 'open' and port_num not in open_ports_local:
                                    open_ports_local.append(port_num)
                                    if self.cancel_event.is_set():
                                        break
                if self.cancel_event.is_set():
                    try:
                        with self.scan_lock:
                            if self.current_scan_proc and self.current_scan_proc.poll() is None:
                                self.current_scan_proc.terminate()
                    except (OSError, subprocess.SubprocessError):
                        pass
                else:
                    try:
                        self.current_scan_proc.wait()
                    except (OSError, InterruptedError, subprocess.SubprocessError):
                        pass
            finally:
                try:
                    with self.scan_lock:
                        self.current_scan_proc = None
                except OSError:
                    pass
            return all_lines_local, open_ports_local, self.cancel_event.is_set()

        # Si hay muchos puertos, aplicamos un flujo en dos fases: quick -> detail
        collected_lines = []
        collected_open = []
        cancelled = False

        if many_ports and not fast_user:
            # Phase 1: quick conservar escaneo sobre la lista completa
            quick_args = list(base_args)
            quick_args[quick_args.index('-oG') if '-oG' in quick_args else -1:quick_args.index('-oG') if '-oG' in quick_args else -1] = quick_args[quick_args.index('-oG') if '-oG' in quick_args else -1:quick_args.index('-oG') if '-oG' in quick_args else -1]
            # Insert '-p ports_str' antes de '-oG'
            # construi quick_args para asegurar orden correcto
            quick_args = ['nmap', '-Pn', '-sS', '-n']
            # usar timing conservador para quick (T2 a menos que el usuario haya elegido un timing más bajo)
            try:
                tval = timing_var.get() if timing_var is not None else 'T2'
                if isinstance(tval, str) and tval.upper() in ('T0','T1'):
                    quick_args.append(f'-{tval.upper()}')
                else:
                    quick_args.append('-T2')
            except (tk.TclError, RuntimeError, NameError):
                quick_args.append('-T2')
            quick_args.extend(['-p', ports_str, '-oG', '-', ip])

            lines_q, open_q, cancelled = _execute_nmap(quick_args)
            collected_lines.extend(lines_q)
            collected_open = list(sorted(set(collected_open + open_q)))
            if cancelled:
                return collected_open

            # Si no hay puertos abiertos detectados, retoma rápido
            if not collected_open:
                try:
                    summary_text = build_summary_text(collected_lines, ports, collected_open, fast_mode=True)
                    try:
                        root.after(0, lambda s=summary_text: show_summary_window(s))
                    except (RuntimeError, tk.TclError):
                        try:
                            show_summary_window(summary_text)
                        except (tk.TclError, RuntimeError):
                            pass
                except Exception:
                    pass
                return collected_open

            # Phase 2: detalle sólo sobre puertos abiertos
            detail_ports_str = ",".join(str(p) for p in sorted(collected_open))
            detail_args = ['nmap', '-Pn', '-sS', '-n']
            # aplicar timing del usuario si solicitó algo más agresivo; si forzó modo rápido, 
            try:
                tval = timing_var.get() if timing_var is not None else None
                if fast_user:
                    detail_args.append('-T4')
                elif isinstance(tval, str) and tval.upper().startswith('T'):
                    detail_args.append(f'-{tval.upper()}')
            except (tk.TclError, RuntimeError, NameError):
                pass

            # Añadir detección de versión/OS/scripts si el usuario los solicitó
            try:
                if version_var is not None and version_var.get():
                    detail_args.extend(['-sV', '-sC'])
            except (tk.TclError, RuntimeError, NameError):
                pass
            try:
                if os_var is not None and os_var.get():
                    detail_args.append('-O')
            except (tk.TclError, RuntimeError, NameError):
                pass
            try:
                if script_var is not None and script_var.get():
                    script_text = script_entry.get().strip() if 'script_entry' in globals() else ''
                    if script_text:
                        detail_args.extend(['--script', script_text])
            except (tk.TclError, RuntimeError, NameError):
                pass
            # Añadir --max-rate sólo si el usuario lo pidió 
            try:
                if 'max_rate_var' in globals() and max_rate_var is not None:
                    mr = max_rate_var.get().strip()
                    if mr:
                        float(mr)
                        detail_args.extend(['--max-rate', mr])
            except Exception:
                try:
                    text_output.insert(tk.END, f"[Aviso] Valor de --max-rate inválido o fallo al procesarlo: {mr}\n")
                except (tk.TclError, RuntimeError):
                    pass

            detail_args.extend(['-p', detail_ports_str, '-oG', '-', ip])
            lines_d, open_d, cancelled = _execute_nmap(detail_args)
            collected_lines.extend(lines_d)
            collected_open = list(sorted(set(collected_open + open_d)))

            # resumen final
            try:
                summary_text = build_summary_text(collected_lines, ports, collected_open, fast_mode=False)
                try:
                    root.after(0, lambda s=summary_text: show_summary_window(s))
                except (RuntimeError, tk.TclError):
                    try:
                        show_summary_window(summary_text)
                    except (tk.TclError, RuntimeError):
                        pass
            except Exception:
                pass

            return collected_open

        # Segun el caso defecto (no many_ports o el usuario forzó fast): comportamiento similar al anterior
        args = ['nmap', '-Pn', '-sS', '-n', '-p', ports_str, '-oG', '-', ip]

        # Timing y demas opciones
        try:
            single_port_fast = len(ports_list) == 1
        except Exception:
            single_port_fast = False

        if single_port_fast and fast_user:
            args.append('-T4')
            args.extend(['--max-retries', '0'])
            args.extend(['--host-timeout', '30s'])

        try:
            if timing_var is not None and timing_var.get() and not fast_user:
                t = timing_var.get()
                if isinstance(t, str) and t.upper().startswith('T'):
                    args.append(f'-{t.upper()}')
        except (tk.TclError, RuntimeError):
            if not fast_user:
                args.append('-T2')

        try:
            if not fast_user and os_var is not None and os_var.get():
                args.append('-O')
        except (tk.TclError, RuntimeError):
            pass

        try:
            if not fast_user and udp_var is not None and udp_var.get():
                args.append('-sU')
        except (tk.TclError, RuntimeError):
            pass

        try:
            if not fast_user and version_var is not None and version_var.get():
                args.extend(['-sV', '-sC'])
        except (tk.TclError, RuntimeError):
            pass

        try:
            if not fast_user and script_var is not None and script_var.get():
                script_text = script_entry.get().strip() if 'script_entry' in globals() else ''
                if script_text:
                    args.extend(['--script', script_text])
        except (tk.TclError, RuntimeError):
            pass

        try:
            if 'max_rate_var' in globals() and max_rate_var is not None:
                mr = max_rate_var.get().strip()
                if mr:
                    float(mr)
                    args.extend(['--max-rate', mr])
        except Exception:
            try:
                text_output.insert(tk.END, "[Aviso] No se pudo procesar --max-rate; se continuará sin él.\n")
            except (tk.TclError, RuntimeError):
                pass

        lines, openp, cancelled = _execute_nmap(args)
        try:
            summary_text = build_summary_text(lines, ports, openp, fast_mode=fast_user)
            try:
                root.after(0, lambda s=summary_text: show_summary_window(s))
            except (RuntimeError, tk.TclError):
                try:
                    show_summary_window(summary_text)
                except (tk.TclError, RuntimeError):
                    pass
        except Exception:
            pass

        return openp

    def stop_scan(self):
        self.cancel_event.set()
        try:
            with self.scan_lock:
                if self.current_scan_proc and self.current_scan_proc.poll() is None:
                    self.current_scan_proc.terminate()
        except (OSError, subprocess.SubprocessError):
            pass


# controlador Instancia global   (se usa en handlers)
controller = ScanController()

# Detección de versión (si se activa, se pasan -sV -sC a nmap)
version_var = None


# Diccionario de servicios comunes por puerto
port_services = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 514: "Syslog", 587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 1812: "Radius", 1813: "Radius", 2082: "cPanel", 2083: "cPanel", 2086: "WHM", 2087: "WHM", 2095: "cPanel", 2096: "cPanel", 2222: "RDP", 2444: "Nessus", 2483: "Oracle", 2484: "Oracle", 25565: "Minecraft", 27017: "MongoDB", 27018: "MongoDB", 28017: "MongoDB", 3000: "Node.js", 3306: "MySQL", 3389: "RDP", 3690: "SVN", 4444: "Blizzard", 5000: "UPnP", 5432: "PostgreSQL", 5500: "VNC", 5601: "Kibana", 5666: "NRPE", 5800: "VNC", 5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6666: "IRC", 6667: "IRC", 7000: "AFP", 7001: "AFP", 7002: "AFP", 7003: "AFP", 7004: "AFP", 8000: "HTTP", 8001: "HTTP", 8008: "HTTP", 8080: "HTTP", 8081: "HTTP", 8088: "HTTP", 8181: "HTTP", 8282: "HTTP", 8443: "HTTPS", 8888: "HTTP", 9000: "HTTP", 9001: "HTTP", 9090: "HTTP", 9091: "HTTP", 9200: "Elasticsearch", 9418: "Git", 9999: "HTTP", 10000: "HTTP", 10080: "HTTP", 10081: "HTTP", 10082: "HTTP", 10083: "HTTP", 10084: "HTTP", 10085: "HTTP", 10086: "HTTP", 10087: "HTTP", 10088: "HTTP", 10089: "HTTP", 10090: "HTTP", 10091: "HTTP", 10092: "HTTP", 10093: "HTTP", 10094: "HTTP", 10095: "HTTP", 10096: "HTTP", 10097: "HTTP", 10098: "HTTP", 10099: "HTTP", 10100: "HTTP"
}

# ==== Traductor (es / en) ====
LANG = 'es'
TRANSLATIONS = {
    'es': {
        'label_ip': 'Ingrese la dirección IP o el dominio:',
        'scan_button': '🔎 Escanear',
        'stop_button': '⏹ Detener escaneo',
        'scan_200': 'Escanear 200 puertos comunes',
        'scan_range': 'Escanear rango de puertos',
        'scan_specific': 'Escanear puerto específico',
        'show_activity': 'Mostrar registro de actividad',
        'save_results': 'Guardar resultados',
        'profile': 'Perfil:',
        'detection_version': 'Detección versión (sV/sC)',
        'detection_os': 'Detección OS (-O)',
        'timing': 'Timing (-T)',
        'udp_scan': 'Escaneo UDP (-sU)',
        'use_scripts': 'Usar scripts NSE',
        'force_fast': 'Forzar modo rápido (más veloz)',
        'max_rate': 'Max rate (--max-rate)',
        'open_common_title': 'Escanear 200 puertos comunes',
        'open_range_title': 'Escanear rango de puertos',
        'open_specific_title': 'Escanear puerto específico',
        'accept': 'Aceptar',
        'copied': 'Copiado',
        'copied_msg': 'Resumen copiado al portapapeles',
        'save': 'Guardar',
        'summary_title': 'Resumen del escaneo',
        'save_summary_title': 'Guardar resumen',
        'save_results_title': 'Guardar resultados',
        'activity_log_title': 'Registro de actividad',
        'last_scan_title': 'Último escaneo',
        'no_entries': 'No hay entradas en el registro.',
        'log_missing': 'No se encontró ningún registro de actividad o el archivo está corrupto. Se creará un nuevo archivo de registro.',
        'error_enter_ip': 'Ingrese una dirección IP o dominio.',
        'no_text_to_save': 'No hay texto para guardar',
        'summary_saved': 'Resumen guardado en {fname}',
        'save_error': 'No se pudo guardar el archivo: {err}',
        'no_results_to_save': 'No hay resultados para guardar.',
        'results_saved': 'Resultados guardados en {fname}',
        'tooltip_scan': 'Inicia el escaneo sobre los 100 puertos más comunes (1-100)',
        'tooltip_stop': 'Detiene el escaneo en curso',
        'tooltip_common': 'Abre ventana para escanear ~200 puertos comunes',
        'tooltip_range': 'Abre ventana para escanear un rango de puertos',
        'tooltip_specific': 'Abre ventana para escanear un puerto específico',
        'tooltip_save': 'Guardar resultados mostrados en archivo de texto',
        'tooltip_log': 'Mostrar registro local de escaneos realizados',
        'profile_values': ['Discreto','Equilibrado','Intenso','Personalizado'],
        'copy': 'Copiar',
        'lang_toggle': 'EN/ES',
    'stop_active': 'Detener (activo)',
    'copy_failed': 'No se pudo copiar al portapapeles',
        'ok': 'OK',
        'accept_btn': 'Aceptar',
        'error_title': 'Error',
        # mensajes de validación de diálogos
        'error_enter_both_ports': 'Por favor, ingrese ambos puertos de inicio y final.',
        'error_ports_int': 'Los puertos de inicio y final deben ser enteros.',
    'start_port': 'Puerto de inicio:',
    'end_port': 'Puerto final:',
    'specific_port': 'Puerto específico:',
        'error_enter_specific': 'Por favor, ingrese un puerto específico.',
        'error_specific_int': 'El puerto específico debe ser un entero.'
        ,
        'nmap_missing': 'nmap no está instalado o no está en PATH. Instala nmap para poder escanear.',
        'scanning_ip': 'Escaneando IP: {ip}',
        'running_nmap': 'Ejecutando escaneo Nmap en los puertos solicitados...',
        'show_last_record': 'Mostrar último registro'
    },
    'en': {
        'label_ip': 'Enter IP or domain:',
        'scan_button': '🔎 Scan',
        'stop_button': '⏹ Stop scan',
        'scan_200': 'Scan 200 common ports',
        'scan_range': 'Scan port range',
        'scan_specific': 'Scan specific port',
        'show_activity': 'Show activity log',
        'save_results': 'Save results',
        'profile': 'Profile:',
        'detection_version': 'Version detection (sV/sC)',
        'detection_os': 'OS detection (-O)',
        'timing': 'Timing (-T)',
        'udp_scan': 'UDP scan (-sU)',
        'use_scripts': 'Use NSE scripts',
        'force_fast': 'Force fast mode (faster)',
        'max_rate': 'Max rate (--max-rate)',
        'open_common_title': 'Scan 200 common ports',
        'open_range_title': 'Scan port range',
        'open_specific_title': 'Scan specific port',
        'accept': 'OK',
        'copied': 'Copied',
        'copied_msg': 'Summary copied to clipboard',
        'save': 'Save',
        'summary_title': 'Scan summary',
        'save_summary_title': 'Save summary',
        'save_results_title': 'Save results',
        'activity_log_title': 'Activity log',
        'last_scan_title': 'Last scan',
        'no_entries': 'No entries in the log.',
        'log_missing': 'No activity log found or file is corrupt. A new log file will be created.',
        'error_enter_ip': 'Please enter an IP address or domain.',
        'no_text_to_save': 'There is no text to save',
        'summary_saved': 'Summary saved to {fname}',
        'save_error': 'Could not save file: {err}',
        'no_results_to_save': 'There are no results to save.',
        'results_saved': 'Results saved to {fname}',
        'tooltip_scan': 'Starts a scan over the 100 most common ports (1-100)',
        'tooltip_stop': 'Stops the running scan',
        'tooltip_common': 'Open window to scan ~200 common ports',
        'tooltip_range': 'Open window to scan a port range',
        'tooltip_specific': 'Open window to scan a specific port',
        'tooltip_save': 'Save the displayed results to a text file',
        'tooltip_log': 'Show local log of performed scans',
        'profile_values': ['Discreet','Balanced','Intense','Custom'],
        'copy': 'Copy',
        'lang_toggle': 'EN/ES',
    'stop_active': 'Stop (active)',
    'copy_failed': 'Could not copy to clipboard',
        'ok': 'OK',
        'accept_btn': 'OK',
        'error_title': 'Error',
        'error_enter_both_ports': 'Please enter both start and end ports.',
        'error_ports_int': 'Start and end ports must be integers.',
    'start_port': 'Start port:',
    'end_port': 'End port:',
    'specific_port': 'Specific port:',
        'error_enter_specific': 'Please enter a specific port.',
        'error_specific_int': 'The specific port must be an integer.'
        ,
        'nmap_missing': 'nmap is not installed or not in PATH. Install nmap to scan.',
        'scanning_ip': 'Scanning IP: {ip}',
        'running_nmap': 'Running Nmap scan on requested ports...',
        'show_last_record': 'Show last record'
    }
}

def tr(key):
    try:
        return TRANSLATIONS.get(LANG, TRANSLATIONS['es']).get(key, key)
    except (AttributeError, KeyError, TypeError):
        return key

TOOLTIPS = {}

def toggle_language():
    # Evitar el uso explícito de la sentencia 'global' para silenciar linters;
    # variable de módulo a través del diccionario globals().
    try:
        current = globals().get('LANG', 'es')
        globals()['LANG'] = 'en' if current == 'es' else 'es'
    except (TypeError, RuntimeError):
        # En caso de cualquier problema con globals()/lectura, asegurar un valor por defecto
        globals()['LANG'] = 'es'
    update_ui_language()

def update_ui_language():
    # Actualiza textos visibles de los widgets (se asume que los widgets existen)
    try:
        label_ip.config(text=tr('label_ip'))
    except NameError:
        pass
    try:
        button_scan_main.config(text=tr('scan_button'))
    except NameError:
        pass
    try:
        button_stop.config(text=tr('stop_button'))
    except NameError:
        pass
    try:
        button_common_scan.config(text=tr('scan_200'))
    except NameError:
        pass
    try:
        button_range_scan.config(text=tr('scan_range'))
    except NameError:
        pass
    try:
        button_specific_scan.config(text=tr('scan_specific'))
    except NameError:
        pass
    try:
        button_log.config(text=tr('show_activity'))
    except NameError:
        pass
    try:
        # button_save puede no existir durante inicializacion; comprobar antes
        if 'button_save' in globals() and button_save is not None:
            button_save.config(text=tr('save_results'))
    except NameError:
        pass
    try:
        # botón junto a 'Guardar resultados' que muestra el último registro
        if 'button_specific_side' in globals() and button_specific_side is not None:
            button_specific_side.config(text=tr('show_last_record'))
    except NameError:
        pass
    try:
        # texto del botón de idioma
        if 'lang_button' in globals() and lang_button is not None:
            lang_button.config(text=tr('lang_toggle'))
    except NameError:
        pass
    try:
        lbl_profile.config(text=tr('profile'))
    except NameError:
        pass
    try:
        timing_label.config(text=tr('timing'))
    except NameError:
        pass
    try:
        lbl_maxrate.config(text=tr('max_rate'))
    except NameError:
        pass
    #panel lateral del checkbuttons 
    try:
        chk_version.config(text=tr('detection_version'))
    except NameError:
        pass
    try:
        chk_os.config(text=tr('detection_os'))
    except NameError:
        pass
    try:
        chk_udp.config(text=tr('udp_scan'))
    except NameError:
        pass
    try:
        chk_script.config(text=tr('use_scripts'))
    except NameError:
        pass
    try:
        chk_fast.config(text=tr('force_fast'))
    except NameError:
        pass
    # valores del combo de perfiles
    try:
        profile_combo['values'] = TRANSLATIONS.get(LANG, TRANSLATIONS['es']).get('profile_values', [])
        # conservar selección posible
        cur = profile_var.get()
        if cur not in profile_combo['values']:
            profile_combo.set(profile_combo['values'][0])
    except (tk.TclError, RuntimeError, KeyError, NameError, AttributeError):
        # se puede actualizar el combo por cualquier razón relacionada con la UI
        # si el objeto no existe, (estamos en init o runtime diferente)
        pass
    #  tooltips textos (TOOLTIPS ahora contiene Tooltip instances)
    for tooltip in list(TOOLTIPS.values()):
        try:
            if hasattr(tooltip, 'set_text'):
                # clave que guarda el tooltip para que set_text
                # determine si debe usar la clave o texto literal.
                keyname = getattr(tooltip, 'key', None)
                if keyname:
                    tooltip.set_text(keyname)
                else:
                    # Forzar reescritura con texto traducido si no hay clave
                    tooltip.set_text(tr(keyname) if keyname else tooltip.text)
        except (tk.TclError, RuntimeError, KeyError, AttributeError):
            continue

    # Fallback robusto: detectar widgets que aún tengan texto literal
    # porque fueron creados antes de toggle) y mapear ese texto a la clave de
    # traducción correspondiente, si existe. Esto corrige casos como "Detección
    # versión (sV/sC)" que no se tradujo en runtime en algunas condiciones.
    try:
        containers = []
        try:
            containers.append(frame)
        except NameError:
            pass
        try:
            containers.append(side_inner)
        except NameError:
            pass
        try:
            containers.append(save_frame)
        except NameError:
            pass

        # Buscar en todas las traducciones la clave cuyo valor coincide con el texto
        for cont in containers:
            try:
                for child in cont.winfo_children():
                    try:
                        cur = None
                        try:
                            cur = child.cget('text')
                        except (tk.TclError, RuntimeError, AttributeError):
                            continue
                        if not cur or not isinstance(cur, str):
                            continue
                        # Buscar la clave por valor en TRANSLATIONS (ambos idiomas)
                        found_key = None
                        for _, mapping in TRANSLATIONS.items():
                            for k, v in mapping.items():
                                try:
                                    # comparar puede lanzar TypeError en casos raros
                                    if v == cur:
                                        found_key = k
                                        break
                                except TypeError:
                                    continue
                            if found_key:
                                break
                        if found_key:
                            try:
                                child.config(text=tr(found_key))
                            except (tk.TclError, RuntimeError, AttributeError):
                                pass
                    except (tk.TclError, RuntimeError, AttributeError):
                        continue
            except (tk.TclError, RuntimeError, AttributeError):
                continue
    except (tk.TclError, RuntimeError, AttributeError):
        # No queremos que un fallback de UI rompa la actualización del idioma
        pass




# Nota: ya no usamos python-nmap (PortScanner). Usamos el binario nmap vía subprocess
# para permitir cancelación y lectura en tiempo real.

def run_nmap_subprocess_scan(ip, ports):
    # Wrapper que delega en el controlador
    return controller.run_nmap_subprocess_scan(ip, ports)


# summarize_nmap_output removed: build_summary_text + show_summary_window se utilizan directamente


def build_summary_text(lines, ports_scanned, open_ports, fast_mode=False):
    """Construye y retorna un texto con el resumen del escaneo.
    Mejora parsing de versiones con varios patrones conocidos en la salida de nmap
    (greppable, normal y líneas de "Service Info").
    """
    scanned_set = set(ports_scanned)
    open_set = set(open_ports)
    closed_set = scanned_set - open_set

    parts = []
    parts.append('\n' + '='*60)
    parts.append('Resumen del escaneo:\n')
    if fast_mode:
        parts.append('(Escaneo ejecutado en modo rápido — detecciones detalladas pueden estar omitidas)\n')
    parts.append(f"Puertos escaneados ({len(scanned_set)}): {', '.join(map(str, sorted(scanned_set)))}\n")
    parts.append(f"Puertos abiertos ({len(open_set)}): {', '.join(map(str, sorted(open_set)))}\n")
    parts.append(f"Puertos cerrados ({len(closed_set)}): {', '.join(map(str, sorted(closed_set)))}\n")

    # Si se pidió detección de versiones, buscar múltiples patrones
    version_lines = []
    if version_var is not None and version_var.get():
        # 1) Buscar líneas con formato típico de nmap normal: '22/tcp open  ssh  OpenSSH 7.2p2 Ubuntu'
        for ln in lines:
            ln_stripped = ln.strip()
            # patrón 1: puerto/tcp ... service ... version
            m1 = re.match(r"^(\d+)/tcp\s+(open|filtered|closed)\s+(\S+)\s+(.*)$", ln_stripped)
            if m1:
                port = m1.group(1)
                state = m1.group(2)
                service = m1.group(3)
                rest = m1.group(4).strip()
                if rest:
                    version_lines.append(f"{port}/tcp {state} {service} — {rest}")
                else:
                    version_lines.append(f"{port}/tcp {state} {service}")
                continue

            # 2) Buscar en la salida greppable (puede contener 'Ports: 22/open/tcp//ssh///')
            gm = re.search(r"(\d+)/tcp\s+([^,\s]+)/tcp(?:[^,]*)/(.*)", ln_stripped)
            if gm:
                # Este patrón es menos fiable; lo usamos como fallback
                version_lines.append(ln_stripped)
                continue

            # 3) Buscar líneas de 'Service Info:' o 'OS:'
            if ln_stripped.lower().startswith('service info:') or 'service info' in ln_stripped.lower() or 'os:' in ln_stripped.lower():
                version_lines.append(ln_stripped)

        if version_lines:
            parts.append('\nServicios y versiones (cuando estén disponibles):')
            for vl in version_lines:
                parts.append(vl)
            parts.append('')
        else:
            parts.append('\n(No se encontraron líneas de versión en la salida de nmap)')
            # Si no hubo líneas de versión, añadir una lista simple de puertos abiertos
            if open_set:
                parts.append('\nDetalle de puertos abiertos:')
                for p in sorted(open_set):
                    svc = port_services.get(p, 'Desconocido')
                    parts.append(f"{p} - {svc}")

    parts.append('\nFin del resumen.')
    parts.append('='*60 + '\n')
    return '\n'.join(parts)


def show_summary_window(text):
    """Muestra el resumen en una ventana separada con botones para copiar y guardar."""
    win = tk.Toplevel(root)
    win.title(tr('summary_title'))
    win.geometry('700x500')

    txt = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=('Consolas', 10))
    txt.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
    txt.insert(tk.END, text)
    txt.see(tk.END)

    btn_frame = ttk.Frame(win)
    btn_frame.pack(fill=tk.X, padx=8, pady=6)

    def copy_to_clipboard():
        try:
            win.clipboard_clear()
            win.clipboard_append(txt.get(1.0, tk.END))
            messagebox.showinfo(tr('copied'), tr('copied_msg'))
        except (tk.TclError, RuntimeError):
            messagebox.showerror(tr('error_title'), tr('copy_failed') if tr('copy_failed') else 'No se pudo copiar al portapapeles')

    def save_summary():
        content = txt.get(1.0, tk.END).strip()
        if not content:
            messagebox.showinfo(tr('save_summary_title'), tr('no_text_to_save'))
            return
        fname = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text files', '*.txt'), ('All files', '*.*')], title=tr('save_summary_title'))
        if not fname:
            return
        try:
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo(tr('save_summary_title'), tr('summary_saved').format(fname=fname))
        except OSError as e:
            messagebox.showerror(tr('error_title'), tr('save_error').format(err=e))

    btn_copy = ttk.Button(btn_frame, text=tr('copy'), command=copy_to_clipboard)
    btn_copy.pack(side=tk.LEFT, padx=4)
    btn_save = ttk.Button(btn_frame, text=tr('save'), command=save_summary)
    btn_save.pack(side=tk.LEFT, padx=4)

def stop_scan():
    """Solicita la cancelación del escaneo en curso delegando en el controlador."""
    try:
        controller.stop_scan()
    except NameError:
        # Si por alguna razón el controlador no existe, ignoramos
        pass

def log_activity(ip, puertos):
    actividad = {
        "ip": ip,
        "puertos": puertos,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    try:
        with open('activity_log.json', 'r+', encoding='utf-8') as archivo:
            datos = json.load(archivo)
            datos.append(actividad)
            archivo.seek(0)
            json.dump(datos, archivo, indent=4, ensure_ascii=False)
    except (FileNotFoundError, json.JSONDecodeError):
        try:
            os.remove('activity_log.json')
        except FileNotFoundError:
            pass
        with open('activity_log.json', 'w', encoding='utf-8') as archivo:
            json.dump([actividad], archivo, indent=4, ensure_ascii=False)

def show_activity_log():
    try:
        with open('activity_log.json', 'r', encoding='utf-8') as archivo:
            datos = json.load(archivo)
            if not datos:
                messagebox.showinfo(tr('activity_log_title'), tr('no_entries'))
                return
            # Toma la última entrada
            last = datos[-1]
            ip = last.get('ip', '<desconocido>')
            puertos = last.get('puertos', [])
            timestamp = last.get('timestamp', '')

            if puertos:
                detalles = []
                for p in sorted(puertos):
                    svc = port_services.get(p, 'Desconocido')
                    detalles.append(f"{p} ({svc})")
                puertos_text = ', '.join(detalles)
            else:
                puertos_text = '(ninguno)'

            log_text = f"{tr('last_scan_title')}:\nIP: {ip}\nPuertos abiertos: {puertos_text}\nFecha y hora: {timestamp}"
            messagebox.showinfo(tr('last_scan_title'), log_text)
    except (FileNotFoundError, json.JSONDecodeError):
        messagebox.showinfo(tr('activity_log_title'), tr('log_missing'))

def scan_ip(ip, puertos):
    if not ip:
        messagebox.showerror(tr('error_title'), tr('error_enter_ip'))
        return
    # Usar nmap como subprocess (soporta cancelación); resultados se escriben en tiempo real
    text_output.delete(1.0, tk.END)
    try:
        text_output.insert(tk.END, tr('scanning_ip').format(ip=ip) + "\n")
        text_output.insert(tk.END, "\n" + tr('running_nmap') + "\n")
    except (tk.TclError, RuntimeError):
        # si no se puede escribir en el text_output, ignora
        pass

    open_ports = run_nmap_subprocess_scan(ip, puertos)
    if open_ports is None:
        # run_nmap_subprocess_scan siempre retorna lista (vacía si no encontró ninguno)
        open_ports = []

    # Log the activity con los puertos abiertos recogidos
    log_activity(ip, open_ports)

# Crear la ventana principal
root = tk.Tk()
root.title("Escáner de Puerto")
# se Ajusta tamaño inicial de la ventana  (si se mueve es mejor dejar grande la interfaz de la venta para que no corte los botones)
root.geometry("1100x680")
root.minsize(1000, 520)

# Use default ttk stilo (con pocos colores personalizados)
TEXT_BG = None
TEXT_FG = None
style = ttk.Style()
try:
    style.theme_use('clam')
except (tk.TclError, RuntimeError):
    pass
style.configure("TButton", font=("Helvetica", 12), padding=10)
style.configure("TLabel", font=("Helvetica", 12), padding=5)
style.configure("TEntry", font=("Helvetica", 12), padding=5)
style.configure("Side.TButton", font=("Helvetica", 10), padding=6)

# Widgets y layout principal: canvas con frame principal y panel lateral
main_canvas = tk.Canvas(root, borderwidth=0, highlightthickness=0)
main_canvas.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))

# Frame que contendrá todo el contenido y que será insertado dentro del canvas

# Frame que contendrá todo el contenido (zona principal + panel lateral)
frame = ttk.Frame(main_canvas, padding="10", style='Main.TFrame')
main_canvas.create_window((0, 0), window=frame, anchor='nw')

# Dentro del frame principal dos columnas: columna 0 = contenido,
# columna 1 = panel lateral. Esto permite que el main_canvas.
frame.grid_columnconfigure(0, weight=1)
# Columna 1 contendrá los botones principales; darle un minsize para evitar recortes
frame.grid_columnconfigure(1, weight=0, minsize=160)

# Ajustar scroll region cuando cambie el contenido
def _on_main_configure(_event=None):
    try:
        main_canvas.configure(scrollregion=main_canvas.bbox('all'))
    except (tk.TclError, RuntimeError):
        pass

frame.bind('<Configure>', _on_main_configure)

# Habilitar scroll del mouse sobre el main_canvas
def _on_main_mousewheel(event):
    try:
        if hasattr(event, 'delta') and event.delta:
            step = int(-1 * (event.delta / 120))
            main_canvas.yview_scroll(step, 'units')
        elif hasattr(event, 'num'):
            if event.num == 4:
                main_canvas.yview_scroll(-1, 'units')
            elif event.num == 5:
                main_canvas.yview_scroll(1, 'units')
    except (tk.TclError, RuntimeError):
        pass

main_canvas.bind_all('<MouseWheel>', _on_main_mousewheel)

# Panel lateral desplazable (contiene controles de escaneo y opciones)
side_frame = ttk.Frame(root, padding="0", style='Side.TFrame')
side_frame.grid(row=0, column=2, sticky=(tk.N, tk.S), padx=(8,10))
# Reduci ligeramente el ancho para evitar recortes de botones en pantallas pequeñas
side_frame.config(width=220)
side_frame.pack_propagate(False)

# Canvas y scrollbar dentro del side_frame para permitir scroll vertical
# (esto seguirá permitiendo scroll independiente cuando el cursor esté en el panel)
side_canvas = tk.Canvas(side_frame, borderwidth=0, highlightthickness=0)
side_scrollbar = ttk.Scrollbar(side_frame, orient=tk.VERTICAL, command=side_canvas.yview)
side_canvas.configure(yscrollcommand=side_scrollbar.set)
side_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
side_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Frame interior que contendrá los widgets reales del panel lateral
side_inner = ttk.Frame(side_canvas, padding="6", style='Side.TFrame')
side_canvas.create_window((0, 0), window=side_inner, anchor='nw')
try:
    side_inner.configure(style='Side.TFrame')
except (tk.TclError, RuntimeError):
    pass

def _on_side_configure(_event=None):
    try:
        side_canvas.configure(scrollregion=side_canvas.bbox('all'))
    except (tk.TclError, RuntimeError):
        pass

side_inner.bind('<Configure>', _on_side_configure)

def _on_side_mousewheel(event):
    try:
        # Diferentes plataformas reportan la rueda distinto
        # Windows/mac: event.delta (multiples of 120), Linux: Button-4/Button-5
        if hasattr(event, 'delta') and event.delta:
            # Scrolling vertical: dividir por 120 para obtener pasos
            step = int(-1 * (event.delta / 120))
            side_canvas.yview_scroll(step, 'units')
        elif hasattr(event, 'num'):
            # Linux: Button-4 (num=4) = up, Button-5 (num=5) = down
            if event.num == 4:
                side_canvas.yview_scroll(-1, 'units')
            elif event.num == 5:
                side_canvas.yview_scroll(1, 'units')
    except (tk.TclError, RuntimeError):
        pass

# Bind mousewheel solo cuando el cursor esté sobre el canvas para evitar
# interferir con otros widgets. También soporta Button-4/5 para X11.
def _bind_scroll_on_enter(_e=None):
    try:
        side_canvas.bind_all('<MouseWheel>', _on_side_mousewheel)
        side_canvas.bind('<Button-4>', _on_side_mousewheel)
        side_canvas.bind('<Button-5>', _on_side_mousewheel)
    except (tk.TclError, RuntimeError):
        pass

def _unbind_scroll_on_leave(_e=None):
    try:
        side_canvas.unbind_all('<MouseWheel>')
        side_canvas.unbind('<Button-4>')
        side_canvas.unbind('<Button-5>')
    except (tk.TclError, RuntimeError):
        pass

side_canvas.bind('<Enter>', _bind_scroll_on_enter)
side_canvas.bind('<Leave>', _unbind_scroll_on_leave)

# se redujo el espaciador superior para mostrar más controles al inicio
side_spacer = ttk.Label(side_inner, text='')
side_spacer.pack(pady=12)

# Nota: el botón de alternar idioma se colocará junto a la entrada IP para que no se corte

# Cargar iconos desde carpeta 'icons' (fallback a imágenes pequeñas)
icon_stop = icon_search = icon_range = icon_specific = None
try:
    base_dir = os.path.dirname(__file__)
except NameError:
    base_dir = '.'
icons_dir = os.path.join(base_dir, 'icons')
def try_load(fname):
    path1 = os.path.join(icons_dir, fname)
    path2 = os.path.join(base_dir, fname)
    for p in (path1, path2):
        try:
            if os.path.exists(p):
                return tk.PhotoImage(file=p)
        except (tk.TclError, OSError):
            # aqui carga la imagen si no -> ignorar y probar siguiente
            continue
    return None

icon_stop = try_load('stop.png') or try_load('icon_stop.png')
icon_search = try_load('search.png') or try_load('icon_search.png')
icon_range = try_load('range.png') or try_load('icon_range.png')
icon_specific = try_load('target.png') or try_load('icon_target.png')

# Si no hay PNG, usar iconos base64 pequeños como fallback (gif 1x1 placeholder repetar el 1x1 o agrandar la interfaz).
gif_b64 = 'R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=='
try:
    if not icon_stop:
        icon_stop = tk.PhotoImage(data=gif_b64)
    if not icon_search:
        icon_search = tk.PhotoImage(data=gif_b64)
    if not icon_range:
        icon_range = tk.PhotoImage(data=gif_b64)
    if not icon_specific:
        icon_specific = tk.PhotoImage(data=gif_b64)
except (tk.TclError, RuntimeError, OSError):
    # Si falla la creación de PhotoImage, deja los iconos en None
    icon_stop = icon_search = icon_range = icon_specific = None

# esto permite que el frame principal y el root se expandan correctamente
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(0, weight=1)

label_ip = ttk.Label(frame, text=tr('label_ip'))
label_ip.grid(row=0, column=0, pady=5, sticky=tk.W)

#entrada IP con apariencia 'transparente' ajustando su estilo/fg/bg
entry_ip = ttk.Entry(frame, width=50, style='TEntry')
entry_ip.grid(row=1, column=0, pady=5, sticky=tk.W)

# Botón para alternar idioma 
try:
    lang_button = ttk.Button(frame, text=tr('lang_toggle'), command=toggle_language, style='Side.TButton')
    # Colocar junto a la etiqueta (fila 0) pero alineado a la derecha de la columna 1
    lang_button.grid(row=0, column=1, sticky=tk.E, padx=(6,0))
except (tk.TclError, RuntimeError, NameError):
    
    pass

# Botones principales (scan/stop)
scan_frame = ttk.Frame(frame)
scan_frame.grid(row=1, column=1, padx=(0,6), pady=5, sticky=tk.E)

def _on_scan_click():
    try:
        threaded_scan(entry_ip.get(), puertos_100, None)
    except (RuntimeError, tk.TclError):
        pass

# Usamos un botón tk simple para poder controlar el fondo (blanco/gris) y
# crear un efecto de "alumbrado" alternando el color. Te invito a que lo cambies.
if icon_search:
    #icono, lo usamos en el lado izquierdo del texto
    button_scan_main = tk.Button(scan_frame, text=tr('scan_button'), image=icon_search, compound=tk.LEFT, command=_on_scan_click, bd=0)
else:
    button_scan_main = tk.Button(scan_frame, text=tr('scan_button'), command=_on_scan_click, bd=0)
button_scan_main.pack(side=tk.TOP, fill=tk.X)
try:
    # color inicial y activebackground 
    # Color blanco puro para que sea visible
    button_scan_main.config(bg='#ffffff', activebackground='#ffffff', fg='black')
except (tk.TclError, RuntimeError):
    pass

# Efecto visual: alterna el fondo del botón principal periódicamente (toggle)
_scan_light_state = {'on': False}
def _toggle_scan_light():
    try:
        root.after(600, _toggle_scan_light)
    except (tk.TclError, RuntimeError):
        return
    muted_red = '#d96b6b'
    try:
        if _scan_light_state.get('on'):
            try:
                button_scan_main.config(bg='#ffffff', activebackground='#ffffff', highlightbackground='#ffffff', fg='black')
            except tk.TclError:
                try:
                    button_scan_main.config(bg='white', activebackground='white', fg='black')
                except (tk.TclError, RuntimeError):
                    pass
            _scan_light_state['on'] = False
        else:
            try:
                button_scan_main.config(bg=muted_red, activebackground=muted_red, highlightbackground=muted_red, fg='white')
            except tk.TclError:
                try:
                    button_scan_main.config(bg='#f0b0b0', activebackground='#f0b0b0', highlightbackground='#f0b0b0', fg='black')
                except (tk.TclError, RuntimeError):
                    pass
            _scan_light_state['on'] = True
    except (tk.TclError, RuntimeError):
        return

try:
    root.after(600, _toggle_scan_light)
except (tk.TclError, RuntimeError):
    pass
# unicamente _toggle_scan_light para alternar el color de fondo.

# Botón 'Detener' debajo del botón Escanear; comienza deshabilitado hasta empezar un escaneo
if icon_stop:
    button_stop = ttk.Button(scan_frame, text=tr('stop_button'), image=icon_stop, compound=tk.LEFT, command=stop_scan, style='Side.TButton')
else:
    button_stop = ttk.Button(scan_frame, text=tr('stop_button'), command=stop_scan)
button_stop.pack(side=tk.TOP, fill=tk.X, pady=(6,0))
button_stop.config(state='disabled')

# Opciones avanzadas: colocarlas en el panel lateral para que siempre sean visibles
# Variables de control
version_var = tk.BooleanVar(value=False)
os_var = tk.BooleanVar(value=False)
timing_var = tk.StringVar(value='T2')
udp_var = tk.BooleanVar(value=False)
script_var = tk.BooleanVar(value=False)
# Variable para forzar modo rápido
fast_mode_var = tk.BooleanVar(value=False)

# Sección de perfil (preset) en side_inner
lbl_profile = ttk.Label(side_inner, text=tr('profile'))
lbl_profile.pack(pady=(4,0), anchor=tk.W)
profile_var = tk.StringVar(value=(TRANSLATIONS.get(LANG, TRANSLATIONS['es']).get('profile_values', ['Discreto'])[0]))
profile_combo = ttk.Combobox(side_inner, textvariable=profile_var, values=TRANSLATIONS.get(LANG, TRANSLATIONS['es']).get('profile_values', ['Discreto','Equilibrado','Intenso','Personalizado']), state='readonly')
profile_combo.pack(fill=tk.X, pady=2)
profile_combo.set(profile_var.get())

def apply_profile(event=None):
    # El evento es opcional, por lo que se puede usar como devolución de llamada para Combobo x Selected
    _ = event
    p = profile_var.get()
    if p == 'Discreto':
        timing_var.set('T2')
        os_var.set(False)
        version_var.set(False)
        udp_var.set(False)
        script_var.set(False)
        # Sin marcador de posición: script_entry permanece deshabilitado a menos que el usuario habilite los scripts
    elif p == 'Equilibrado':
        timing_var.set('T3')
        os_var.set(False)
        version_var.set(True)
        udp_var.set(False)
        script_var.set(False)
    elif p == 'Intenso':
        timing_var.set('T4')
        os_var.set(True)
        version_var.set(True)
        udp_var.set(False)
        script_var.set(True)
    # 'Personalizado' deja las opciones como estan

# bind unchanged
profile_combo.bind('<<ComboboxSelected>>', apply_profile)

# los checkbuttons y controles en el side_inner
chk_version = ttk.Checkbutton(side_inner, text=tr('detection_version'), variable=version_var)
chk_version.pack(fill=tk.X, pady=2)
chk_os = ttk.Checkbutton(side_inner, text=tr('detection_os'), variable=os_var)
chk_os.pack(fill=tk.X, pady=2)

# Timing combobox en side_inner
timing_label = ttk.Label(side_inner, text=tr('timing'))
timing_label.pack(anchor=tk.W, pady=(6,0))
# T0..T5 para cubrir las opciones de timing
timing_combo = ttk.Combobox(side_inner, textvariable=timing_var, values=['T0','T1','T2','T3','T4','T5'], state='readonly', width=6)
timing_combo.pack(fill=tk.X, pady=2)
timing_combo.set('T2')

chk_udp = ttk.Checkbutton(side_inner, text=tr('udp_scan'), variable=udp_var)
chk_udp.pack(fill=tk.X, pady=2)

chk_script = ttk.Checkbutton(side_inner, text=tr('use_scripts'), variable=script_var)
chk_script.pack(fill=tk.X, pady=2)
# La entrada del script comienza deshabilitada hasta que los scripts estén habilitados para evitar confusiones con 'predeterminado'
script_entry = ttk.Entry(side_inner, width=20, state='disabled')
script_entry.pack(fill=tk.X, pady=2)

def on_script_toggle():
    try:
        if script_var.get():
            script_entry.config(state='normal')
            # elimina cualquier marcador de posición
            try:
                script_entry.delete(0, tk.END)
            except (tk.TclError, RuntimeError):
                pass
        else:
            try:
                script_entry.delete(0, tk.END)
            except (tk.TclError, RuntimeError):
                pass
            script_entry.config(state='disabled')
    except (tk.TclError, RuntimeError):
        pass

# Enlazar trazas para habilitar/deshabilitar el campo de scripts (compatibilidad entre versiones)
try:
    script_var.trace_add('write', lambda *args: on_script_toggle())
except AttributeError:
    try:
        script_var.trace('w', lambda *args: on_script_toggle())
    except (tk.TclError, RuntimeError):
        pass

# Opción para forzar modo rápido (reduce checks para aumentar velocidad)
chk_fast = ttk.Checkbutton(side_inner, text=tr('force_fast'), variable=fast_mode_var)
chk_fast.pack(fill=tk.X, pady=2)

# control: --max-rate para nmap (presets + Custom)
max_rate_var = tk.StringVar(value='')
max_rate_choice_var = tk.StringVar(value='(none)')
lbl_maxrate = ttk.Label(side_inner, text=tr('max_rate'))
lbl_maxrate.pack(anchor=tk.W, pady=(8,0))
# Combobox de presets
maxrate_values = ['(none)', '100', '500', '1000', '5000', '10000', 'Custom...']
maxrate_combo = ttk.Combobox(side_inner, textvariable=max_rate_choice_var, values=maxrate_values, state='readonly', width=12)
maxrate_combo.pack(fill=tk.X, pady=2)

# Entrada para valor custom (inicialmente deshabilitada)
entry_maxrate = ttk.Entry(side_inner, textvariable=max_rate_var, width=12, state='disabled')
entry_maxrate.pack(fill=tk.X, pady=(2,6))

def on_maxrate_choice(_event=None):
    choice = max_rate_choice_var.get()
    try:
        if choice == '(none)':
            max_rate_var.set('')
            entry_maxrate.config(state='disabled')
        elif choice == 'Custom...':
            # entrada habilitada para que el usuario escriba lo que busca
            entry_maxrate.config(state='normal')
            max_rate_var.set('')
            entry_maxrate.focus_set()
        else:
            # preestablecido seleccionado
            max_rate_var.set(choice)
            entry_maxrate.config(state='disabled')
    except (tk.TclError, RuntimeError):
        pass

maxrate_combo.bind('<<ComboboxSelected>>', on_maxrate_choice)

# Aplicar perfil inicial
apply_profile()

# Área de resultados: ScrolledText monoespaciado (sin wrap)
if TEXT_BG is None:
    text_output = scrolledtext.ScrolledText(frame, height=12, width=100, wrap=tk.NONE, font=("Consolas", 10), relief=tk.SUNKEN, borderwidth=1)
else:
    text_output = scrolledtext.ScrolledText(frame, height=12, width=100, wrap=tk.NONE, font=("Consolas", 10), background=TEXT_BG, foreground=TEXT_FG, relief=tk.SUNKEN, borderwidth=1)
text_output.grid(row=3, column=0, columnspan=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))

# Scrollbar horizontal para leer salidas largas de nmap
hscroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=text_output.xview)
hscroll.grid(row=4, column=0, columnspan=5, sticky=(tk.W, tk.E))
text_output.configure(xscrollcommand=hscroll.set)

# Barra de scroll/sea para desplazamiento rápido (scale)
# Barra de progreso (indeterminada) para indicar actividad durante el escaneo
progress = ttk.Progressbar(frame, mode='indeterminate', length=600)
progress.grid(row=5, column=0, columnspan=6, pady=5, sticky=(tk.W, tk.E))

# un pequeño frame bajo la progressbar para acciones globales (guardar)
save_frame = ttk.Frame(frame)
save_frame.grid(row=6, column=0, columnspan=6, sticky=(tk.W, tk.E), pady=(6,8))

# (El botón de guardar se creará más abajo, después de la definición de save_results_to_file)
# (Se elimina la creación duplicada de button_stop en el panel lateral)

def set_main_buttons_state(state: str):
    """Habilita o deshabilita los botones principales de la ventana."""
    try:
        button_scan_main.config(state=state)
        button_common_scan.config(state=state)
        button_range_scan.config(state=state)
        button_specific_scan.config(state=state)
        button_log.config(state=state)
    except NameError:
        # Algunos botones aún no existen durante la inicialización; ignorar
        pass

def threaded_scan(ip, puertos, caller_button=None):
    """Ejecuta scan_ip en un hilo para no bloquear la interfaz."""
    def worker():
        set_main_buttons_state('disabled')
        # boton detener: habilitar y marcar como activo
        try:
            button_stop.config(state='normal')
        except (tk.TclError, AttributeError, RuntimeError):
            # Si no existe o no se puede actualizar,
            pass
        else:
            try:
                button_stop.config(text=tr('stop_active'))
            except (tk.TclError, AttributeError, RuntimeError):
                pass
        if caller_button:
            try:
                caller_button.config(state='disabled')
            except (AttributeError, tk.TclError):
                pass
        progress.start(10)
        try:
            scan_ip(ip, puertos)
        finally:
            progress.stop()
            set_main_buttons_state('normal')
            # Restaurar el botón detener a estado inicial (deshabilitado)
            try:
                try:
                    button_stop.config(text=tr('stop_button'))
                except (tk.TclError, AttributeError, RuntimeError):
                    pass
                button_stop.config(state='disabled')
            except (tk.TclError, AttributeError, RuntimeError):
                pass
            if caller_button:
                try:
                    caller_button.config(state='normal')
                except (AttributeError, tk.TclError):
                    pass

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

def save_results_to_file():
    content = text_output.get(1.0, tk.END).strip()
    if not content:
        messagebox.showinfo(tr('save_results_title'), tr('no_results_to_save'))
        return
    fname = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text files', '*.txt'), ('All files', '*.*')], title=tr('save_results_title'))
    if not fname:
        return
    try:
        with open(fname, 'w', encoding='utf-8') as f:
            f.write(content)
        messagebox.showinfo(tr('save_results_title'), tr('results_saved').format(fname=fname))
    except OSError as e:
        messagebox.showerror(tr('error_title'), tr('save_error').format(err=e))

# boton de guardar resultados ahora que la función existe
if 'save_frame' in globals():
    try:
        # Usaremos grid dentro de save_frame para poder colocar otros botones al lado
        save_frame.grid_columnconfigure(0, weight=1)
        save_frame.grid_columnconfigure(1, weight=0)
        if icon_stop:
            button_save = ttk.Button(save_frame, text=tr('save_results'), image=icon_stop, compound=tk.LEFT, command=save_results_to_file, style='Side.TButton')
        else:
            button_save = ttk.Button(save_frame, text=tr('save_results'), command=save_results_to_file, style='Side.TButton')
        button_save.grid(row=0, column=0, sticky=tk.W, padx=6, pady=4)
    except (tk.TclError, RuntimeError, OSError):
        # Si algo falla con grid o image, creamos un botón 
        try:
            button_save = ttk.Button(save_frame, text=tr('save_results'), command=save_results_to_file)
            button_save.grid(row=0, column=0, sticky=tk.W, padx=6, pady=4)
        except (tk.TclError, RuntimeError, OSError):
            pass
    
    try:
        
        # "Guardar resultados" abrirá el registro más reciente.
        if icon_specific:
            button_specific_side = ttk.Button(save_frame, text=tr('show_last_record'), image=icon_specific, compound=tk.LEFT, command=show_activity_log, style='Side.TButton')
        else:
            button_specific_side = ttk.Button(save_frame, text=tr('show_last_record'), command=show_activity_log, style='Side.TButton')
        button_specific_side.grid(row=0, column=1, sticky=tk.E, padx=6, pady=4)
    except (tk.TclError, RuntimeError, OSError):
        try:
            button_specific_side = ttk.Button(save_frame, text=tr('show_last_record'), command=show_activity_log)
            button_specific_side.grid(row=0, column=1, sticky=tk.E, padx=6, pady=4)
        except (tk.TclError, RuntimeError):
            pass

# Botones "Mostrar registro" y "Guardar resultados"
action_frame = ttk.Frame(frame)
action_frame.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)

# Funciones para abrir nuevas ventanas
def open_common_scan():
    common_scan_window = tk.Toplevel(root)
    common_scan_window.title(tr('open_common_title'))

    try:
        main_x = root.winfo_x()
        main_y = root.winfo_y()
        main_w = root.winfo_width()
        # ventana desplazada a la derecha del main
        common_scan_window.geometry(f"400x220+{main_x + main_w + 20}+{main_y + 20}")
    except (tk.TclError, RuntimeError):
        # geometría 
        common_scan_window.geometry("400x220")

    label_ip_common = ttk.Label(common_scan_window, text=tr('label_ip'))
    label_ip_common.pack(pady=5)
    entry_ip_common = ttk.Entry(common_scan_window, width=50)
    entry_ip_common.pack(pady=5)

    # botón primero (sin command) para poder pasarlo a threaded_scan desde la función
    button_scan_common = ttk.Button(common_scan_window, text=tr('scan_button'))

    def on_scan_common():
        ip = entry_ip_common.get()
        if not ip:
            messagebox.showerror(tr('error_title'), tr('error_enter_ip'))
            return
        # Esta opción lanzará el escaneo sobre la lista de ~200 puertos comunes
        threaded_scan(ip, puertos_comunes, button_scan_common)

    button_scan_common.config(command=on_scan_common)
    button_scan_common.pack(pady=5)

def open_range_scan():
    range_scan_window = tk.Toplevel(root)
    range_scan_window.title(tr('open_range_title'))
    # ventana un poco más alta para que el botón 'Aceptar' no quede cortado
    range_scan_window.geometry("420x320")

    label_ip_range = ttk.Label(range_scan_window, text=tr('label_ip'))
    label_ip_range.pack(pady=5)
    entry_ip_range = ttk.Entry(range_scan_window, width=50)
    entry_ip_range.pack(pady=5)
    label_start_port = ttk.Label(range_scan_window, text=tr('start_port'))
    label_start_port.pack(pady=5)
    entry_start_port = ttk.Entry(range_scan_window, width=10)
    entry_start_port.pack(pady=5)
    label_end_port = ttk.Label(range_scan_window, text=tr('end_port'))
    label_end_port.pack(pady=5)
    entry_end_port = ttk.Entry(range_scan_window, width=10)
    entry_end_port.pack(pady=5)

    # Usamos texto 'Aceptar' para que sea evidente cómo confirmar los valores
    button_scan_range = ttk.Button(range_scan_window, text=tr('accept'))

    def on_scan_range():
        ip = entry_ip_range.get()
        start_port = entry_start_port.get()
        end_port = entry_end_port.get()
        if not ip:
            messagebox.showerror(tr('error_title'), tr('error_enter_ip'))
            return
        if not start_port or not end_port:
            messagebox.showerror(tr('error_title'), tr('error_enter_both_ports'))
            return
        try:
            start_port_int = int(start_port)
            end_port_int = int(end_port)
        except ValueError:
            messagebox.showerror(tr('error_title'), tr('error_ports_int'))
            return
        threaded_scan(ip, range(start_port_int, end_port_int + 1), button_scan_range)

    button_scan_range.config(command=on_scan_range)
    button_scan_range.pack(pady=10)

def open_specific_scan():
    specific_scan_window = tk.Toplevel(root)
    specific_scan_window.title(tr('open_specific_title'))
    # Aumentar ligeramente la altura y posicionar un poco más arriba para evitar recorte
    try:
        main_x = root.winfo_x()
        main_y = root.winfo_y()
        pos_y = max(0, main_y - 40)
        specific_scan_window.geometry(f"400x240+{main_x + 60}+{pos_y}")
    except (tk.TclError, RuntimeError):
        specific_scan_window.geometry("420x240")

    label_ip_specific = ttk.Label(specific_scan_window, text=tr('label_ip'))
    label_ip_specific.pack(pady=5)
    entry_ip_specific = ttk.Entry(specific_scan_window, width=50)
    entry_ip_specific.pack(pady=5)
    label_specific_port = ttk.Label(specific_scan_window, text=tr('specific_port'))
    label_specific_port.pack(pady=5)
    entry_specific_port = ttk.Entry(specific_scan_window, width=10)
    entry_specific_port.pack(pady=5)

    # Botón de aceptación
    button_scan_specific = ttk.Button(specific_scan_window, text=tr('accept'))

    def on_scan_specific():
        ip = entry_ip_specific.get()
        specific_port = entry_specific_port.get()
        if not ip:
            messagebox.showerror(tr('error_title'), tr('error_enter_ip'))
            return
        if not specific_port:
            messagebox.showerror(tr('error_title'), tr('error_enter_specific'))
            return
        try:
            specific_port_int = int(specific_port)
        except ValueError:
            messagebox.showerror(tr('error_title'), tr('error_specific_int'))
            return
        threaded_scan(ip, [specific_port_int], button_scan_specific)

    button_scan_specific.config(command=on_scan_specific)
    button_scan_specific.pack(pady=8)

# Botones para abrir las nuevas ventanas (guardar se colocará al final)

if icon_search:
    button_common_scan = ttk.Button(side_inner, text=tr('scan_200'), image=icon_search, compound=tk.LEFT, command=open_common_scan, style='Side.TButton')
else:
    button_common_scan = ttk.Button(side_inner, text=tr('scan_200'), command=open_common_scan, style='Side.TButton')
button_common_scan.pack(fill=tk.X, pady=6, ipadx=6)

if icon_range:
    button_range_scan = ttk.Button(side_inner, text=tr('scan_range'), image=icon_range, compound=tk.LEFT, command=open_range_scan, style='Side.TButton')
else:
    button_range_scan = ttk.Button(side_inner, text=tr('scan_range'), command=open_range_scan, style='Side.TButton')
button_range_scan.pack(fill=tk.X, pady=6, ipadx=6)

if icon_specific:
    button_specific_scan = ttk.Button(side_inner, text=tr('scan_specific'), image=icon_specific, compound=tk.LEFT, command=open_specific_scan, style='Side.TButton')
else:
    button_specific_scan = ttk.Button(side_inner, text=tr('scan_specific'), command=open_specific_scan, style='Side.TButton')
button_specific_scan.pack(fill=tk.X, pady=6, ipadx=6)

# boton panel lateral justo debajo de 'Escanear puerto específico'
button_log = ttk.Button(side_inner, text=tr('show_activity'), command=show_activity_log, style='Side.TButton')
button_log.pack(fill=tk.X, pady=(4,10), ipadx=6)

# (boton de guardar en el área principal, debajo de la barra de progreso)

# (Los botones de registro y guardar han sido colocados en el frame principal debajo de la barra de búsqueda)

# núcleo principal de la ventana
class Tooltip:
    """Tooltips simples para tkinter widgets.

    Ahora registramos la instancia en TOOLTIPS y aceptamos una clave de
    traducción (por ejemplo 'tooltip_scan') para que el texto se actualice
    automáticamente cuando cambie el idioma.
    """
    def __init__(self, widget, key, delay=400):
        # key: clave de traducción dentro de TRANSLATIONS (ej. 'tooltip_scan')
        self.widget = widget
        self.key = key
        self.delay = delay
        self._id = None
        self.tipwindow = None
        self.text = None
        widget.bind('<Enter>', self._schedule)
        widget.bind('<Leave>', self._hide)
        # instancia para poder actualizar idioma desde update_ui_language
        try:
            TOOLTIPS[widget] = self
        except (TypeError, RuntimeError, tk.TclError):
            pass

    def _schedule(self, _event=None):
        self._id = self.widget.after(self.delay, self._show)

    def _show(self):
        if self.tipwindow:
            return
        try:
            x, y, _cx, _cy = self.widget.bbox('insert')
        except (tk.TclError, TypeError, IndexError, AttributeError):
            x, y = 0, 0
        x = x + self.widget.winfo_rootx() + 25
        y = y + self.widget.winfo_rooty() + 20
        # Obtener texto traducido al mostrar (permite cambios dinámicos de idioma)
        txt = tr(self.key) if isinstance(self.key, str) else (self.text or '')
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=txt, justify=tk.LEFT, background="#ffffe0", relief=tk.SOLID, borderwidth=1, font=("tahoma", "8", "normal"))
        label.pack(ipadx=4, ipady=2)

    def _hide(self, _event=None):
        if self._id:
            try:
                self.widget.after_cancel(self._id)
            except (tk.TclError, RuntimeError):
                pass
            self._id = None
        if self.tipwindow:
            try:
                self.tipwindow.destroy()
            except (tk.TclError, RuntimeError):
                pass
            self.tipwindow = None

    def set_text(self, new_text):
        # new_text puede ser una cadena ya traducida o una clave; almacenamos la clave
        try:
            if isinstance(new_text, str) and new_text in TRANSLATIONS.get(LANG, TRANSLATIONS['es']):
                self.key = new_text
            else:
                self.text = new_text
                self.key = None
        except (TypeError, RuntimeError, tk.TclError):
            pass


# Attach tooltips to main controls (widgets)
for w, tip_key in [
    (button_scan_main, 'tooltip_scan'),
    (button_stop, 'tooltip_stop'),
    (button_common_scan, 'tooltip_common'),
    (button_range_scan, 'tooltip_range'),
    (button_specific_scan, 'tooltip_specific'),
    (button_save, 'tooltip_save'),
    (button_log, 'tooltip_log'),
]:
    try:
        # Pasamos la clave (no el texto traducido) para que el Tooltip pueda
        # mostrar el texto correcto y actualizarlo cuando cambie el idioma.
        Tooltip(w, tip_key)
    except (NameError, tk.TclError, RuntimeError):
        continue

root.mainloop()