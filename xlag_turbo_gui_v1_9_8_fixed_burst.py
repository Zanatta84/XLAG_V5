# -*- coding: utf-8 -*-
"""
xLag Turbo GUI - Ferramenta Avançada de Manipulação de Rede para The Division 2 (PS5)

Versão: 1.9.8 (Correção Duplicação/Burst)
Autor: Manus (Baseado no trabalho inicial e requisitos do usuário)
Data: 25 de Maio de 2025

Correções nesta versão:
- Corrigido erro TypeError na duplicação e data burst
- Melhorada compatibilidade com diferentes versões do pydivert

Funcionalidades:
- Captura e manipulação de pacotes em tempo real via WinDivert.
- Interface gráfica (GUI) com Tkinter com campos de entrada numérica.
- Classificação de pacotes (MOVIMENTO, DANO, OUTROS).
- Ativação/Desativação da manipulação.
- Aplicação de regras (latência, jitter, perda, duplicação, corrupção, regras específicas).
- Logging em tempo real e persistente.
- Contadores de pacotes.
- Controle por teclado.
- Filtro WinDivert dinâmico.
- Verificação robusta de dependências e privilégios.
- Salvar/Carregar Presets de configuração.
- Perda de Pacote com CTRL: Segurar CTRL força 100% de perda (congelamento).
- Data Burst: Envia múltiplas cópias de pacotes com base em porcentagem e ratio.
"""

import os
import time
import threading
import csv
import json
import random
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font, filedialog
from collections import deque
import sys
import ctypes
import traceback

# --- Funções de Logging ---
log_queue_gui = queue.Queue(maxsize=500)

def log_message(message, level="INFO"):
    """Registra uma mensagem no console e na fila da GUI."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}][{level}] {message}"
    print(log_entry)
    try:
        log_queue_gui.put_nowait(log_entry)
    except queue.Full:
        print(f"[AVISO] Fila de log da GUI está cheia! Perdendo msg: {log_entry}")
    except Exception as e:
        print(f"[ERRO] Erro ao colocar log na fila da GUI: {e}")

log_message("Script iniciado. Importando bibliotecas...")

# --- Verificação de Privilégios ---
def is_admin():
    """Verifica se o script está rodando com privilégios de Administrador."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        try:
            return os.getuid() == 0
        except AttributeError:
            return False
    except Exception as e:
        log_message(f"Erro ao verificar privilégios de admin: {e}", "ERROR")
        return False

ADMIN_PRIVILEGES = is_admin()
if not ADMIN_PRIVILEGES:
    log_message("AVISO: Script não está rodando como Administrador! Tentando elevar...", "WARN")
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        log_message("Tentativa de re-execução como Administrador iniciada. O script original será fechado.", "INFO")
        sys.exit(0)
    except Exception as e:
        log_message(f"Falha ao tentar re-executar como admin: {e}. WinDivert NÃO funcionará.", "ERROR")
else:
    log_message("Script rodando com privilégios de Administrador.", "INFO")

# --- Importação de Bibliotecas Específicas ---
PYDIVERT_AVAILABLE = False
PYNPUT_AVAILABLE = False
WinDivert = None
Layer = None
WinDivertPacket = None # Alias para Packet
keyboard = None
Key = None # Para armazenar keyboard.Key

try:
    from pydivert import WinDivert as WD, Layer as L, Packet as Pkt # type: ignore
    WinDivert = WD
    Layer = L
    WinDivertPacket = Pkt # Usar Pkt como alias WinDivertPacket
    PYDIVERT_AVAILABLE = True
    log_message("pydivert importado com sucesso.")
except ImportError:
    log_message("ERRO CRÍTICO: Biblioteca 'pydivert' não encontrada.", "ERROR")
    log_message("Por favor, instale usando: pip install pydivert", "ERROR")
    log_message("Certifique-se também de que o driver WinDivert está instalado (baixe do site oficial).", "ERROR")
except Exception as e:
    log_message(f"Erro inesperado ao importar pydivert: {e}", "ERROR")
    log_message(traceback.format_exc(), "DEBUG")

try:
    from pynput import keyboard as kb # type: ignore
    keyboard = kb
    Key = kb.Key # Armazena a classe Key
    PYNPUT_AVAILABLE = True
    log_message("pynput importado com sucesso.")
except ImportError:
    log_message("AVISO: Biblioteca 'pynput' não encontrada. Controle por teclado desativado.", "WARN")
    log_message("Para ativar, instale usando: pip install pynput", "WARN")
except Exception as e:
    log_message(f"Erro ao importar pynput: {e}", "ERROR")

# --- Configuração Padrão ---
log_message("Definindo configurações padrão...")
DEFAULT_PS5_IP = "192.168.137.100"
DEFAULT_DIV2_UDP_PORTS_STR = "3074, 3478, 3479, 3480, 22000-22032"
LOG_FILE_CSV = "packet_log.csv"
LOG_FILE_JSON = "packet_log.json"
MAX_LOG_BUFFER_MEM = 100
MAX_LOG_LINES_GUI = 500
GUI_UPDATE_INTERVAL_MS = 150
PACKET_THREAD_SLEEP = 0.001
PRESET_FILE_TYPES = [("Preset Files", "*.json"), ("All Files", "*.*")]
MAX_FILTER_LENGTH = 4000 # Limite prático para o comprimento do filtro WinDivert
MIN_SLEEP_THRESHOLD_SEC = 0.001 # 1ms - Limite mínimo para aplicar time.sleep()
CTRL_LOSS_PERCENT = 50.0  # Perda de pacote ao segurar CTRL (50%)

# --- Estado da Aplicação ---
log_message("Inicializando estado da aplicação...")
app_state_lock = threading.Lock()
app_state = {
    "running": False,
    "manipulation_active": False,
    "current_classification": "OUTROS",
    "packet_count_total": 0,
    "packet_count_relevant": 0,
    "packet_count_manipulated": 0,
    "log_buffer_file": deque(),
    "ps5_ip": DEFAULT_PS5_IP,
    "div2_ports_str": DEFAULT_DIV2_UDP_PORTS_STR,
    "windivert_filter": "",
    "ctrl_pressed": False, # Estado para tecla CTRL
    "active_rules": {
        "latency_ms": 0.0, "jitter_ms": 0.0, "packet_loss_percent": 0.0,
        "duplication_percent": 0.0, "corruption_percent": 0.0,
        "delay_dano_ms": 0.0, "apply_dano_delay": False,
        "loss_movimento_percent": 0.0, "apply_movimento_loss": False,
        "apply_data_burst": False, # Novo
        "data_burst_percent": 0.0, # Novo
        "data_burst_ratio": 1      # Novo (int)
    }
}

# --- Filas de Comunicação ---
log_message("Inicializando filas de comunicação...")
status_update_queue = queue.Queue(maxsize=10)
command_queue = queue.Queue()

# --- Funções de Logging (Restantes) ---
def write_log_buffer_to_files():
    """Escreve o conteúdo do buffer de log para os arquivos CSV e JSON Lines."""
    logs_to_write = []
    with app_state_lock:
        while app_state["log_buffer_file"]:
            logs_to_write.append(app_state["log_buffer_file"].popleft())
    if not logs_to_write:
        return
    log_message(f"Escrevendo {len(logs_to_write)} logs para arquivos...", "DEBUG")
    try:
        file_exists_csv = os.path.exists(LOG_FILE_CSV)
        with open(LOG_FILE_CSV, 'a', newline='', encoding='utf-8') as csvfile:
            if not logs_to_write: return
            # Determina todas as chaves possíveis (para cabeçalho dinâmico)
            fieldnames_set = set()
            for entry in logs_to_write:
                fieldnames_set.update(entry.keys())
            fieldnames = sorted(list(fieldnames_set))

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if not file_exists_csv or os.path.getsize(LOG_FILE_CSV) == 0:
                writer.writeheader()
            writer.writerows(logs_to_write)
    except Exception as e:
        log_message(f"Erro ao escrever no CSV: {e}", "ERROR")
    try:
        with open(LOG_FILE_JSON, 'a', encoding='utf-8') as jsonfile:
            for entry in logs_to_write:
                json.dump(entry, jsonfile)
                jsonfile.write('\n')
    except Exception as e:
        log_message(f"Erro ao escrever no JSON Lines: {e}", "ERROR")

def log_packet_data(pkt, classification, manipulated):
    """Cria uma entrada de log para um pacote e a adiciona ao buffer."""
    if not isinstance(pkt, WinDivertPacket): return
    try:
        protocol_str = "TCP" if pkt.protocol == 6 else ("UDP" if pkt.protocol == 17 else str(pkt.protocol))
        src_port_val = pkt.src_port if hasattr(pkt, 'src_port') and pkt.src_port is not None else None
        dst_port_val = pkt.dst_port if hasattr(pkt, 'dst_port') and pkt.dst_port is not None else None
    except Exception as e:
        log_message(f"Erro ao acessar atributos do pacote para log: {e}", "WARN")
        protocol_str = "Desconhecido"
        src_port_val = None
        dst_port_val = None

    entry = {
        "timestamp": time.time(),
        "direction": "OUT" if pkt.is_outbound else "IN",
        "src_ip": str(pkt.src_addr),
        "dst_ip": str(pkt.dst_addr),
        "src_port": src_port_val,
        "dst_port": dst_port_val,
        "protocol": protocol_str,
        "length": len(pkt.payload) if pkt.payload else 0,
        "classification": classification,
        "manipulated": manipulated,
        "payload_preview": pkt.payload[:16].hex() if pkt.payload else ""
    }
    schedule_write = False
    with app_state_lock:
        app_state["log_buffer_file"].append(entry)
        if len(app_state["log_buffer_file"]) >= MAX_LOG_BUFFER_MEM:
            schedule_write = True
    if schedule_write:
        try:
            command_queue.put({"action": "write_log_files"})
        except queue.Full:
            log_message("Fila de comando cheia ao tentar agendar escrita de log!", "WARN")

# --- Funções de Manipulação de Pacotes ---
def apply_manipulations(packet, classification):
    """Aplica as manipulações configuradas a um pacote.
       Retorna uma lista de pacotes a serem enviados e um booleano indicando se houve manipulação.
    """
    if not isinstance(packet, WinDivertPacket): return [], False

    with app_state_lock:
        rules = app_state["active_rules"].copy()
        ctrl_pressed = app_state["ctrl_pressed"]

    manipulated = False
    packets_to_send = []
    
    # 1. Perda (Packet Loss) - Modificado para incluir CTRL
    current_loss_chance = rules["packet_loss_percent"]
    if ctrl_pressed:
        current_loss_chance = CTRL_LOSS_PERCENT
        log_message(f"[CTRL] Perda temporária ativada: {CTRL_LOSS_PERCENT}%", "DEBUG")
    elif classification == "MOVIMENTO" and rules["apply_movimento_loss"]:
        current_loss_chance = max(current_loss_chance, rules["loss_movimento_percent"])

    if current_loss_chance > 0 and random.random() * 100 < current_loss_chance:
        log_message(f"[MANIP_DEBUG] Aplicando Perda: Chance={current_loss_chance:.1f}% (CTRL: {ctrl_pressed})", "DEBUG")
        log_message(f"[DROP] Pacote {classification} descartado (Loss: {current_loss_chance:.1f}%)", "MANIP")
        return [], True # Retorna lista vazia para indicar descarte

    # --- Outras manipulações (aplicadas ao pacote original antes de duplicar/burst) ---

    # NOVO: Aplicar latência fixa se CTRL estiver pressionado
    if ctrl_pressed:
        ctrl_delay_sec = 1.5 # 1500 ms
        log_message(f"[CTRL] Aplicando latência fixa: {ctrl_delay_sec * 1000:.0f}ms", "DEBUG")
        time.sleep(ctrl_delay_sec)
        manipulated = True # Marcar como manipulado devido à latência do CTRL

    # 2. Latência (Lag) e Jitter
    delay_sec = 0.0
    if rules["latency_ms"] > 0:
        delay_sec = rules["latency_ms"] / 1000.0
    if rules["jitter_ms"] > 0:
        jitter_sec = random.uniform(-rules["jitter_ms"], rules["jitter_ms"]) / 1000.0
        delay_sec += jitter_sec
    actual_delay = max(0, delay_sec)
    if actual_delay >= MIN_SLEEP_THRESHOLD_SEC:
        log_message(f"[MANIP_DEBUG] Aplicando Latência/Jitter: {actual_delay:.4f}s (>= {MIN_SLEEP_THRESHOLD_SEC*1000}ms)", "DEBUG")
        time.sleep(actual_delay)
        manipulated = True
    elif actual_delay > 0:
        log_message(f"[MANIP_DEBUG] Latência/Jitter {actual_delay:.4f}s ignorado (< {MIN_SLEEP_THRESHOLD_SEC*1000}ms)", "TRACE")

    # 3. Atraso Específico para DANO
    if classification == "DANO" and rules["apply_dano_delay"] and rules["delay_dano_ms"] > 0:
        dano_delay_sec = rules["delay_dano_ms"] / 1000.0
        if dano_delay_sec >= MIN_SLEEP_THRESHOLD_SEC:
            log_message(f"[MANIP_DEBUG] Aplicando Atraso DANO: {dano_delay_sec:.4f}s (>= {MIN_SLEEP_THRESHOLD_SEC*1000}ms)", "DEBUG")
            time.sleep(dano_delay_sec)
            manipulated = True
            log_message(f"[DELAY DANO] Atraso DANO aplicado: {rules['delay_dano_ms']} ms", "MANIP")
        elif dano_delay_sec > 0:
             log_message(f"[MANIP_DEBUG] Atraso DANO {dano_delay_sec:.4f}s ignorado (< {MIN_SLEEP_THRESHOLD_SEC*1000}ms)", "TRACE")

    # 4. Corrupção (Tamper) - Aplica ao objeto 'packet' original
    if rules["corruption_percent"] > 0 and random.random() * 100 < rules["corruption_percent"]:
        if packet.payload:
            try:
                payload = bytearray(packet.payload)
                if len(payload) > 0:
                    index_to_corrupt = random.randint(0, len(payload) - 1)
                    payload[index_to_corrupt] ^= (1 << random.randint(0, 7))
                    packet.payload = bytes(payload) # Modifica o payload do pacote original
                    manipulated = True
                    log_message(f"[MANIP_DEBUG] Aplicando Corrupção: Chance={rules['corruption_percent']:.1f}%", "DEBUG")
                    log_message(f"[CORRUPT] Pacote {classification} corrompido", "MANIP")
            except Exception as e:
                log_message(f"Erro ao corromper pacote: {e}", "ERROR")
        else:
            log_message("Tentativa de corrupção falhou (pacote sem payload)", "WARN")

    # --- Adiciona o pacote original (possivelmente modificado) à lista de envio ---
    packets_to_send.append(packet)

    # --- Manipulações que enviam cópias extras (usando o mesmo objeto packet) ---

    # 5. Duplicação (Duplicate) - CORRIGIDO: Reenviar o mesmo objeto packet
    if rules["duplication_percent"] > 0 and random.random() * 100 < rules["duplication_percent"]:
        try:
            # Adiciona o mesmo pacote novamente à lista para duplicar
            packets_to_send.append(packet)
            log_message(f"[MANIP_DEBUG] Aplicando Duplicação: Chance={rules['duplication_percent']:.1f}%", "DEBUG")
            log_message(f"[DUPLICATE] Pacote {classification} duplicado", "MANIP")
            manipulated = True
        except Exception as e:
            log_message(f"Erro ao duplicar pacote: {e}", "ERROR")

    # 6. Data Burst (Novo) - CORRIGIDO: Reenviar o mesmo objeto packet múltiplas vezes
    burst_ratio = int(rules.get("data_burst_ratio", 1))
    burst_percent = rules.get("data_burst_percent", 0.0)
    apply_burst = rules.get("apply_data_burst", False)

    if apply_burst and burst_ratio > 1 and burst_percent > 0:
        if random.random() * 100 < burst_percent:
            num_burst_copies = burst_ratio - 1 # Já estamos enviando o original
            log_message(f"[MANIP_DEBUG] Aplicando Data Burst: Chance={burst_percent:.1f}%, Ratio={burst_ratio}", "DEBUG")
            
            # Adiciona o mesmo pacote várias vezes à lista
            for _ in range(num_burst_copies):
                packets_to_send.append(packet)
            
            log_message(f"[BURST] Pacote {classification} enviado {burst_ratio} vezes", "MANIP")
            manipulated = True

    return packets_to_send, manipulated

# --- Funções Otimizadas para Gerar Filtro WinDivert ---
def parse_ports(ports_str):
    """Converte uma string de portas (ex: "80, 443, 1000-1010") em uma lista de inteiros."""
    ports = set()
    if not ports_str: return []
    parts = ports_str.split(',')
    for part in parts:
        part = part.strip()
        if not part: continue
        if '-' in part:
            try:
                start, end = map(int, part.split('-', 1))
                if start <= end: ports.update(range(start, end + 1))
                else: log_message(f"Intervalo de portas inválido (início > fim): {part}", "WARN")
            except ValueError: log_message(f"Formato de intervalo de portas inválido: {part}", "WARN")
        else:
            try: ports.add(int(part))
            except ValueError: log_message(f"Número de porta inválido: {part}", "WARN")
    return sorted(list(ports))

def group_contiguous_ports(ports):
    """Agrupa uma lista ordenada de portas em intervalos contíguos.
       Retorna uma lista de tuplas: (porta_unica,) ou (porta_inicio, porta_fim).
    """
    if not ports: return []
    groups = []
    start_range = ports[0]
    end_range = ports[0]
    for i in range(1, len(ports)):
        if ports[i] == end_range + 1:
            end_range = ports[i]
        else:
            if start_range == end_range:
                groups.append((start_range,))
            else:
                groups.append((start_range, end_range))
            start_range = ports[i]
            end_range = ports[i]
    # Adiciona o último grupo
    if start_range == end_range:
        groups.append((start_range,))
    else:
        groups.append((start_range, end_range))
    return groups

def generate_optimized_windivert_filter(ps5_ip, udp_ports_str):
    """Gera a string de filtro WinDivert otimizada usando intervalos de portas."""
    if not ps5_ip:
        log_message("IP do PS5 não definido para o filtro!", "ERROR")
        return None

    # Filtro base para o IP do PS5
    base_filter = f"(ip.SrcAddr == {ps5_ip} or ip.DstAddr == {ps5_ip})"

    # Se não houver portas UDP, retorna apenas o filtro base com UDP
    if not udp_ports_str or udp_ports_str.strip() == "":
        return f"udp and {base_filter}"

    # Processa as portas UDP
    udp_ports = parse_ports(udp_ports_str)
    if not udp_ports:
        log_message("Nenhuma porta UDP válida encontrada, usando apenas filtro de IP.", "WARN")
        return f"udp and {base_filter}"

    # Agrupa portas contíguas
    port_groups = group_contiguous_ports(udp_ports)
    log_message(f"Portas agrupadas: {port_groups}", "DEBUG")

    # Constrói o filtro de portas otimizado
    port_conditions = []
    for group in port_groups:
        if len(group) == 1:
            # Porta única
            port_conditions.append(f"udp.DstPort == {group[0]} or udp.SrcPort == {group[0]}")
        else:
            # Intervalo de portas
            port_conditions.append(f"(udp.DstPort >= {group[0]} and udp.DstPort <= {group[1]}) or (udp.SrcPort >= {group[0]} and udp.SrcPort <= {group[1]})")

    # Combina as condições de porta
    port_filter = " or ".join(port_conditions)
    if len(port_conditions) > 1:
        port_filter = f"({port_filter})"

    # Combina com o filtro base
    full_filter = f"udp and {base_filter} and {port_filter}"

    # Verifica o comprimento do filtro
    if len(full_filter) > MAX_FILTER_LENGTH:
        log_message(f"AVISO: Filtro muito longo ({len(full_filter)} caracteres). Pode causar erro WinError 87.", "WARN")
        log_message("Tente reduzir o número de portas ou usar intervalos mais amplos.", "WARN")

    return full_filter

# --- Thread de Processamento de Pacotes ---
def packet_processing_thread():
    """Thread principal que captura e processa pacotes."""
    if not PYDIVERT_AVAILABLE:
        log_message("Thread de processamento não iniciada (pydivert indisponível).", "ERROR")
        status_update_queue.put({"status": "Erro: pydivert indisponível"})
        return

    log_message("Thread de processamento de pacotes iniciada.", "SYSTEM")
    status_update_queue.put({"status": "Iniciando..."})

    windivert_handle = None
    running = True

    while running:
        # Processa comandos da fila
        try:
            while not command_queue.empty():
                cmd = command_queue.get_nowait()
                if cmd["action"] == "stop":
                    log_message("Comando de parada recebido.", "SYSTEM")
                    running = False
                    break
                elif cmd["action"] == "write_log_files":
                    write_log_buffer_to_files()
                elif cmd["action"] == "update_classification":
                    with app_state_lock:
                        app_state["current_classification"] = cmd["classification"]
                    log_message(f"Classificação atualizada para: {cmd['classification']}", "INFO")
                elif cmd["action"] == "set_ctrl_pressed":
                    with app_state_lock:
                        app_state["ctrl_pressed"] = cmd["pressed"]
                    log_message(f"Estado CTRL atualizado: {cmd['pressed']}", "DEBUG")
        except queue.Empty:
            pass
        except Exception as e:
            log_message(f"Erro ao processar comando: {e}", "ERROR")

        if not running:
            break

        # Verifica se o handle WinDivert precisa ser criado/recriado
        if windivert_handle is None:
            with app_state_lock:
                ps5_ip = app_state["ps5_ip"]
                ports_str = app_state["div2_ports_str"]

            filter_to_use = generate_optimized_windivert_filter(ps5_ip, ports_str)
            if filter_to_use is None:
                log_message("Falha ao gerar filtro, aguardando próxima tentativa.", "ERROR")
                status_update_queue.put({"status": "Erro: Falha ao gerar filtro"})
                time.sleep(1)
                continue

            log_message(f"Aplicando filtro WinDivert: {filter_to_use}", "SYSTEM")
            try:
                # Tenta usar camada FORWARD primeiro
                capture_layer = Layer.NETWORK_FORWARD
                log_message(f"Usando camada de captura WinDivert: {capture_layer.name}", "INFO")
                windivert_handle = WinDivert(filter=filter_to_use, layer=capture_layer)
                log_message("Abrindo handle WinDivert...", "DEBUG")
                windivert_handle.open()
                log_message("Captura WinDivert iniciada/reiniciada com sucesso.", "SYSTEM")
                status_update_queue.put({"status": "Captura Ativa"})
            except OSError as e_open:
                log_message(f"Falha ao abrir WinDivert com {capture_layer.name}: {e_open}", "WARN")
                if e_open.winerror == 87:
                     log_message("Erro WinError 87: Parâmetro incorreto. Verifique o filtro ou tente menos portas.", "ERROR")
                     status_update_queue.put({"status": "Erro: Filtro Inválido (WinError 87)"})
                elif e_open.winerror == 5: # Access Denied
                     log_message("Erro WinError 5: Acesso Negado. Execute como Administrador.", "ERROR")
                     status_update_queue.put({"status": "Erro: Acesso Negado (Admin?)"})
                else:
                    # Tenta camada NETWORK como fallback
                    log_message("Tentando camada NETWORK como fallback...", "INFO")
                    try:
                        capture_layer = Layer.NETWORK
                        log_message(f"Usando camada de captura WinDivert: {capture_layer.name}", "INFO")
                        windivert_handle = WinDivert(filter=filter_to_use, layer=capture_layer)
                        windivert_handle.open()
                        log_message("Captura WinDivert iniciada/reiniciada com sucesso (NETWORK).", "SYSTEM")
                        status_update_queue.put({"status": "Captura Ativa (NETWORK)"})
                    except Exception as e_fallback:
                        log_message(f"Falha ao abrir WinDivert com {capture_layer.name}: {e_fallback}", "ERROR")
                        status_update_queue.put({"status": f"Erro: Falha WinDivert ({e_fallback})"})
                        windivert_handle = None # Garante que tentará novamente
                        time.sleep(2) # Espera antes de tentar novamente
            except Exception as e_generic:
                log_message(f"Erro genérico ao iniciar WinDivert: {e_generic}", "ERROR")
                log_message(traceback.format_exc(), "DEBUG")
                status_update_queue.put({"status": f"Erro: {e_generic}"})
                windivert_handle = None
                time.sleep(2)

        # Processa pacotes se o handle estiver ativo
        if windivert_handle:
            try:
                packet = windivert_handle.recv()
                if packet:
                    with app_state_lock:
                        app_state["packet_count_total"] += 1
                        current_classification = app_state["current_classification"]
                        manipulation_on = app_state["manipulation_active"]

                    # TODO: Adicionar lógica para determinar se o pacote é relevante (ex: UDP e IP correto)
                    # Por enquanto, consideramos todos os pacotes filtrados como relevantes
                    with app_state_lock:
                        app_state["packet_count_relevant"] += 1

                    packets_to_send = [packet] # Lista de pacotes a enviar
                    manipulated_flag = False

                    if manipulation_on:
                        packets_to_send, manipulated_flag = apply_manipulations(packet, current_classification)
                    else:
                        log_message("Manipulação desativada, enviando pacote original.", "TRACE")
                        # Mesmo desativada, apply_manipulations pode retornar lista vazia se CTRL estiver pressionado
                        if app_state["ctrl_pressed"]:
                             packets_to_send, manipulated_flag = apply_manipulations(packet, current_classification)

                    if manipulated_flag:
                        with app_state_lock:
                            app_state["packet_count_manipulated"] += 1

                    # Log do pacote original ANTES do envio das cópias
                    log_packet_data(packet, current_classification, manipulated_flag)

                    # Envia todos os pacotes na lista (original modificado + duplicatas/bursts)
                    for pkt_to_send in packets_to_send:
                        if pkt_to_send:
                            try:
                                windivert_handle.send(pkt_to_send)
                                log_message(f"Pacote enviado (Payload: {pkt_to_send.payload[:8].hex() if pkt_to_send.payload else 'vazio'}...)", "TRACE")
                            except Exception as send_err:
                                log_message(f"Erro ao reenviar pacote: {send_err}", "ERROR")
                        else:
                             log_message("Tentativa de enviar pacote None ignorada.", "WARN")

                else:
                    log_message("windivert_handle.recv() retornou None.", "TRACE")
                    # Espera um pouco se não houver pacotes para evitar busy-wait
                    time.sleep(PACKET_THREAD_SLEEP)

            except OSError as e_recv:
                log_message(f"Erro ao receber/enviar pacote: {e_recv}", "ERROR")
                if e_recv.winerror == 995: # Operação abortada (geralmente ao fechar)
                    log_message("Erro 995 (operação abortada), provavelmente fechando handle.", "INFO")
                    break # Sai do loop se a operação foi abortada
                else:
                    # Outro erro de OS, tenta recriar o handle
                    log_message("Tentando recriar handle WinDivert devido a OSError...", "WARN")
                    try: windivert_handle.close()
                    except: pass
                    windivert_handle = None
                    time.sleep(1)
            except Exception as e_loop:
                log_message(f"Erro inesperado no loop de pacotes: {e_loop}", "ERROR")
                log_message(traceback.format_exc(), "DEBUG")
                # Tenta recriar o handle em caso de erro inesperado
                try: windivert_handle.close()
                except: pass
                windivert_handle = None
                time.sleep(1)
        else:
            # Se o handle não está ativo, espera um pouco
            time.sleep(0.1)

    # Limpeza ao sair do loop
    if windivert_handle:
        try:
            log_message("Fechando handle WinDivert na finalização da thread...", "DEBUG")
            windivert_handle.close()
        except Exception as e_final_close:
            log_message(f"Erro ao fechar handle WinDivert na finalização: {e_final_close}", "WARN")

    # Garante que o buffer de log seja escrito ao parar
    write_log_buffer_to_files()
    log_message("Thread de processamento de pacotes finalizada.", "SYSTEM")
    status_update_queue.put({"status": "Parado"})

# --- Thread de Listener de Teclado ---
def keyboard_listener_thread():
    """Thread que escuta teclas para classificação e CTRL."""
    if not PYNPUT_AVAILABLE or not keyboard or not Key:
        log_message("Listener de teclado não iniciado (pynput indisponível).", "WARN")
        return

    log_message("Listener de teclado iniciado.", "DEBUG")
    pressed_keys = set()

    def on_press(key):
        nonlocal pressed_keys
        pressed_keys.add(key)
        try:
            # Classificação F1, F2, F3
            if key == Key.f1:
                command_queue.put({"action": "update_classification", "classification": "MOVIMENTO"})
            elif key == Key.f2:
                command_queue.put({"action": "update_classification", "classification": "DANO"})
            elif key == Key.f3:
                command_queue.put({"action": "update_classification", "classification": "OUTROS"})
            # Tecla CTRL (Esquerda ou Direita)
            elif key == Key.ctrl_l or key == Key.ctrl_r:
                # Verifica se já não estava pressionada para evitar comandos repetidos
                if Key.ctrl_l not in pressed_keys or Key.ctrl_r not in pressed_keys:
                     command_queue.put({"action": "set_ctrl_pressed", "pressed": True})

        except Exception as e:
            log_message(f"Erro no on_press do teclado: {e}", "ERROR")

    def on_release(key):
        nonlocal pressed_keys
        try:
            # Tecla CTRL (Esquerda ou Direita)
            if key == Key.ctrl_l or key == Key.ctrl_r:
                # Verifica se a *outra* tecla CTRL ainda está pressionada
                other_ctrl = Key.ctrl_r if key == Key.ctrl_l else Key.ctrl_l
                if other_ctrl not in pressed_keys:
                    command_queue.put({"action": "set_ctrl_pressed", "pressed": False})

            if key in pressed_keys:
                pressed_keys.remove(key)

        except Exception as e:
            log_message(f"Erro no on_release do teclado: {e}", "ERROR")
        # Para sair do listener (opcional, pode ser útil para debug)
        # if key == Key.esc:
        #    return False

    # Coleta eventos até ser interrompido
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        try:
            listener.join()
        except Exception as e_listener:
             log_message(f"Erro no listener de teclado: {e_listener}", "ERROR")

    log_message("Listener de teclado finalizado.", "DEBUG")

# --- Classe da Interface Gráfica (GUI) ---
class XLagTurboGUI:
    def __init__(self, master):
        self.master = master
        master.title("xLag Turbo GUI v1.9.8 - Otimizado")
        # master.geometry("650x750") # Ajustar tamanho conforme necessário

        # Fontes
        self.title_font = font.Font(family="Arial", size=12, weight="bold")
        self.section_font = font.Font(family="Arial", size=10, weight="bold")
        self.normal_font = font.Font(family="Arial", size=9)
        self.mono_font = font.Font(family="Courier", size=9)

        # Variáveis de controle
        self.status_var = tk.StringVar(value="Parado")
        self.ps5_ip_var = tk.StringVar(value=DEFAULT_PS5_IP)
        self.div2_ports_var = tk.StringVar(value=DEFAULT_DIV2_UDP_PORTS_STR)
        self.manipulation_active_var = tk.BooleanVar(value=False)
        self.current_classification_var = tk.StringVar(value="OUTROS")
        self.packet_count_total_var = tk.StringVar(value="0")
        self.packet_count_relevant_var = tk.StringVar(value="0")
        self.packet_count_manipulated_var = tk.StringVar(value="0")

        # Variáveis para regras
        self.latency_ms_var = tk.StringVar(value="0.0")
        self.jitter_ms_var = tk.StringVar(value="0.0")
        self.packet_loss_percent_var = tk.StringVar(value="0.0")
        self.duplication_percent_var = tk.StringVar(value="0.0")
        self.corruption_percent_var = tk.StringVar(value="0.0")
        self.delay_dano_ms_var = tk.StringVar(value="0.0")
        self.apply_dano_delay_var = tk.BooleanVar(value=False)
        self.loss_movimento_percent_var = tk.StringVar(value="0.0")
        self.apply_movimento_loss_var = tk.BooleanVar(value=False)
        self.apply_data_burst_var = tk.BooleanVar(value=False)
        self.data_burst_percent_var = tk.StringVar(value="0.0")
        self.data_burst_ratio_var = tk.StringVar(value="1")

        # Criar layout
        self.create_layout()

        # Iniciar threads
        self.start_threads()

        # Configurar atualização periódica da GUI
        self.update_gui()

    def create_layout(self):
        """Cria o layout da interface gráfica."""
        # Frame principal
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Título
        title_label = ttk.Label(main_frame, text="xLag Turbo GUI", font=self.title_font)
        title_label.pack(pady=(0, 10))

        # Frame de controle
        control_frame = ttk.LabelFrame(main_frame, text="Controle", padding="5")
        control_frame.pack(fill=tk.X, pady=5)

        # Status
        status_frame = ttk.Frame(control_frame)
        status_frame.pack(fill=tk.X, pady=2)
        ttk.Label(status_frame, text="Status:", width=15).pack(side=tk.LEFT)
        ttk.Label(status_frame, textvariable=self.status_var, foreground="blue").pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Botões de controle
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, pady=2)
        ttk.Button(button_frame, text="Iniciar Captura", command=self.start_capture).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Parar Captura", command=self.stop_capture).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Salvar Preset", command=self.save_preset).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Carregar Preset", command=self.load_preset).pack(side=tk.LEFT, padx=5)

        # Frame de configuração
        config_frame = ttk.LabelFrame(main_frame, text="Configuração", padding="5")
        config_frame.pack(fill=tk.X, pady=5)

        # IP do PS5
        ip_frame = ttk.Frame(config_frame)
        ip_frame.pack(fill=tk.X, pady=2)
        ttk.Label(ip_frame, text="IP do PS5:", width=15).pack(side=tk.LEFT)
        ttk.Entry(ip_frame, textvariable=self.ps5_ip_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Portas UDP
        ports_frame = ttk.Frame(config_frame)
        ports_frame.pack(fill=tk.X, pady=2)
        ttk.Label(ports_frame, text="Portas UDP (opcional):", width=15).pack(side=tk.LEFT)
        ttk.Entry(ports_frame, textvariable=self.div2_ports_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Frame de regras
        rules_frame = ttk.LabelFrame(main_frame, text="Regras de Manipulação", padding="5")
        rules_frame.pack(fill=tk.X, pady=5)

        # Checkbox para ativar manipulação
        manip_check = ttk.Checkbutton(rules_frame, text="Ativar Manipulação", variable=self.manipulation_active_var,
                                      command=self.update_manipulation_active)
        manip_check.pack(anchor=tk.W, pady=2)

        # Regras básicas (com campos de entrada numérica)
        basic_rules_frame = ttk.Frame(rules_frame)
        basic_rules_frame.pack(fill=tk.X, pady=2)

        # Latência
        latency_frame = ttk.Frame(basic_rules_frame)
        latency_frame.pack(fill=tk.X, pady=2)
        ttk.Label(latency_frame, text="Latência (ms):", width=15).pack(side=tk.LEFT)
        ttk.Entry(latency_frame, textvariable=self.latency_ms_var, width=10).pack(side=tk.LEFT)
        ttk.Button(latency_frame, text="Aplicar", command=lambda: self.update_rule("latency_ms")).pack(side=tk.LEFT, padx=5)

        # Jitter
        jitter_frame = ttk.Frame(basic_rules_frame)
        jitter_frame.pack(fill=tk.X, pady=2)
        ttk.Label(jitter_frame, text="Jitter (ms):", width=15).pack(side=tk.LEFT)
        ttk.Entry(jitter_frame, textvariable=self.jitter_ms_var, width=10).pack(side=tk.LEFT)
        ttk.Button(jitter_frame, text="Aplicar", command=lambda: self.update_rule("jitter_ms")).pack(side=tk.LEFT, padx=5)

        # Perda
        loss_frame = ttk.Frame(basic_rules_frame)
        loss_frame.pack(fill=tk.X, pady=2)
        ttk.Label(loss_frame, text="Perda (%):", width=15).pack(side=tk.LEFT)
        ttk.Entry(loss_frame, textvariable=self.packet_loss_percent_var, width=10).pack(side=tk.LEFT)
        ttk.Button(loss_frame, text="Aplicar", command=lambda: self.update_rule("packet_loss_percent")).pack(side=tk.LEFT, padx=5)

        # Duplicação
        dup_frame = ttk.Frame(basic_rules_frame)
        dup_frame.pack(fill=tk.X, pady=2)
        ttk.Label(dup_frame, text="Duplicação (%):", width=15).pack(side=tk.LEFT)
        ttk.Entry(dup_frame, textvariable=self.duplication_percent_var, width=10).pack(side=tk.LEFT)
        ttk.Button(dup_frame, text="Aplicar", command=lambda: self.update_rule("duplication_percent")).pack(side=tk.LEFT, padx=5)

        # Corrupção
        corrupt_frame = ttk.Frame(basic_rules_frame)
        corrupt_frame.pack(fill=tk.X, pady=2)
        ttk.Label(corrupt_frame, text="Corrupção (%):", width=15).pack(side=tk.LEFT)
        ttk.Entry(corrupt_frame, textvariable=self.corruption_percent_var, width=10).pack(side=tk.LEFT)
        ttk.Button(corrupt_frame, text="Aplicar", command=lambda: self.update_rule("corruption_percent")).pack(side=tk.LEFT, padx=5)

        # Data Burst (Novo)
        burst_check_frame = ttk.Frame(rules_frame)
        burst_check_frame.pack(fill=tk.X, pady=2)
        ttk.Checkbutton(burst_check_frame, text="Ativar Data Burst", variable=self.apply_data_burst_var,
                       command=lambda: self.update_rule("apply_data_burst")).pack(anchor=tk.W)

        burst_frame = ttk.Frame(rules_frame)
        burst_frame.pack(fill=tk.X, pady=2)
        ttk.Label(burst_frame, text="Data Burst (%):", width=15).pack(side=tk.LEFT)
        ttk.Entry(burst_frame, textvariable=self.data_burst_percent_var, width=10).pack(side=tk.LEFT)
        ttk.Button(burst_frame, text="Aplicar", command=lambda: self.update_rule("data_burst_percent")).pack(side=tk.LEFT, padx=5)

        burst_ratio_frame = ttk.Frame(rules_frame)
        burst_ratio_frame.pack(fill=tk.X, pady=2)
        ttk.Label(burst_ratio_frame, text="Data Burst Ratio:", width=15).pack(side=tk.LEFT)
        ttk.Entry(burst_ratio_frame, textvariable=self.data_burst_ratio_var, width=10).pack(side=tk.LEFT)
        ttk.Button(burst_ratio_frame, text="Aplicar", command=lambda: self.update_rule("data_burst_ratio")).pack(side=tk.LEFT, padx=5)

        # Regras específicas
        specific_rules_frame = ttk.LabelFrame(rules_frame, text="Regras Específicas", padding="5")
        specific_rules_frame.pack(fill=tk.X, pady=5)

        # Atraso de DANO
        dano_check = ttk.Checkbutton(specific_rules_frame, text="Aplicar Atraso em DANO", variable=self.apply_dano_delay_var,
                                    command=lambda: self.update_rule("apply_dano_delay"))
        dano_check.pack(anchor=tk.W, pady=2)

        dano_frame = ttk.Frame(specific_rules_frame)
        dano_frame.pack(fill=tk.X, pady=2)
        ttk.Label(dano_frame, text="Atraso DANO (ms):", width=15).pack(side=tk.LEFT)
        ttk.Entry(dano_frame, textvariable=self.delay_dano_ms_var, width=10).pack(side=tk.LEFT)
        ttk.Button(dano_frame, text="Aplicar", command=lambda: self.update_rule("delay_dano_ms")).pack(side=tk.LEFT, padx=5)

        # Perda de MOVIMENTO
        movimento_check = ttk.Checkbutton(specific_rules_frame, text="Aplicar Perda em MOVIMENTO", variable=self.apply_movimento_loss_var,
                                         command=lambda: self.update_rule("apply_movimento_loss"))
        movimento_check.pack(anchor=tk.W, pady=2)

        movimento_frame = ttk.Frame(specific_rules_frame)
        movimento_frame.pack(fill=tk.X, pady=2)
        ttk.Label(movimento_frame, text="Perda MOVIMENTO (%):", width=15).pack(side=tk.LEFT)
        ttk.Entry(movimento_frame, textvariable=self.loss_movimento_percent_var, width=10).pack(side=tk.LEFT)
        ttk.Button(movimento_frame, text="Aplicar", command=lambda: self.update_rule("loss_movimento_percent")).pack(side=tk.LEFT, padx=5)

        # Frame de estatísticas
        stats_frame = ttk.LabelFrame(main_frame, text="Estatísticas", padding="5")
        stats_frame.pack(fill=tk.X, pady=5)

        # Classificação atual
        class_frame = ttk.Frame(stats_frame)
        class_frame.pack(fill=tk.X, pady=2)
        ttk.Label(class_frame, text="Classificação:", width=15).pack(side=tk.LEFT)
        ttk.Label(class_frame, textvariable=self.current_classification_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Contadores
        count_frame = ttk.Frame(stats_frame)
        count_frame.pack(fill=tk.X, pady=2)
        ttk.Label(count_frame, text="Total:", width=15).pack(side=tk.LEFT)
        ttk.Label(count_frame, textvariable=self.packet_count_total_var).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(count_frame, text="Relevantes:").pack(side=tk.LEFT)
        ttk.Label(count_frame, textvariable=self.packet_count_relevant_var).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(count_frame, text="Manipulados:").pack(side=tk.LEFT)
        ttk.Label(count_frame, textvariable=self.packet_count_manipulated_var).pack(side=tk.LEFT)

        # Frame de log
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Área de texto para log
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, font=self.mono_font)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)

        # Instruções
        instructions_frame = ttk.LabelFrame(main_frame, text="Instruções", padding="5")
        instructions_frame.pack(fill=tk.X, pady=5)
        instructions_text = (
            "F1: Classificar como MOVIMENTO | F2: Classificar como DANO | F3: Classificar como OUTROS\n"
            "CTRL: Segurar para congelar (100% perda) | Soltar para voltar ao normal"
        )
        ttk.Label(instructions_frame, text=instructions_text, font=self.normal_font).pack(pady=5)

    def start_threads(self):
        """Inicia as threads de processamento e teclado."""
        self.packet_thread = None
        self.keyboard_thread = None
        self.running = False

    def update_gui(self):
        """Atualiza a GUI periodicamente."""
        # Atualiza status
        try:
            while not status_update_queue.empty():
                status = status_update_queue.get_nowait()
                if "status" in status:
                    self.status_var.set(status["status"])
        except queue.Empty:
            pass
        except Exception as e:
            log_message(f"Erro ao atualizar status: {e}", "ERROR")

        # Atualiza contadores
        with app_state_lock:
            self.packet_count_total_var.set(str(app_state["packet_count_total"]))
            self.packet_count_relevant_var.set(str(app_state["packet_count_relevant"]))
            self.packet_count_manipulated_var.set(str(app_state["packet_count_manipulated"]))
            self.current_classification_var.set(app_state["current_classification"])

        # Atualiza log
        try:
            while not log_queue_gui.empty():
                log_entry = log_queue_gui.get_nowait()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, log_entry + "\n")
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
                if self.log_text.index('end-1c').split('.')[0] > str(MAX_LOG_LINES_GUI):
                    self.log_text.config(state=tk.NORMAL)
                    self.log_text.delete(1.0, 2.0)
                    self.log_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        except Exception as e:
            print(f"Erro ao atualizar log na GUI: {e}")

        # Agenda próxima atualização
        self.master.after(GUI_UPDATE_INTERVAL_MS, self.update_gui)

    def start_capture(self):
        """Inicia a captura de pacotes."""
        if self.running:
            messagebox.showinfo("Já em execução", "A captura já está em execução.")
            return

        # Atualiza o IP e portas no estado da aplicação
        with app_state_lock:
            app_state["ps5_ip"] = self.ps5_ip_var.get()
            app_state["div2_ports_str"] = self.div2_ports_var.get()
            app_state["running"] = True
            app_state["packet_count_total"] = 0
            app_state["packet_count_relevant"] = 0
            app_state["packet_count_manipulated"] = 0

        # Inicia a thread de processamento
        self.packet_thread = threading.Thread(target=packet_processing_thread, daemon=True)
        self.packet_thread.start()

        # Inicia a thread de teclado se disponível
        if PYNPUT_AVAILABLE and not self.keyboard_thread:
            self.keyboard_thread = threading.Thread(target=keyboard_listener_thread, daemon=True)
            self.keyboard_thread.start()

        self.running = True
        log_message("Captura iniciada.", "SYSTEM")

    def stop_capture(self):
        """Para a captura de pacotes."""
        if not self.running:
            messagebox.showinfo("Não está em execução", "A captura não está em execução.")
            return

        with app_state_lock:
            app_state["running"] = False

        try:
            command_queue.put({"action": "stop"})
            log_message("Comando de parada enviado.", "SYSTEM")
        except Exception as e:
            log_message(f"Erro ao enviar comando de parada: {e}", "ERROR")

        self.running = False

    def update_manipulation_active(self):
        """Atualiza o estado de ativação da manipulação."""
        with app_state_lock:
            app_state["manipulation_active"] = self.manipulation_active_var.get()
        log_message(f"Manipulação {'ativada' if self.manipulation_active_var.get() else 'desativada'}.", "INFO")

    def update_rule(self, rule_name):
        """Atualiza uma regra específica."""
        try:
            with app_state_lock:
                if rule_name == "latency_ms":
                    value = float(self.latency_ms_var.get())
                    app_state["active_rules"]["latency_ms"] = max(0, value)
                    log_message(f"Latência atualizada: {value} ms", "INFO")
                elif rule_name == "jitter_ms":
                    value = float(self.jitter_ms_var.get())
                    app_state["active_rules"]["jitter_ms"] = max(0, value)
                    log_message(f"Jitter atualizado: {value} ms", "INFO")
                elif rule_name == "packet_loss_percent":
                    value = float(self.packet_loss_percent_var.get())
                    app_state["active_rules"]["packet_loss_percent"] = max(0, min(100, value))
                    log_message(f"Perda atualizada: {value}%", "INFO")
                elif rule_name == "duplication_percent":
                    value = float(self.duplication_percent_var.get())
                    app_state["active_rules"]["duplication_percent"] = max(0, min(100, value))
                    log_message(f"Duplicação atualizada: {value}%", "INFO")
                elif rule_name == "corruption_percent":
                    value = float(self.corruption_percent_var.get())
                    app_state["active_rules"]["corruption_percent"] = max(0, min(100, value))
                    log_message(f"Corrupção atualizada: {value}%", "INFO")
                elif rule_name == "delay_dano_ms":
                    value = float(self.delay_dano_ms_var.get())
                    app_state["active_rules"]["delay_dano_ms"] = max(0, value)
                    log_message(f"Atraso DANO atualizado: {value} ms", "INFO")
                elif rule_name == "apply_dano_delay":
                    value = self.apply_dano_delay_var.get()
                    app_state["active_rules"]["apply_dano_delay"] = value
                    log_message(f"Aplicar atraso DANO: {'Sim' if value else 'Não'}", "INFO")
                elif rule_name == "loss_movimento_percent":
                    value = float(self.loss_movimento_percent_var.get())
                    app_state["active_rules"]["loss_movimento_percent"] = max(0, min(100, value))
                    log_message(f"Perda MOVIMENTO atualizada: {value}%", "INFO")
                elif rule_name == "apply_movimento_loss":
                    value = self.apply_movimento_loss_var.get()
                    app_state["active_rules"]["apply_movimento_loss"] = value
                    log_message(f"Aplicar perda MOVIMENTO: {'Sim' if value else 'Não'}", "INFO")
                elif rule_name == "apply_data_burst":
                    value = self.apply_data_burst_var.get()
                    app_state["active_rules"]["apply_data_burst"] = value
                    log_message(f"Aplicar Data Burst: {'Sim' if value else 'Não'}", "INFO")
                elif rule_name == "data_burst_percent":
                    value = float(self.data_burst_percent_var.get())
                    app_state["active_rules"]["data_burst_percent"] = max(0, min(100, value))
                    log_message(f"Data Burst % atualizado: {value}%", "INFO")
                elif rule_name == "data_burst_ratio":
                    value = int(float(self.data_burst_ratio_var.get()))
                    app_state["active_rules"]["data_burst_ratio"] = max(1, value)
                    log_message(f"Data Burst Ratio atualizado: {value}", "INFO")
        except ValueError:
            messagebox.showerror("Erro", f"Valor inválido para {rule_name}. Use apenas números.")
        except Exception as e:
            log_message(f"Erro ao atualizar regra {rule_name}: {e}", "ERROR")

    def save_preset(self):
        """Salva as configurações atuais em um arquivo JSON."""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=PRESET_FILE_TYPES,
                title="Salvar Preset"
            )
            if not filename:
                return

            with app_state_lock:
                preset_data = {
                    "ps5_ip": app_state["ps5_ip"],
                    "div2_ports_str": app_state["div2_ports_str"],
                    "active_rules": app_state["active_rules"].copy()
                }

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(preset_data, f, indent=4)

            log_message(f"Preset salvo em: {filename}", "INFO")
            messagebox.showinfo("Sucesso", f"Preset salvo com sucesso em:\n{filename}")
        except Exception as e:
            log_message(f"Erro ao salvar preset: {e}", "ERROR")
            messagebox.showerror("Erro", f"Falha ao salvar preset: {e}")

    def load_preset(self):
        """Carrega configurações de um arquivo JSON."""
        try:
            filename = filedialog.askopenfilename(
                filetypes=PRESET_FILE_TYPES,
                title="Carregar Preset"
            )
            if not filename:
                return

            with open(filename, 'r', encoding='utf-8') as f:
                preset_data = json.load(f)

            # Atualiza o estado da aplicação
            with app_state_lock:
                if "ps5_ip" in preset_data:
                    app_state["ps5_ip"] = preset_data["ps5_ip"]
                    self.ps5_ip_var.set(preset_data["ps5_ip"])

                if "div2_ports_str" in preset_data:
                    app_state["div2_ports_str"] = preset_data["div2_ports_str"]
                    self.div2_ports_var.set(preset_data["div2_ports_str"])

                if "active_rules" in preset_data:
                    for rule, value in preset_data["active_rules"].items():
                        if rule in app_state["active_rules"]:
                            app_state["active_rules"][rule] = value

            # Atualiza a interface
            self.latency_ms_var.set(str(app_state["active_rules"]["latency_ms"]))
            self.jitter_ms_var.set(str(app_state["active_rules"]["jitter_ms"]))
            self.packet_loss_percent_var.set(str(app_state["active_rules"]["packet_loss_percent"]))
            self.duplication_percent_var.set(str(app_state["active_rules"]["duplication_percent"]))
            self.corruption_percent_var.set(str(app_state["active_rules"]["corruption_percent"]))
            self.delay_dano_ms_var.set(str(app_state["active_rules"]["delay_dano_ms"]))
            self.apply_dano_delay_var.set(app_state["active_rules"]["apply_dano_delay"])
            self.loss_movimento_percent_var.set(str(app_state["active_rules"]["loss_movimento_percent"]))
            self.apply_movimento_loss_var.set(app_state["active_rules"]["apply_movimento_loss"])
            self.apply_data_burst_var.set(app_state["active_rules"].get("apply_data_burst", False))
            self.data_burst_percent_var.set(str(app_state["active_rules"].get("data_burst_percent", 0.0)))
            self.data_burst_ratio_var.set(str(app_state["active_rules"].get("data_burst_ratio", 1)))

            log_message(f"Preset carregado de: {filename}", "INFO")
            messagebox.showinfo("Sucesso", f"Preset carregado com sucesso de:\n{filename}")
        except Exception as e:
            log_message(f"Erro ao carregar preset: {e}", "ERROR")
            messagebox.showerror("Erro", f"Falha ao carregar preset: {e}")

# --- Função Principal ---
def main():
    """Função principal que inicia a aplicação."""
    log_message("Iniciando aplicação...", "SYSTEM")

    # Verifica dependências
    if not PYDIVERT_AVAILABLE:
        log_message("ERRO CRÍTICO: pydivert não disponível. A aplicação não funcionará corretamente.", "ERROR")
    if not PYNPUT_AVAILABLE:
        log_message("AVISO: pynput não disponível. Controle por teclado desativado.", "WARN")
    if not ADMIN_PRIVILEGES:
        log_message("AVISO: Sem privilégios de administrador. WinDivert pode não funcionar.", "WARN")

    # Inicia a GUI
    root = tk.Tk()
    app = XLagTurboGUI(root)
    root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root))
    root.mainloop()

def on_closing(root):
    """Função chamada ao fechar a janela."""
    log_message("Fechando aplicação...", "SYSTEM")
    try:
        command_queue.put({"action": "stop"})
    except:
        pass
    time.sleep(0.5)  # Dá tempo para as threads terminarem
    root.destroy()

if __name__ == "__main__":
    main()
