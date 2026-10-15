#!/usr/bin/python3
import sys
import json
import re
from datetime import datetime
from netmiko import ConnectHandler

LOG_FILE = "/var/ossec/logs/active-responses.log"

def log_message(message):
    timestamp = datetime.now().strftime('%Y/%m/%d %H:%M:%S')
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} active-response/bin/cisco_ips.py: {message}\n")

def main():
    # Ler a primeira linha do STDIN (log)
    try:
        input_str = sys.stdin.readline().strip()
        if not input_str:
            return
        alert_data = json.loads(input_str)
    except Exception as e:
        log_message(f"Erro: Nao foi possivel processar o JSON inicial: {str(e)}")
        return

    # Extrair acao do Wazuh (add/delete)
    wazuh_command = alert_data.get("command", "")
    
    # Extrair a informacao necessaria do log
    parameters = alert_data.get("parameters", {})
    alert = parameters.get("alert", {})
    rule_id = str(alert.get("rule", {}).get("id", ""))
    full_log = alert.get("full_log", "")
    
    if not wazuh_command or not rule_id:
        log_message("Erro: Comando ou ID da regra nao encontrados no log.")
        return

    # HANDSHAKE STATEFUL (Documentacao Wazuh)
    if wazuh_command == "add":
        action_key = "tcp_intercept"
        if rule_id == "100301":
            match = re.search(r'denied \w+ ([0-9\.]+)', full_log)
            if match:
                action_key = match.group(1) # Usa o IP do atacante como chave
                
        # Enviar check_keys para o STDOUT
        keys_msg = json.dumps({
            "version": 1,
            "origin": {"name": sys.argv[0], "module": "active-response"},
            "command": "check_keys",
            "parameters": {"keys": [action_key]}
        })
        print(keys_msg)
        sys.stdout.flush()
        
        # Ler imediatamente a resposta do Wazuh Manager (continue = ok)
        try:
            response_str = sys.stdin.readline().strip()
            response_data = json.loads(response_str)
            if response_data.get("command") != "continue":
                log_message("Info: Acao repetida ignorada. A ameaca ja se encontra bloqueada pelo Wazuh.")
                return
        except Exception as e:
            log_message(f"Erro ao ler confirmacao do Wazuh: {str(e)}")
            return

    log_message(f"Custom IPS iniciado -> Comando: {wazuh_command.upper()} | Regra: {rule_id}")

    # Ligacao telnet (ssh nao e compativel entre wazuh server e imagem ios antiga)
    cisco_router = {
        'device_type': 'cisco_ios_telnet',
        'host': '192.168.1.254',
        'username': 'cisco',
        'password': 'cisco',
        'secret': 'cisco'
    }
    
    commands_to_send = []
    
    # LOGICA DO NMAP SCAN (NULL ROUTE)
    if rule_id == "100301":
        match = re.search(r'denied \w+ ([0-9\.]+)', full_log)
        if not match:
            log_message("Erro: logica do nmap falhou (IP do atacante nao encontrado).")
            return
            
        malicious_ip = match.group(1)
        
        if wazuh_command == "add":
            commands_to_send = [f"ip route {malicious_ip} 255.255.255.255 Null0"]
            log_message(f"A injetar null route no router. IP alvo: {malicious_ip}")
        elif wazuh_command == "delete":
            commands_to_send = [f"no ip route {malicious_ip} 255.255.255.255 Null0"]
            log_message(f"Timeout (Stateful). A remover null route para: {malicious_ip}")

    # LOGICA DO SYN FLOOD (TCP INTERCEPT)
    elif rule_id == "100302":
        if wazuh_command == "add":
            commands_to_send = [
                "ip access-list extended SYN_PROTECT",
                "permit tcp any any eq 80",
                "exit",
                "ip tcp intercept list SYN_PROTECT",
                "ip tcp intercept mode intercept",
                "ip tcp intercept max-incomplete low 50 high 100",
                "ip tcp intercept connection-timeout 30",
                "ip tcp intercept drop-mode random"
            ]
            log_message("A injetar protecao TCP Intercept no router (anti SYN Flood).")
        elif wazuh_command == "delete":
            commands_to_send = [
                "no ip tcp intercept list SYN_PROTECT",
                "no ip access-list extended SYN_PROTECT"
            ]
            log_message("Timeout (Stateful). A remover protecao TCP Intercept.")
    else:
        log_message(f"Erro: Regra {rule_id} nao mapeada no script.")
        return

    # APLICAR COMANDOS NO ROUTER
    try:
        net_connect = ConnectHandler(**cisco_router)
        net_connect.enable()
        net_connect.send_config_set(commands_to_send)
        net_connect.disconnect()
        log_message(f"SUCESSO: Comandos aplicados no router ({wazuh_command.upper()})!")
    except Exception as e:
        log_message(f"Erro de ligacao ao router: {str(e)}")

if __name__ == "__main__":
    main()