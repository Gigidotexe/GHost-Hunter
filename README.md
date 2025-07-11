# GHost Hunter 
<img src="https://github.com/Gigidotexe/Gigidotexe/blob/main/Img/PCPixel.png" height="90"/> <img src="https://github.com/Gigidotexe/Gigidotexe/blob/main/Img/haunter.png" height="100" /><br>
**GHost Hunter** è uno script Python avanzato per il network discovery, progettato per identificare host attivi in una rete locale utilizzando metodi multipli (ARP, ICMP, TCP) e fornire una mappatura dettagliata dei dispositivi. Include spiegazioni dettagliate del funzionamento di ogni fase.

---

## Funzionalità principali

### ARP Discovery (Layer 2)

Questa scansione usa ARP per interrogare tutti gli IP della subnet, mandando pacchetti Ethernet broadcast. Così si scoprono dispositivi nella LAN che non rispondono a ICMP o non hanno porte TCP aperte.

```python
pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_list)  # prepara pacchetti ARP
ans, _ = srp(pkt, timeout=2, retry=1, verbose=0)        # invia e riceve risposte
for _, r in ans:
    ip, mac = r.psrc, r.hwsrc
    hostname = resolve_hostname(ip)                     # tenta DNS reverse
    results[ip] = {"method": "ARP", "hostname": hostname, "mac": mac}
```

### ICMP Discovery (Ping personalizzato)

Invia pacchetti ICMP Echo Request (ping) per verificare se un host è online. <br>
Può ricevere un Echo Reply (host attivo) o messaggi ICMP Destination Unreachable che indicano comunque che l’IP è raggiungibile, ma potrebbe rifiutare connessioni su determinate porte.
```python
# Costruisce pacchetti ICMP Echo Request per ogni IP
pkt = [IP(dst=ip)/ICMP() for ip in ip_list]
# Invia i pacchetti e riceve le risposte ICMP
ans, _ = sr(pkt, timeout=1.5, retry=1, verbose=0)

for _, r in ans:
    ip = r.src
    icmp_type = r.getlayer(ICMP).type
    icmp_code = r.getlayer(ICMP).code

    if icmp_type == 0:
        # Echo Reply: host online
        results[ip] = {"method": "ICMP", "hostname": resolve_hostname(ip), "mac": "N/A"}
    elif icmp_type == 3 and icmp_code == 3:
        # Destination Unreachable - Port Unreachable: host raggiungibile ma porta chiusa
        results[ip] = {"method": "ICMP Port Unreachable", "hostname": resolve_hostname(ip), "mac": "N/A"}

```

### TCP Connect Scan

Tenta connessioni reali sulle porte più comuni, completando handshake TCP. Utile per trovare servizi attivi anche se ICMP e ARP non danno esito.

```python
for port in COMMON_PORTS:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        s.close()
        return ip, port  # porta aperta
    except:
        continue
```

### Risoluzione automatica di Hostname e MAC

Per ogni IP trovato, tenta DNS reverse. Questo aiuta a identificare dispositivi da nome, non solo IP.

```python
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "N/A"
```

### Output dettagliato e formattato

Salva in un file `.txt` con colonne adattate alla lunghezza dei valori più lunghi per leggere facilmente i dati.

```python
with open(path, "w") as f:
    f.write(f"{'IP'.ljust(max_ip_len)}{'Method'.ljust(max_method_len)}"
            f"{'Hostname'.ljust(max_host_len)}{'MAC'.ljust(max_mac_len)}\n")
    for ip, meth, hostname, mac in hosts:
        f.write(f"{ip.ljust(max_ip_len)}{meth.ljust(max_method_len)}"
                f"{hostname.ljust(max_host_len)}{mac.ljust(max_mac_len)}\n")
```

### Multi-threading

Usa `ThreadPoolExecutor` per velocizzare la scansione parallelizzando i chunk di IP.

```python
with ThreadPoolExecutor(max_workers=THREADS_ARP) as executor:
    futures = [executor.submit(arp_worker, chunk, results) for chunk in chunks]
```

---

## Setup automatico

Incluso `setup.sh` che:

* aggiorna pacchetti,
* installa Python e venv,
* crea un ambiente virtuale,
* installa le dipendenze.

```bash
#!/usr/bin/env bash
sudo apt update
sudo apt install -y python3 python3-venv
python3 -m venv ghostenv
ghostenv/bin/pip install --upgrade pip
ghostenv/bin/pip install colorama pyfiglet scapy
source ghostenv/bin/activate
sudo python3 main.py
```

---
