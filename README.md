# GHost Hunter 
<img src="https://github.com/Gigidotexe/Gigidotexe/blob/main/Img/PCPixel.png" height="100"/> <img src="https://github.com/Gigidotexe/Gigidotexe/blob/main/Img/haunter.png" height="100" /><br>
GHost Hunter è uno script Python progettato per eseguire scansioni di rete alla ricerca di dispositivi attivi all’interno di una subnet specificata, confrontare i risultati con scansioni precedenti e segnalare eventuali nuovi dispositivi rilevati. È particolarmente utile per monitorare cambiamenti in una LAN, utile in ambito di sicurezza informatica e network administration.

---

## Caratteristiche principali

- Scansione della rete tramite Nmap con rilevamento di host attivi.
- Salvataggio dei risultati in file di testo ordinati per IP, hostname, router e MAC address.
-  Identificazione e visualizzazione di nuovi dispositivi rispetto alle scansioni precedenti.
- Directory dedicata `scans` per memorizzare i file di scansione.
- Supporto per subnet personalizzate (default: `192.168.1.0/24`).

---

## Struttura del progetto

```text
ghost-hunter/
├── ascii/
│   └── haunter.txt          # ASCII art mostrata all'avvio
├── scans/
│   └── ...                  # File di output delle scansioni
├── setup/
│   ├── setup.sh             # Script per configurare l’ambiente
│   └── requirements.txt     # Librerie Python necessarie
├── ghost_hunter.py          # Script principale
└── README.md                # Questo file
```

---

## Requisiti

- Python 3.7 o superiore
- Nmap installato sulla macchina
- Librerie Python:
  - `python-nmap`
  - `colorama`
  - `pyfiglet`

---

## Installazione

È disponibile uno script `setup.sh` per installare automaticamente tutte le dipendenze necessarie.

Esempio di utilizzo:

```bash
chmod +x setup.sh
./setup.sh
```
se dovessi avere un errore `zsh: ./setup.sh: bad interpreter: /bin/bash^M: no such file or directory` dopo aver eseguito `setup.sh` converti il file in formato Unix(LF) usando `dos2unix setup.sh`
