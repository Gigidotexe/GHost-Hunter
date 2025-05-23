# GHost Hunter 
<img src="https://github.com/Gigidotexe/Gigidotexe/blob/main/Img/PCPixel.png" height="100"/> <img src="https://github.com/Gigidotexe/Gigidotexe/blob/main/Img/haunter.png" height="100" />
<br>GHost Hunter è uno scanner di rete Python che rileva dispositivi attivi all’interno di una rete locale, confronta i risultati con scansioni precedenti per identificare nuovi dispositivi, e salva i risultati in file di testo organizzati.

---

## Caratteristiche principali

- Scansione della rete tramite Nmap con rilevamento di host attivi.
- Identificazione e visualizzazione di nuovi dispositivi rispetto alle scansioni precedenti.
- Salvataggio dei risultati in file di testo ordinati per IP, hostname, router e MAC address.
- Interfaccia a linea di comando con animazioni di caricamento e output colorato.
- Directory dedicata `scans` per memorizzare i file di scansione.
- Supporto per subnet personalizzate (default: `192.168.1.0/24`).

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
