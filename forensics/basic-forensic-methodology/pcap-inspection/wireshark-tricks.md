# Trucchi di Wireshark

## Trucchi di Wireshark

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di github.

</details>

## Migliora le tue competenze di Wireshark

### Tutorial

I seguenti tutorial sono fantastici per imparare alcuni trucchi di base interessanti:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informazioni analizzate

**Informazioni esperte**

Cliccando su _**Analyze** --> **Expert Information**_ avrai una **panoramica** di ciò che sta accadendo nei pacchetti **analizzati**:

![](<../../../.gitbook/assets/image (570).png>)

**Indirizzi risolti**

Sotto _**Statistics --> Resolved Addresses**_ puoi trovare diverse **informazioni** che sono state "**risolte**" da Wireshark come porta/trasporto a protocollo, MAC al produttore, ecc. È interessante sapere cosa è coinvolto nella comunicazione.

![](<../../../.gitbook/assets/image (571).png>)

**Gerarchia dei protocolli**

Sotto _**Statistics --> Protocol Hierarchy**_ puoi trovare i **protocolli** **coinvolti** nella comunicazione e i dati relativi ad essi.

![](<../../../.gitbook/assets/image (572).png>)

**Conversazioni**

Sotto _**Statistics --> Conversations**_ puoi trovare un **riassunto delle conversazioni** nella comunicazione e i dati relativi ad esse.

![](<../../../.gitbook/assets/image (573).png>)

**Endpoint**

Sotto _**Statistics --> Endpoints**_ puoi trovare un **riassunto degli endpoint** nella comunicazione e i dati relativi ad ognuno di essi.

![](<../../../.gitbook/assets/image (575).png>)

**Informazioni DNS**

Sotto _**Statistics --> DNS**_ puoi trovare statistiche sulla richiesta DNS catturata.

![](<../../../.gitbook/assets/image (577).png>)

**Grafico I/O**

Sotto _**Statistics --> I/O Graph**_ puoi trovare un **grafico della comunicazione**.

![](<../../../.gitbook/assets/image (574).png>)

### Filtri

Qui puoi trovare filtri di Wireshark in base al protocollo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Altri filtri interessanti:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* Traffico HTTP e HTTPS iniziale
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* Traffico HTTP e HTTPS iniziale + SYN TCP
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* Traffico HTTP e HTTPS iniziale + SYN TCP + richieste DNS

### Ricerca

Se vuoi **cercare** il **contenuto** all'interno dei **pacchetti** delle sessioni premi _CTRL+f_. Puoi aggiungere nuovi livelli alla barra delle informazioni principali (No., Tempo, Sorgente, ecc.) premendo il pulsante destro e quindi modifica colonna.

### Laboratori pcap gratuiti

**Esercitati con le sfide gratuite di: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)**

## Identificazione dei domini

Puoi aggiungere una colonna che mostra l'intestazione Host HTTP:

![](<../../../.gitbook/assets/image (403).png>)

E una colonna che aggiunge il nome del server da una connessione HTTPS iniziale (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identificazione dei nomi host locali

### Da DHCP

Nella versione attuale di Wireshark, invece di `bootp`, devi cercare `DHCP`

![](<../../../.gitbook/assets/image (404).png>)

### Da NBNS

![](<../../../.gitbook/assets/image (405).png>)

## Decrittazione di TLS

### Decrittazione del traffico https con la chiave privata del server

_modifica>preferenze>protocollo>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

Premi _Modifica_ e aggiungi tutti i dati del server e la chiave privata (_IP, Porta, Protocollo, File chiave e password_)

### Decrittazione del traffico https con chiavi di sessione simmetriche

Sia Firefox che Chrome hanno la capacità di registrare le chiavi di sessione TLS, che possono essere utilizzate con Wireshark per decrittare il traffico TLS. Ciò consente un'analisi approfondita delle comunicazioni sicure. Maggiori dettagli su come eseguire questa decrittazione possono essere trovati in una guida su [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Per rilevare ciò, cerca nell'ambiente la variabile `SSLKEYLOGFILE`

Un file di chiavi condivise avrà questo aspetto:

![](<../../../.gitbook/assets/image (99).png>)

Per importarlo in Wireshark vai su \_modifica > preferenze > protocollo > ssl > e importalo in (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (100).png>)

## Comunicazione ADB

Estrai un APK da una comunicazione ADB in cui è stato inviato l'APK:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
