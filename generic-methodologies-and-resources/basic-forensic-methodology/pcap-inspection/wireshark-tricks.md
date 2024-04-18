# Trucchi di Wireshark

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale di WhiteIntel è combattere i takeover degli account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi controllare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}

---

## Migliora le tue abilità di Wireshark

### Tutorial

I seguenti tutorial sono fantastici per imparare alcuni trucchi di base interessanti:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informazioni Analizzate

**Informazioni Esperte**

Cliccando su _**Analyze** --> **Expert Information**_ avrai una **panoramica** di cosa sta accadendo nei pacchetti **analizzati**:

![](<../../../.gitbook/assets/image (253).png>)

**Indirizzi Risolti**

Sotto _**Statistics --> Resolved Addresses**_ puoi trovare diverse **informazioni** che sono state "**risolte**" da Wireshark come porta/trasporto a protocollo, MAC al produttore, ecc. È interessante sapere cosa è coinvolto nella comunicazione.

![](<../../../.gitbook/assets/image (890).png>)

**Gerarchia dei Protocolli**

Sotto _**Statistics --> Protocol Hierarchy**_ puoi trovare i **protocolli** **coinvolti** nella comunicazione e dati su di essi.

![](<../../../.gitbook/assets/image (583).png>)

**Conversazioni**

Sotto _**Statistics --> Conversations**_ puoi trovare un **riassunto delle conversazioni** nella comunicazione e dati su di esse.

![](<../../../.gitbook/assets/image (450).png>)

**Endpoint**

Sotto _**Statistics --> Endpoints**_ puoi trovare un **riassunto degli endpoint** nella comunicazione e dati su ciascuno di essi.

![](<../../../.gitbook/assets/image (893).png>)

**Informazioni DNS**

Sotto _**Statistics --> DNS**_ puoi trovare statistiche sulla richiesta DNS catturata.

![](<../../../.gitbook/assets/image (1060).png>)

**Grafico I/O**

Sotto _**Statistics --> I/O Graph**_ puoi trovare un **grafico della comunicazione**.

![](<../../../.gitbook/assets/image (989).png>)

### Filtri

Qui puoi trovare filtri di Wireshark a seconda del protocollo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Altri filtri interessanti:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* Traffico HTTP e HTTPS iniziale
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* Traffico HTTP e HTTPS iniziale + SYN TCP
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* Traffico HTTP e HTTPS iniziale + SYN TCP + richieste DNS

### Ricerca

Se vuoi **cercare** **contenuti** all'interno dei **pacchetti** delle sessioni premi _CTRL+f_. Puoi aggiungere nuovi livelli alla barra delle informazioni principali (No., Tempo, Sorgente, ecc.) premendo il pulsante destro e quindi modifica colonna.

### Laboratori pcap gratuiti

**Pratica con le sfide gratuite di:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificare i Domini

Puoi aggiungere una colonna che mostra l'intestazione Host HTTP:

![](<../../../.gitbook/assets/image (635).png>)

E una colonna che aggiunge il nome del server da una connessione HTTPS iniziale (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identificare i nomi host locali

### Da DHCP

Nel Wireshark attuale invece di `bootp` devi cercare `DHCP`

![](<../../../.gitbook/assets/image (1010).png>)

### Da NBNS

![](<../../../.gitbook/assets/image (1000).png>)

## Decrittazione TLS

### Decrittare il traffico https con la chiave privata del server

_modifica>preferenze>protocollo>ssl>_

![](<../../../.gitbook/assets/image (1100).png>)

Premi _Modifica_ e aggiungi tutti i dati del server e la chiave privata (_IP, Porta, Protocollo, File chiave e password_)

### Decrittare il traffico https con chiavi di sessione simmetriche

Sia Firefox che Chrome hanno la capacità di registrare le chiavi di sessione TLS, che possono essere utilizzate con Wireshark per decrittare il traffico TLS. Questo consente un'analisi approfondita delle comunicazioni sicure. Ulteriori dettagli su come eseguire questa decrittazione possono essere trovati in una guida su [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Per individuare questo cerca all'interno dell'ambiente la variabile `SSLKEYLOGFILE`

Un file di chiavi condivise apparirà così:

![](<../../../.gitbook/assets/image (817).png>)

Per importarlo in Wireshark vai a \_modifica > preferenze > protocollo > ssl > e importalo in (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (986).png>)
## Comunicazione ADB

Estrarre un APK da una comunicazione ADB in cui l'APK è stato inviato:
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
### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) è un motore di ricerca alimentato dal **dark web** che offre funzionalità **gratuite** per verificare se un'azienda o i suoi clienti sono stati **compromessi** da **malware ruba-informazioni**.

Il loro obiettivo principale di WhiteIntel è combattere i takeover di account e gli attacchi ransomware derivanti da malware che rubano informazioni.

Puoi visitare il loro sito web e provare il loro motore **gratuitamente** su:

{% embed url="https://whiteintel.io" %}


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
