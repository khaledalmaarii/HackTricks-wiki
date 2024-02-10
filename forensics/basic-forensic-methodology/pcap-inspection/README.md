# Ispezione di Pcap

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) è l'evento di sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro bollente per professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
Una nota su **PCAP** vs **PCAPNG**: ci sono due versioni del formato di file PCAP; **PCAPNG è più recente e non supportato da tutti gli strumenti**. Potrebbe essere necessario convertire un file da PCAPNG a PCAP utilizzando Wireshark o un altro strumento compatibile, per poterlo utilizzare in altri strumenti.
{% endhint %}

## Strumenti online per pcaps

* Se l'intestazione del tuo pcap è **corrotta**, dovresti provare a **ripararla** utilizzando: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
* Estrarre **informazioni** e cercare **malware** all'interno di un pcap su [**PacketTotal**](https://packettotal.com)
* Cercare **attività malevole** utilizzando [**www.virustotal.com**](https://www.virustotal.com) e [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)

## Estrarre informazioni

Gli strumenti seguenti sono utili per estrarre statistiche, file, ecc.

### Wireshark

{% hint style="info" %}
**Se stai per analizzare un PCAP, devi fondamentalmente sapere come usare Wireshark**
{% endhint %}

Puoi trovare alcuni trucchi di Wireshark in:

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Framework Xplico

[**Xplico** ](https://github.com/xplico/xplico)_(solo linux)_ può **analizzare** un **pcap** ed estrarre informazioni da esso. Ad esempio, da un file pcap Xplico estrae ogni email (protocolli POP, IMAP e SMTP), tutti i contenuti HTTP, ogni chiamata VoIP (SIP), FTP, TFTP, e così via.

**Installare**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**Esegui**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
Accedi a _**127.0.0.1:9876**_ con le credenziali _**xplico:xplico**_

Successivamente crea un **nuovo caso**, crea una **nuova sessione** all'interno del caso e **carica il file pcap**.

### NetworkMiner

Come Xplico, è uno strumento per **analizzare ed estrarre oggetti dai file pcap**. Ha una versione gratuita che puoi **scaricare** [**qui**](https://www.netresec.com/?page=NetworkMiner). Funziona con **Windows**.\
Questo strumento è anche utile per ottenere **altri tipi di informazioni analizzate** dai pacchetti al fine di conoscere in modo **più rapido** ciò che stava accadendo.

### NetWitness Investigator

Puoi scaricare [**NetWitness Investigator da qui**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **(Funziona su Windows)**.\
Questo è un altro strumento utile che **analizza i pacchetti** e organizza le informazioni in modo utile per **conoscere ciò che sta accadendo all'interno**.

### [BruteShark](https://github.com/odedshimon/BruteShark)

* Estrarre e codificare nomi utente e password (HTTP, FTP, Telnet, IMAP, SMTP...)
* Estrarre hash di autenticazione e craccarli utilizzando Hashcat (Kerberos, NTLM, CRAM-MD5, HTTP-Digest...)
* Creare un diagramma di rete visuale (Nodi di rete e utenti)
* Estrarre le query DNS
* Ricostruire tutte le sessioni TCP e UDP
* Carving di file

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

Se stai cercando qualcosa all'interno del pcap, puoi utilizzare **ngrep**. Ecco un esempio che utilizza i filtri principali:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Intaglio

Utilizzare tecniche di intaglio comuni può essere utile per estrarre file e informazioni dal pcap:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Cattura delle credenziali

Puoi utilizzare strumenti come [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) per analizzare le credenziali da un pcap o da un'interfaccia live.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) è l'evento di sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro vivace per i professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

## Verifica Exploit/Malware

### Suricata

**Installazione e configurazione**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**Verifica pcap**

To analyze a network traffic capture file (pcap), you can use tools like Wireshark or tcpdump. These tools allow you to inspect the packets and extract valuable information from the capture.

Per analizzare un file di cattura del traffico di rete (pcap), puoi utilizzare strumenti come Wireshark o tcpdump. Questi strumenti ti consentono di ispezionare i pacchetti ed estrarre informazioni preziose dalla cattura.

To start, open the pcap file in Wireshark. You will see a list of captured packets, each with various details such as source and destination IP addresses, protocols used, and payload data.

Per iniziare, apri il file pcap in Wireshark. Vedrai un elenco di pacchetti catturati, ognuno con vari dettagli come indirizzi IP di origine e destinazione, protocolli utilizzati e dati del payload.

You can filter the packets based on specific criteria, such as IP addresses, protocols, or port numbers. This can help you focus on the relevant packets for your analysis.

Puoi filtrare i pacchetti in base a criteri specifici, come indirizzi IP, protocolli o numeri di porta. Questo può aiutarti a concentrarti sui pacchetti rilevanti per la tua analisi.

By inspecting the packet details, you can identify potential security issues, such as unauthorized access attempts, suspicious network activity, or data leaks.

Ispezionando i dettagli del pacchetto, puoi identificare potenziali problemi di sicurezza, come tentativi di accesso non autorizzati, attività di rete sospette o perdite di dati.

Additionally, you can analyze the payload data to extract information such as usernames, passwords, or sensitive data that may have been transmitted over the network.

Inoltre, puoi analizzare i dati del payload per estrarre informazioni come nomi utente, password o dati sensibili che potrebbero essere stati trasmessi sulla rete.

Remember to always handle pcap files with caution, as they may contain sensitive information. Make sure to follow ethical guidelines and legal requirements when analyzing network traffic captures.

Ricorda sempre di gestire i file pcap con cautela, poiché potrebbero contenere informazioni sensibili. Assicurati di seguire le linee guida etiche e i requisiti legali durante l'analisi delle catture di traffico di rete.
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) è uno strumento che

* Legge un file PCAP ed estrae gli stream HTTP.
* Scompatta eventuali stream compressi con gzip.
* Scansiona ogni file con Yara.
* Scrive un report.txt.
* Opzionalmente salva i file corrispondenti in una directory.

### Analisi di malware

Verifica se puoi trovare qualche impronta di un malware noto:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) è un analizzatore di traffico di rete passivo e open-source. Molti operatori utilizzano Zeek come Network Security Monitor (NSM) per supportare le indagini su attività sospette o maligne. Zeek supporta anche una vasta gamma di attività di analisi del traffico al di là del dominio della sicurezza, inclusa la misurazione delle prestazioni e la risoluzione dei problemi.

Fondamentalmente, i log creati da `zeek` non sono **pcap**. Pertanto, sarà necessario utilizzare **altri strumenti** per analizzare i log in cui sono presenti le **informazioni** sui pcap.

### Informazioni sulle connessioni
```bash
#Get info about longest connections (add "grep udp" to see only udp traffic)
#The longest connection might be of malware (constant reverse shell?)
cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service duration | sort -nrk 7 | head -n 10

10.55.100.100   49778   65.52.108.225   443     tcp     -       86222.365445
10.55.100.107   56099   111.221.29.113  443     tcp     -       86220.126151
10.55.100.110   60168   40.77.229.82    443     tcp     -       86160.119664


#Improve the metrics by summing up the total duration time for connections that have the same destination IP and Port.
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += $5 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10

10.55.100.100   65.52.108.225   443     tcp     86222.4
10.55.100.107   111.221.29.113  443     tcp     86220.1
10.55.100.110   40.77.229.82    443     tcp     86160.1

#Get the number of connections summed up per each line
cat conn.log | zeek-cut id.orig_h id.resp_h duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2] += $3; count[$1 FS $2] += 1 } END{ for (key in arr) printf "%s%s%s%s%s\n", key, FS, count[key], FS, arr[key] }' | sort -nrk 4 | head -n 10

10.55.100.100   65.52.108.225   1       86222.4
10.55.100.107   111.221.29.113  1       86220.1
10.55.100.110   40.77.229.82    134       86160.1

#Check if any IP is connecting to 1.1.1.1
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | grep '1.1.1.1' | sort | uniq -c

#Get number of connections per source IP, dest IP and dest Port
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += 1 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10


# RITA
#Something similar can be done with the tool rita
rita show-long-connections -H --limit 10 zeek_logs

+---------------+----------------+--------------------------+----------------+
|   SOURCE IP   | DESTINATION IP | DSTPORT:PROTOCOL:SERVICE |    DURATION    |
+---------------+----------------+--------------------------+----------------+
| 10.55.100.100 | 65.52.108.225  | 443:tcp:-                | 23h57m2.3655s  |
| 10.55.100.107 | 111.221.29.113 | 443:tcp:-                | 23h57m0.1262s  |
| 10.55.100.110 | 40.77.229.82   | 443:tcp:-                | 23h56m0.1197s  |

#Get connections info from rita
rita show-beacons zeek_logs | head -n 10
Score,Source IP,Destination IP,Connections,Avg Bytes,Intvl Range,Size Range,Top Intvl,Top Size,Top Intvl Count,Top Size Count,Intvl Skew,Size Skew,Intvl Dispersion,Size Dispersion
1,192.168.88.2,165.227.88.15,108858,197,860,182,1,89,53341,108319,0,0,0,0
1,10.55.100.111,165.227.216.194,20054,92,29,52,1,52,7774,20053,0,0,0,0
0.838,10.55.200.10,205.251.194.64,210,69,29398,4,300,70,109,205,0,0,0,0
```
### Informazioni DNS

When analyzing network traffic captured in a PCAP file, it is often useful to inspect the DNS (Domain Name System) information. DNS is responsible for translating domain names into IP addresses, allowing devices to communicate with each other over the internet.

To inspect DNS information in a PCAP file, you can use tools like Wireshark or tcpdump. These tools allow you to view DNS queries and responses, which can provide valuable insights into the network activity.

When inspecting DNS information, pay attention to the following:

- **DNS queries**: These are requests made by a device to resolve a domain name into an IP address. Analyzing DNS queries can help identify the domains being accessed by the device.

- **DNS responses**: These are the replies sent by DNS servers, providing the IP address associated with a domain name. Analyzing DNS responses can reveal the IP addresses of the servers being accessed.

- **DNS record types**: DNS supports various record types, such as A, AAAA, CNAME, MX, and TXT. Each record type serves a different purpose and provides different information. Understanding the record types can help in analyzing DNS information effectively.

- **DNS cache**: DNS information is often cached by devices and DNS servers to improve performance. Analyzing the DNS cache can provide insights into previously resolved domain names and their associated IP addresses.

By inspecting DNS information in a PCAP file, you can gain a better understanding of the network activity and identify any suspicious or malicious domains or IP addresses. This can be valuable in forensic investigations or network security analysis.
```bash
#Get info about each DNS request performed
cat dns.log | zeek-cut -c id.orig_h query qtype_name answers

#Get the number of times each domain was requested and get the top 10
cat dns.log | zeek-cut query | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head -n 10

#Get all the IPs
cat dns.log | zeek-cut id.orig_h query | grep 'example\.com' | cut -f 1 | sort | uniq -c

#Sort the most common DNS record request (should be A)
cat dns.log | zeek-cut qtype_name | sort | uniq -c | sort -nr

#See top DNS domain requested with rita
rita show-exploded-dns -H --limit 10 zeek_logs
```
## Altri trucchi per l'analisi dei file pcap

{% content-ref url="dnscat-exfiltration.md" %}
[dnscat-exfiltration.md](dnscat-exfiltration.md)
{% endcontent-ref %}

{% content-ref url="wifi-pcap-analysis.md" %}
[wifi-pcap-analysis.md](wifi-pcap-analysis.md)
{% endcontent-ref %}

{% content-ref url="usb-keystrokes.md" %}
[usb-keystrokes.md](usb-keystrokes.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) è l'evento sulla sicurezza informatica più rilevante in **Spagna** e uno dei più importanti in **Europa**. Con **la missione di promuovere la conoscenza tecnica**, questo congresso è un punto di incontro vivace per i professionisti della tecnologia e della sicurezza informatica in ogni disciplina.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>
