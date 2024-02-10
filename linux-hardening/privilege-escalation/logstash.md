<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


## Logstash

Logstash viene utilizzato per **raccogliere, trasformare e inviare log** attraverso un sistema noto come **pipeline**. Queste pipeline sono composte da fasi di **input**, **filtro** e **output**. Un aspetto interessante si presenta quando Logstash opera su una macchina compromessa.

### Configurazione della pipeline

Le pipeline sono configurate nel file **/etc/logstash/pipelines.yml**, che elenca le posizioni delle configurazioni delle pipeline:
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Questo file rivela dove sono posizionati i file **.conf**, contenenti le configurazioni delle pipeline. Quando si utilizza un modulo di output **Elasticsearch**, è comune che le **pipeline** includano le **credenziali Elasticsearch**, che spesso possiedono privilegi estesi a causa della necessità di Logstash di scrivere dati su Elasticsearch. I caratteri jolly nei percorsi di configurazione consentono a Logstash di eseguire tutte le pipeline corrispondenti nella directory designata.

### Escalation dei privilegi tramite pipeline scrivibili

Per tentare l'escalation dei privilegi, identificare prima l'utente sotto il quale viene eseguito il servizio Logstash, di solito l'utente **logstash**. Assicurarsi di soddisfare **una** di queste condizioni:

- Possedere **accesso in scrittura** a un file **.conf** della pipeline **o**
- Il file **/etc/logstash/pipelines.yml** utilizza un carattere jolly e si può scrivere nella cartella di destinazione

Inoltre, **una** di queste condizioni deve essere soddisfatta:

- Capacità di riavviare il servizio Logstash **o**
- Il file **/etc/logstash/logstash.yml** ha impostato **config.reload.automatic: true**

Dato un carattere jolly nella configurazione, la creazione di un file che corrisponde a questo carattere jolly consente l'esecuzione di comandi. Ad esempio:
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
Qui, **interval** determina la frequenza di esecuzione in secondi. Nell'esempio fornito, il comando **whoami** viene eseguito ogni 120 secondi, con il suo output diretto a **/tmp/output.log**.

Con **config.reload.automatic: true** in **/etc/logstash/logstash.yml**, Logstash rileverà automaticamente e applicherà nuove o modificate configurazioni di pipeline senza bisogno di riavvio. Se non è presente un carattere jolly, è comunque possibile apportare modifiche alle configurazioni esistenti, ma si consiglia cautela per evitare interruzioni.


## Riferimenti

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
