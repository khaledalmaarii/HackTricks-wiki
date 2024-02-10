# PsExec/Winexec/ScExec

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Wie funktionieren sie

Der Prozess wird in den folgenden Schritten erläutert, die zeigen, wie Service-Binärdateien manipuliert werden, um eine Remote-Ausführung auf einer Zielmaschine über SMB zu erreichen:

1. **Kopieren einer Service-Binärdatei auf den ADMIN$-Freigabe über SMB**.
2. **Erstellen eines Dienstes auf der Remote-Maschine**, indem auf die Binärdatei verwiesen wird.
3. Der Dienst wird **remote gestartet**.
4. Beim Beenden wird der Dienst **gestoppt und die Binärdatei gelöscht**.

### **Ablauf der manuellen Ausführung von PsExec**

Angenommen, es gibt eine ausführbare Nutzlast (erstellt mit msfvenom und mit Veil obfuskiert, um die Erkennung durch Antivirensoftware zu umgehen), mit dem Namen 'met8888.exe', die eine Meterpreter Reverse-HTTP-Nutzlast darstellt, werden die folgenden Schritte unternommen:

- **Kopieren der Binärdatei**: Die ausführbare Datei wird von einem Befehlsfenster aus auf die ADMIN$-Freigabe kopiert, obwohl sie an einem beliebigen Ort im Dateisystem platziert werden kann, um verborgen zu bleiben.

- **Erstellen eines Dienstes**: Mit dem Windows-Befehl `sc`, der das Abfragen, Erstellen und Löschen von Windows-Diensten remote ermöglicht, wird ein Dienst mit dem Namen "meterpreter" erstellt, der auf die hochgeladene Binärdatei verweist.

- **Starten des Dienstes**: Der letzte Schritt besteht darin, den Dienst zu starten, was wahrscheinlich zu einem "Timeout"-Fehler führt, da die Binärdatei keine echte Dienst-Binärdatei ist und den erwarteten Antwortcode nicht zurückgibt. Dieser Fehler ist unerheblich, da das Hauptziel die Ausführung der Binärdatei ist.

Die Beobachtung des Metasploit-Listeners zeigt, dass die Sitzung erfolgreich initiiert wurde.

[Erfahren Sie mehr über den `sc`-Befehl](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Weitere detaillierte Schritte finden Sie unter: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Sie können auch die Windows Sysinternals-Binärdatei PsExec.exe verwenden:**

![](<../../.gitbook/assets/image (165).png>)

Sie können auch [**SharpLateral**](https://github.com/mertdas/SharpLateral) verwenden:

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
