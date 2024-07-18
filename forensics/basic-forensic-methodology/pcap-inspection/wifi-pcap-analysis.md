{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}


# Überprüfen von BSSIDs

Wenn Sie einen Capture erhalten, dessen Hauptverkehr Wifi mit WireShark ist, können Sie alle SSIDs des Captures mit _Wireless --> WLAN Traffic_ untersuchen:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Brute Force

Eine der Spalten dieses Bildschirms gibt an, ob **eine Authentifizierung im pcap gefunden wurde**. In diesem Fall können Sie versuchen, sie mit `aircrack-ng` zu Brute-Forcen:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
```markdown
Zum Beispiel wird es das WPA-Passwort abrufen, das einen PSK (pre-shared key) schützt, das später zum Entschlüsseln des Datenverkehrs erforderlich sein wird.

# Daten in Beacons / Side Channel

Wenn Sie vermuten, dass **Daten in den Beacons eines WLAN-Netzwerks durchsickern**, können Sie die Beacons des Netzwerks mithilfe eines Filters wie dem folgenden überprüfen: `wlan contains <NAMEdesNETZWERKS>` oder `wlan.ssid == "NAMEdesNETZWERKS"` suchen Sie in den gefilterten Paketen nach verdächtigen Zeichenfolgen.

# Unbekannte MAC-Adressen in einem WLAN-Netzwerk finden

Der folgende Link ist nützlich, um die **Geräte zu finden, die Daten in einem WLAN-Netzwerk senden**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Wenn Sie bereits **MAC-Adressen kennen, können Sie sie aus der Ausgabe entfernen**, indem Sie Überprüfungen wie diese hinzufügen: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Sobald Sie **unbekannte MAC-Adressen** entdeckt haben, die im Netzwerk kommunizieren, können Sie **Filter** wie den folgenden verwenden: `wlan.addr==<MAC-Adresse> && (ftp || http || ssh || telnet)` um den Datenverkehr zu filtern. Beachten Sie, dass ftp/http/ssh/telnet-Filter nützlich sind, wenn Sie den Datenverkehr entschlüsselt haben.

# Datenverkehr entschlüsseln

Bearbeiten --> Einstellungen --> Protokolle --> IEEE 802.11 --> Bearbeiten

![](<../../../.gitbook/assets/image (426).png>)

{% hint style="success" %}
Lernen & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys einreichen.

</details>
{% endhint %}
```
