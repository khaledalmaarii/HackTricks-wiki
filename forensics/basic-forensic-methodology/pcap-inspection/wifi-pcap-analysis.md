<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


# Überprüfen Sie BSSIDs

Wenn Sie einen Capture erhalten, dessen Hauptverkehr Wifi ist und Sie WireShark verwenden, können Sie alle SSIDs des Captures mit _Wireless --> WLAN Traffic_ untersuchen:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Brute Force

Eine der Spalten auf diesem Bildschirm gibt an, ob **eine Authentifizierung im pcap gefunden wurde**. Wenn dies der Fall ist, können Sie versuchen, sie mit `aircrack-ng` zu Brute-Force:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Zum Beispiel wird es das WPA-Passwort abrufen, das einen PSK (Pre-Shared Key) schützt, das später zum Entschlüsseln des Datenverkehrs erforderlich sein wird.

# Daten in Beacons / Side Channel

Wenn Sie vermuten, dass **Daten in den Beacons eines Wifi-Netzwerks durchsickern**, können Sie die Beacons des Netzwerks überprüfen, indem Sie einen Filter wie den folgenden verwenden: `wlan contains <NAMEdesNETZWERKS>` oder `wlan.ssid == "NAMEdesNETZWERKS"` suchen Sie in den gefilterten Paketen nach verdächtigen Zeichenketten.

# Unbekannte MAC-Adressen in einem Wifi-Netzwerk finden

Der folgende Link ist nützlich, um die **Geräte zu finden, die Daten in einem Wifi-Netzwerk senden**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Wenn Sie bereits **MAC-Adressen kennen, können Sie sie aus der Ausgabe entfernen**, indem Sie Überprüfungen wie diese hinzufügen: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Sobald Sie **unbekannte MAC-Adressen** entdeckt haben, die innerhalb des Netzwerks kommunizieren, können Sie **Filter** wie den folgenden verwenden: `wlan.addr==<MAC-Adresse> && (ftp || http || ssh || telnet)` um den Datenverkehr zu filtern. Beachten Sie, dass die ftp/http/ssh/telnet-Filter nützlich sind, wenn Sie den Datenverkehr entschlüsselt haben.

# Datenverkehr entschlüsseln

Bearbeiten --> Einstellungen --> Protokolle --> IEEE 802.11 --> Bearbeiten

![](<../../../.gitbook/assets/image (426).png>)





<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
