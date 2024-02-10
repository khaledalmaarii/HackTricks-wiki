# macOS Start-/Umgebungseinschränkungen und Trust Cache

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**
*
* .

</details>

## Grundlegende Informationen

Startbeschränkungen in macOS wurden eingeführt, um die Sicherheit zu verbessern, indem sie regeln, wie, von wem und von wo aus ein Prozess gestartet werden kann. Eingeführt in macOS Ventura, bieten sie einen Rahmen, der **jede Systembinary in verschiedene Constraint-Kategorien** einteilt, die in der **Trust Cache**, einer Liste mit Systembinaries und ihren entsprechenden Hashes, definiert sind. Diese Einschränkungen gelten für jede ausführbare Binary im System und umfassen eine Reihe von **Regeln**, die die Anforderungen für das Starten einer bestimmten Binary festlegen. Die Regeln umfassen Selbstbeschränkungen, die eine Binary erfüllen muss, Elternbeschränkungen, die vom übergeordneten Prozess erfüllt werden müssen, und verantwortliche Beschränkungen, die von anderen relevanten Entitäten eingehalten werden müssen.

Der Mechanismus erstreckt sich auch auf Apps von Drittanbietern durch **Umgebungseinschränkungen**, die ab macOS Sonoma eingeführt wurden und es Entwicklern ermöglichen, ihre Apps durch Angabe eines Satzes von Schlüsseln und Werten für Umgebungseinschränkungen zu schützen.

Sie definieren **Startumgebung und Bibliothekseinschränkungen** in Constraint-Dictionaries, die Sie entweder in **`launchd`-Eigenschaftslisten-Dateien** oder in **separaten Eigenschaftslisten**-Dateien speichern, die Sie beim Codesignieren verwenden.

Es gibt 4 Arten von Einschränkungen:

* **Selbstbeschränkungen**: Einschränkungen, die auf die **ausgeführte** Binary angewendet werden.
* **Elternprozess**: Einschränkungen, die auf den **übergeordneten Prozess** angewendet werden (z. B. **`launchd`**, der einen XP-Dienst ausführt).
* **Verantwortliche Beschränkungen**: Einschränkungen, die auf den **Prozess angewendet werden, der den Dienst aufruft**, in einer XPC-Kommunikation.
* **Bibliotheksladebeschränkungen**: Verwenden Sie Bibliotheksladebeschränkungen, um selektiv Code zu beschreiben, der geladen werden kann.

Wenn ein Prozess versucht, einen anderen Prozess zu starten - indem er `execve(_:_:_:)` oder `posix_spawn(_:_:_:_:_:_:)` aufruft - überprüft das Betriebssystem, ob die **ausführbare** Datei ihre **eigene Selbstbeschränkung** erfüllt. Es überprüft auch, ob die ausführbare Datei des **übergeordneten Prozesses** die **Elternbeschränkung** der ausführbaren Datei erfüllt und ob die ausführbare Datei des **verantwortlichen Prozesses** die **verantwortliche Prozessbeschränkung** der ausführbaren Datei erfüllt. Wenn eine dieser Startbeschränkungen nicht erfüllt ist, führt das Betriebssystem das Programm nicht aus.

Wenn beim Laden einer Bibliothek ein Teil der **Bibliothekseinschränkung nicht erfüllt** ist, lädt Ihr Prozess die Bibliothek nicht.

## LC-Kategorien

Eine LC besteht aus **Fakten** und **logischen Operationen** (und, oder...), die Fakten kombinieren.

Die [**Fakten, die eine LC verwenden kann, sind dokumentiert**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). Zum Beispiel:

* is-init-proc: Ein boolescher Wert, der angibt, ob die ausführbare Datei der Initialisierungsprozess des Betriebssystems (`launchd`) sein muss.
* is-sip-protected: Ein boolescher Wert, der angibt, ob die ausführbare Datei eine von der Systemintegritätsschutz (SIP) geschützte Datei sein muss.
* `on-authorized-authapfs-volume:` Ein boolescher Wert, der angibt, ob das Betriebssystem die ausführbare Datei von einem autorisierten, authentifizierten APFS-Volume geladen hat.
* `on-authorized-authapfs-volume`: Ein boolescher Wert, der angibt, ob das Betriebssystem die ausführbare Datei von einem autorisierten, authentifizierten APFS-Volume geladen hat.
* Cryptexes-Volume
* `on-system-volume:` Ein boolescher Wert, der angibt, ob das Betriebssystem die ausführbare Datei vom aktuell gebooteten Systemvolume geladen hat.
* Innerhalb von /System...
* ...

Wenn eine Apple-Binary signiert ist, **weist sie eine LC-Kategorie** im **Trust Cache** zu.

* Die **LC-Kategorien für iOS 16** wurden [**hier umgekehrt und dokumentiert**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* Die aktuellen **LC-Kategorien (macOS 14** - Somona) wurden umgekehrt und ihre [**Beschreibungen finden Sie hier**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Zum Beispiel ist Kategorie 1:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(on-authorized-authapfs-volume || on-system-volume)`: Muss sich im System- oder Cryptexes-Volume befinden.
* `launch-type == 1`: Muss ein Systemdienst sein (plist in LaunchDaemons).
* `validation-category == 1`: Ein Betriebssystem-Executable.
* `is-init-proc`: Launchd

### Umkehrung der LC-Kategorien

Weitere Informationen dazu finden Sie [**hier**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), aber im Grunde genommen sind sie in **AMFI (AppleMobileFileIntegrity)** definiert, daher müssen Sie das Kernel Development Kit herunterladen, um das **KEXT** zu erhalten. Die Symbole, die mit **`kConstraintCategory`** beginnen, sind die **interessanten**. Wenn Sie sie extrahieren, erhalten Sie einen DER (ASN.1) codierten Stream, den Sie mit dem [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) oder der python-asn1-Bibliothek und ihrem `dump.py`-Skript, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), decodieren müssen, was Ihnen einen verständlicheren String liefert.

## Umgebungseinschränkungen

Dies sind die konfigurierten Launch Constraints in **Drittanbieteranwendungen**. Der Entwickler kann die **Fakten** und **logischen Operanden** auswählen, die in seiner Anwendung verwendet werden sollen, um den Zugriff darauf einzuschränken.

Es ist möglich, die Umgebungseinschränkungen einer Anwendung mit folgendem Befehl aufzulisten:
```bash
codesign -d -vvvv app.app
```
## Trust-Caches

In **macOS** gibt es einige Trust-Caches:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

Und in iOS scheint es sich in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** zu befinden.

{% hint style="warning" %}
Auf macOS-Geräten mit Apple Silicon verweigert AMFI das Laden einer von Apple signierten Binärdatei, wenn sie nicht im Trust-Cache enthalten ist.
{% endhint %}

### Auflisten von Trust-Caches

Die zuvor genannten Trust-Cache-Dateien haben das Format **IMG4** und **IM4P**, wobei IM4P der Payload-Bereich eines IMG4-Formats ist.

Sie können [**pyimg4**](https://github.com/m1stadev/PyIMG4) verwenden, um den Payload der Datenbanken zu extrahieren:

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

(Eine andere Option könnte sein, das Tool [**img4tool**](https://github.com/tihmstar/img4tool) zu verwenden, das auch auf M1 läuft, selbst wenn die Version veraltet ist und für x86\_64, wenn Sie es an den richtigen Stellen installieren).

Jetzt können Sie das Tool [**trustcache**](https://github.com/CRKatri/trustcache) verwenden, um die Informationen in einem lesbaren Format zu erhalten:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Der Trust-Cache folgt der folgenden Struktur, daher ist die **LC-Kategorie die vierte Spalte**.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Dann könnten Sie ein Skript wie [**dieses hier**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) verwenden, um Daten zu extrahieren.

Aus diesen Daten können Sie die Apps überprüfen, die einen **Startbeschränkungswert von `0`** haben, was bedeutet, dass sie nicht eingeschränkt sind ([**hier überprüfen**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056), was jeder Wert bedeutet).

## Angriffsabwehr

Startbeschränkungen hätten mehrere alte Angriffe abgewehrt, indem sie sicherstellen, dass der Prozess nicht unter unerwarteten Bedingungen ausgeführt wird. Zum Beispiel aus unerwarteten Orten oder wenn er von einem unerwarteten übergeordneten Prozess aufgerufen wird (wenn nur launchd ihn starten sollte).

Darüber hinaus schützen Startbeschränkungen auch vor Downgrade-Angriffen.

Sie schützen jedoch nicht vor gängigen XPC-Missbräuchen, Electron-Code-Injektionen oder dylib-Injektionen ohne Bibliotheksvalidierung (es sei denn, die Team-IDs, die Bibliotheken laden können, sind bekannt).

### XPC-Dämonenschutz

In der Sonoma-Version ist eine bemerkenswerte Änderung die **Verantwortungskonfiguration des XPC-Dienstes**. Der XPC-Dienst ist für sich selbst verantwortlich, im Gegensatz dazu ist der verbindende Client verantwortlich. Dies ist im Feedback-Bericht FB13206884 dokumentiert. Diese Konfiguration mag fehlerhaft erscheinen, da sie bestimmte Interaktionen mit dem XPC-Dienst ermöglicht:

- **Starten des XPC-Dienstes**: Wenn dies als Fehler angesehen wird, erlaubt diese Konfiguration nicht das Initiieren des XPC-Dienstes durch Angreifercode.
- **Verbindung zu einem aktiven Dienst**: Wenn der XPC-Dienst bereits läuft (möglicherweise aktiviert durch seine ursprüngliche Anwendung), gibt es keine Barrieren, um eine Verbindung zu ihm herzustellen.

Obwohl die Implementierung von Beschränkungen für den XPC-Dienst vorteilhaft sein könnte, indem der Angriffsvektor eingeschränkt wird, adressiert dies nicht das Hauptproblem. Die Sicherheit des XPC-Dienstes erfordert grundsätzlich eine effektive Validierung des verbindenden Clients. Dies ist nach wie vor die einzige Methode, um die Sicherheit des Dienstes zu stärken. Es ist auch erwähnenswert, dass die genannte Verantwortungskonfiguration derzeit aktiv ist, was möglicherweise nicht mit dem beabsichtigten Design übereinstimmt.

### Electron-Schutz

Auch wenn es erforderlich ist, dass die Anwendung **von LaunchService geöffnet wird** (in den übergeordneten Beschränkungen). Dies kann mit **`open`** (das Umgebungsvariablen setzen kann) oder mit der **Launch Services API** (bei der Umgebungsvariablen angegeben werden können) erreicht werden.

## Referenzen

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersecurity-Unternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder folgen Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**
*
* .

</details>
