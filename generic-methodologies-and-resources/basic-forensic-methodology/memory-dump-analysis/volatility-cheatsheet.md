# Volatility - Spickzettel

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **dem Ziel, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsfachleute in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

Wenn Sie etwas **Schnelles und Verrücktes** wollen, das mehrere Volatility-Plugins parallel startet, können Sie dies verwenden: [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## Installation

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
#### Methode 1: Prozessliste anzeigen

Verwenden Sie den Befehl `pslist`, um eine Liste aller laufenden Prozesse im Speicherabbild anzuzeigen.

```bash
volatility -f memory_dump.raw --profile=PROFILE pslist
```

Ersetzen Sie `memory_dump.raw` durch den Pfad zum Speicherabbild und `PROFILE` durch das Profil, das für das Speicherabbild geeignet ist.

Dieser Befehl zeigt Informationen wie PID (Prozess-ID), Name, Elternprozess-ID, Startzeit und Speicherbereich des Prozesses an.

Beispiel:

```bash
volatility -f memory_dump.raw --profile=Win7SP1x64 pslist
```

{% endtab %}

{% tab title="Method2" %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% tab title="Methode 2" %}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Volatility-Befehle

Greifen Sie auf die offizielle Dokumentation unter [Volatility-Befehlsreferenz](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan) zu.

### Hinweis zu "list"- und "scan"-Plugins

Volatility hat zwei Hauptansätze für Plugins, die sich manchmal in ihren Namen widerspiegeln. "List"-Plugins versuchen, durch Windows-Kernel-Strukturen zu navigieren, um Informationen wie Prozesse (Suchen und Durchlaufen der verketteten Liste der `_EPROCESS`-Strukturen im Speicher), Betriebssystem-Handles (Suchen und Auflisten der Handle-Tabelle, Dereferenzieren von gefundenen Zeigern usw.) abzurufen. Sie verhalten sich mehr oder weniger wie die Windows-API, wenn sie beispielsweise Prozesse auflistet.

Das macht "List"-Plugins ziemlich schnell, aber genauso anfällig für Manipulationen durch Malware wie die Windows-API. Wenn beispielsweise Malware DKOM verwendet, um einen Prozess aus der verketteten Liste `_EPROCESS` zu trennen, wird er nicht im Task-Manager angezeigt und auch nicht in der pslist.

"Scan"-Plugins hingegen verwenden einen Ansatz ähnlich dem Herausschneiden des Speichers nach Dingen, die Sinn ergeben könnten, wenn sie als bestimmte Strukturen dereferenziert werden. `psscan` liest beispielsweise den Speicher und versucht, `_EPROCESS`-Objekte daraus zu erstellen (es verwendet Pool-Tag-Scanning, bei dem nach 4-Byte-Zeichenketten gesucht wird, die auf das Vorhandensein einer interessanten Struktur hinweisen). Der Vorteil ist, dass es Prozesse ausgraben kann, die beendet wurden, und selbst wenn Malware die verkettete Liste `_EPROCESS` manipuliert, findet das Plugin die Struktur immer noch im Speicher (da sie für den Prozess weiterhin vorhanden sein muss). Der Nachteil ist, dass "Scan"-Plugins etwas langsamer als "List"-Plugins sind und manchmal falsch positive Ergebnisse liefern können (ein Prozess, der vor langer Zeit beendet wurde und dessen Struktur von anderen Operationen überschrieben wurde).

Quelle: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## Betriebssystem-Profile

### Volatility3

Wie im Readme erklärt, müssen Sie die **Symboltabelle des Betriebssystems**, das Sie unterstützen möchten, in _volatility3/volatility/symbols_ platzieren.\
Symboltabelle-Pakete für verschiedene Betriebssysteme stehen zum **Download** zur Verfügung unter:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### Externes Profil

Sie können die Liste der unterstützten Profile erhalten, indem Sie Folgendes tun:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
Wenn Sie ein **neues Profil, das Sie heruntergeladen haben**, verwenden möchten (zum Beispiel ein Linux-Profil), müssen Sie die folgende Ordnerstruktur erstellen: _plugins/overlays/linux_ und die Zip-Datei mit dem Profil in diesen Ordner legen. Anschließend erhalten Sie die Anzahl der Profile mit dem Befehl:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
Sie können **Linux- und Mac-Profile** von [https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles) herunterladen.

Im vorherigen Abschnitt sehen Sie, dass das Profil `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64` genannt wird und Sie es verwenden können, um etwas Ähnliches auszuführen:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### Profil entdecken

```plaintext
volatility -f <memory_dump> imageinfo
```

```plaintext
volatility -f <memory_dump> kdbgscan
```

```plaintext
volatility -f <memory_dump> hivelist
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=html -D <output_directory>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=csv -D <output_directory>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=json -D <output_directory>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv> --output-encryption-salt=<output_encryption_salt>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv> --output-encryption-salt=<output_encryption_salt> --output-encryption-iterations=<output_encryption_iterations>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv> --output-encryption-salt=<output_encryption_salt> --output-encryption-iterations=<output_encryption_iterations> --output-encryption-mode=<output_encryption_mode>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv> --output-encryption-salt=<output_encryption_salt> --output-encryption-iterations=<output_encryption_iterations> --output-encryption-mode=<output_encryption_mode> --output-encryption-padding=<output_encryption_padding>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv> --output-encryption-salt=<output_encryption_salt> --output-encryption-iterations=<output_encryption_iterations> --output-encryption-mode=<output_encryption_mode> --output-encryption-padding=<output_encryption_padding> --output-encryption-authentication=<output_encryption_authentication>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv> --output-encryption-salt=<output_encryption_salt> --output-encryption-iterations=<output_encryption_iterations> --output-encryption-mode=<output_encryption_mode> --output-encryption-padding=<output_encryption_padding> --output-encryption-authentication=<output_encryption_authentication> --output-encryption-authentication-key=<output_encryption_authentication_key>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv> --output-encryption-salt=<output_encryption_salt> --output-encryption-iterations=<output_encryption_iterations> --output-encryption-mode=<output_encryption_mode> --output-encryption-padding=<output_encryption_padding> --output-encryption-authentication=<output_encryption_authentication> --output-encryption-authentication-key=<output_encryption_authentication_key> --output-encryption-authentication-iv=<output_encryption_authentication_iv>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv> --output-encryption-salt=<output_encryption_salt> --output-encryption-iterations=<output_encryption_iterations> --output-encryption-mode=<output_encryption_mode> --output-encryption-padding=<output_encryption_padding> --output-encryption-authentication=<output_encryption_authentication> --output-encryption-authentication-key=<output_encryption_authentication_key> --output-encryption-authentication-iv=<output_encryption_authentication_iv> --output-encryption-authentication-tag=<output_encryption_authentication_tag>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv> --output-encryption-salt=<output_encryption_salt> --output-encryption-iterations=<output_encryption_iterations> --output-encryption-mode=<output_encryption_mode> --output-encryption-padding=<output_encryption_padding> --output-encryption-authentication=<output_encryption_authentication> --output-encryption-authentication-key=<output_encryption_authentication_key> --output-encryption-authentication-iv=<output_encryption_authentication_iv> --output-encryption-authentication-tag=<output_encryption_authentication_tag> --output-encryption-authentication-aad=<output_encryption_authentication_aad>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv> --output-encryption-salt=<output_encryption_salt> --output-encryption-iterations=<output_encryption_iterations> --output-encryption-mode=<output_encryption_mode> --output-encryption-padding=<output_encryption_padding> --output-encryption-authentication=<output_encryption_authentication> --output-encryption-authentication-key=<output_encryption_authentication_key> --output-encryption-authentication-iv=<output_encryption_authentication_iv> --output-encryption-authentication-tag=<output_encryption_authentication_tag> --output-encryption-authentication-aad=<output_encryption_authentication_aad> --output-encryption-authentication-tag-length=<output_encryption_authentication_tag_length>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv> --output-encryption-salt=<output_encryption_salt> --output-encryption-iterations=<output_encryption_iterations> --output-encryption-mode=<output_encryption_mode> --output-encryption-padding=<output_encryption_padding> --output-encryption-authentication=<output_encryption_authentication> --output-encryption-authentication-key=<output_encryption_authentication_key> --output-encryption-authentication-iv=<output_encryption_authentication_iv> --output-encryption-authentication-tag=<output_encryption_authentication_tag> --output-encryption-authentication-aad=<output_encryption_authentication_aad> --output-encryption-authentication-tag-length=<output_encryption_authentication_tag_length> --output-encryption-authentication-tag-iv=<output_encryption_authentication_tag_iv>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv> --output-encryption-salt=<output_encryption_salt> --output-encryption-iterations=<output_encryption_iterations> --output-encryption-mode=<output_encryption_mode> --output-encryption-padding=<output_encryption_padding> --output-encryption-authentication=<output_encryption_authentication> --output-encryption-authentication-key=<output_encryption_authentication_key> --output-encryption-authentication-iv=<output_encryption_authentication_iv> --output-encryption-authentication-tag=<output_encryption_authentication_tag> --output-encryption-authentication-aad=<output_encryption_authentication_aad> --output-encryption-authentication-tag-length=<output_encryption_authentication_tag_length> --output-encryption-authentication-tag-iv=<output_encryption_authentication_tag_iv> --output-encryption-authentication-tag-iv-length=<output_encryption_authentication_tag_iv_length>
```

```plaintext
volatility -f <memory_dump> printkey -K <registry_key> -o <offset> --output=sqlite -D <output_directory> --output-file=<output_file> --output-format=<output_format> --output-encoding=<output_encoding> --output-compression=<output_compression> --output-compression-level=<output_compression_level> --output-encryption=<output_encryption> --output-password=<output_password> --output-encryption-algorithm=<output_encryption_algorithm> --output-encryption-key=<output_encryption_key> --output-encryption-iv=<output_encryption_iv> --output-encryption-salt=<output_encryption_salt> --output-encryption-iterations=<output_encryption_iterations> --output-encryption-mode=<output_encryption_mode> --output-encryption-padding=<output_encryption_padding> --output-encryption-authentication=<output_encryption_authentication> --output-encryption-authentication-key=<output_encryption_authentication_key> --output-encryption-authentication-iv=<output_encryption_authentication_iv> --output-encryption-authentication-tag=<output_encryption_authentication_tag> --output-encryption-authentication-aad=<output_encryption_authentication_aad> --output-encryption-authentication-tag-length=<output_encryption_authentication_tag_length> --output-encryption-authentication-tag-iv=<output_encryption_authentication_tag_iv> --output-encryption-authentication-tag-iv-length=<output_encryption_authentication_tag_iv_length> --output
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **Unterschiede zwischen imageinfo und kdbgscan**

[**Von hier**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): Im Gegensatz zu imageinfo, das nur Profilvorschläge liefert, ist **kdbgscan** darauf ausgelegt, das richtige Profil und die richtige KDBG-Adresse (falls mehrere vorhanden sind) positiv zu identifizieren. Dieses Plugin sucht nach den mit Volatility-Profilen verknüpften KDBGHeader-Signaturen und wendet Integritätsprüfungen an, um falsche positive Ergebnisse zu reduzieren. Die Ausführlichkeit der Ausgabe und die Anzahl der durchgeführten Integritätsprüfungen hängen davon ab, ob Volatility eine DTB finden kann. Wenn Sie also bereits das richtige Profil kennen (oder wenn Sie einen Profilvorschlag von imageinfo haben), stellen Sie sicher, dass Sie es verwenden.

Werfen Sie immer einen Blick auf die **Anzahl der Prozesse, die kdbgscan gefunden hat**. Manchmal können imageinfo und kdbgscan **mehr als ein geeignetes Profil finden**, aber nur das **gültige Profil wird einige prozessbezogene Informationen enthalten** (Dies liegt daran, dass zur Extraktion von Prozessen die richtige KDBG-Adresse benötigt wird).
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

Der **Kernel Debugger Block**, von Volatility als **KDBG** bezeichnet, ist für forensische Aufgaben, die von Volatility und verschiedenen Debuggern durchgeführt werden, entscheidend. Er wird als `KdDebuggerDataBlock` identifiziert und hat den Typ `_KDDEBUGGER_DATA64`. Er enthält wichtige Verweise wie `PsActiveProcessHead`. Dieser spezifische Verweis zeigt auf den Anfang der Prozessliste und ermöglicht die Auflistung aller Prozesse, was für eine gründliche Speicheranalyse unerlässlich ist.

## Betriebssysteminformationen
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
Das Plugin `banners.Banners` kann in **vol3 verwendet werden, um Linux-Banner** im Dump zu finden.

## Hashes/Passwörter

Extrahiere SAM-Hashes, [zwischengespeicherte Anmeldeinformationen der Domäne](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) und [lsa secrets](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets).

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{% endtab %}
{% endtabs %}

## Speicherabbild

Das Speicherabbild eines Prozesses extrahiert **alles** zum aktuellen Status des Prozesses. Das Modul **procdump** extrahiert nur den **Code**.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit der Mission, technisches Wissen zu fördern, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsprofis in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

## Prozesse

### Prozesse auflisten

Versuchen Sie, **verdächtige** Prozesse (nach Namen) oder **unerwartete** Kindprozesse zu finden (zum Beispiel eine cmd.exe als Kind von iexplorer.exe).\
Es könnte interessant sein, das Ergebnis von pslist mit dem von psscan zu vergleichen, um versteckte Prozesse zu identifizieren.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{% tab title="vol2" %}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{% endtab %}
{% endtabs %}

### Dump proc

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### Befehlszeile

Wurde etwas Verdächtiges ausgeführt?

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

- `volatility -f <memory_dump_file> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump_file> --profile=<profile_name> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile_name> psscan`: This command scans the memory dump for hidden or terminated processes.
- `volatility -f <memory_dump_file> --profile=<profile_name> dlllist -p <process_id>`: This command lists all loaded DLLs for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> cmdline -p <process_id>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump_file> --profile=<profile_name> dumpfiles -Q <file_object_address> -D <output_directory>`: This command dumps a specific file from the memory dump.

### Advanced Volatility Commands

- `volatility -f <memory_dump_file> --profile=<profile_name> malfind`: This command scans the memory dump for injected or modified code.
- `volatility -f <memory_dump_file> --profile=<profile_name> apihooks`: This command lists all API hooks in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile_name> handles -p <process_id>`: This command lists all open handles for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump_file> --profile=<profile_name> connscan`: This command scans the memory dump for TCP and UDP connections.
- `volatility -f <memory_dump_file> --profile=<profile_name> timeliner`: This command creates a timeline of events based on timestamps in the memory dump.

### Memory Analysis Plugins

Volatility provides a wide range of plugins for analyzing different aspects of memory dumps. Some of the most commonly used plugins include:

- `pslist`: Lists all running processes.
- `psscan`: Scans for hidden or terminated processes.
- `dlllist`: Lists loaded DLLs for a specific process.
- `cmdline`: Displays command line arguments for a specific process.
- `filescan`: Scans for file objects.
- `dumpfiles`: Dumps specific files from the memory dump.
- `malfind`: Scans for injected or modified code.
- `apihooks`: Lists API hooks.
- `handles`: Lists open handles for a specific process.
- `netscan`: Scans for network connections.
- `connscan`: Scans for TCP and UDP connections.
- `timeliner`: Creates a timeline of events based on timestamps.

### Additional Resources

- [Volatility GitHub repository](https://github.com/volatilityfoundation/volatility)
- [Volatility documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility plugins](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

Befehle, die in `cmd.exe` ausgeführt werden, werden von **`conhost.exe`** (oder `csrss.exe` in Systemen vor Windows 7) verwaltet. Das bedeutet, dass, wenn **`cmd.exe`** von einem Angreifer beendet wird, bevor ein Memory-Dump erhalten wird, es immer noch möglich ist, die Befehlshistorie der Sitzung aus dem Speicher von **`conhost.exe`** wiederherzustellen. Um dies zu tun, sollte bei ungewöhnlicher Aktivität innerhalb der Konsolenmodule der Speicher des zugehörigen **`conhost.exe`**-Prozesses gedumpt werden. Anschließend können durch die Suche nach **Strings** in diesem Dump potenziell verwendete Befehlszeilen der Sitzung extrahiert werden.

### Umgebung

Erhalten Sie die Umgebungsvariablen jedes laufenden Prozesses. Es könnten einige interessante Werte vorhanden sein.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{% tab title="vol2" %}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
{% endtab %}
{% endtabs %}

### Token-Berechtigungen

Überprüfen Sie Berechtigungstoken in unerwarteten Diensten.\
Es könnte interessant sein, die Prozesse aufzulisten, die ein privilegiertes Token verwenden.
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% tab title="vol2" %}
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

### SIDs

Überprüfen Sie jede SSID, die von einem Prozess verwendet wird.\
Es könnte interessant sein, die Prozesse aufzulisten, die eine privilegierte SSID verwenden (und die Prozesse, die eine bestimmte Dienst-SSID verwenden).
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

- `volatility -f <memory_dump_file> imageinfo`: This command displays information about the memory dump file, such as the profile and operating system version.
- `volatility -f <memory_dump_file> --profile=<profile> <command>`: This command runs a specific Volatility command using the specified profile.
- `volatility -f <memory_dump_file> --profile=<profile> --output-file=<output_file> <command>`: This command runs a specific Volatility command and saves the output to a file.

### Memory Analysis

- `volatility -f <memory_dump_file> --profile=<profile> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> psscan`: This command scans for hidden processes in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> dlllist -p <pid>`: This command lists the DLLs loaded by a specific process.
- `volatility -f <memory_dump_file> --profile=<profile> handles -p <pid>`: This command lists the handles opened by a specific process.

### Network Analysis

- `volatility -f <memory_dump_file> --profile=<profile> connections`: This command lists the network connections in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> connscan`: This command scans for hidden network connections in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> netscan`: This command scans for network artifacts in the memory dump.

### File Analysis

- `volatility -f <memory_dump_file> --profile=<profile> filescan`: This command scans for file objects in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> dumpfiles -Q <address_range>`: This command dumps files from the memory dump based on the specified address range.

### Registry Analysis

- `volatility -f <memory_dump_file> --profile=<profile> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> printkey -K <key_path>`: This command displays the contents of a specific registry key.

### Malware Analysis

- `volatility -f <memory_dump_file> --profile=<profile> malfind`: This command scans for injected code and suspicious processes in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> malprocfind`: This command scans for malicious processes in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> malsysproc`: This command lists the system processes associated with malware in the memory dump.

### Plugin Usage

- `volatility -f <memory_dump_file> --profile=<profile> --plugins=<plugin_directory> <plugin_name>`: This command runs a specific Volatility plugin using the specified profile and plugin directory.

### Additional Resources

- Volatility GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
- Volatility documentation: [https://github.com/volatilityfoundation/volatility/wiki](https://github.com/volatilityfoundation/volatility/wiki)
- Volatility plugins: [https://github.com/volatilityfoundation/community](https://github.com/volatilityfoundation/community)

### References

- Volatility Cheat Sheet: [https://github.com/sans-dfir/sift-cheatsheet/blob/master/cheatsheets/Volatility-Commands.pdf](https://github.com/sans-dfir/sift-cheatsheet/blob/master/cheatsheets/Volatility-Commands.pdf)
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{% endtab %}
{% endtabs %}

### Handles

Nützlich zu wissen, zu welchen anderen Dateien, Schlüsseln, Threads, Prozessen... ein Prozess einen **Handle** hat (geöffnet hat)
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. It includes commands and techniques for analyzing memory dumps to extract valuable information during forensic investigations.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required dependencies using pip: `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository: `git clone https://github.com/volatilityfoundation/volatility.git`.
4. Navigate to the Volatility directory: `cd volatility`.
5. Run Volatility using the command `python vol.py`.

### Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin_name>
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin_name>` with the name of the plugin you want to use for analysis.

### Common Plugins

Here are some commonly used plugins in Volatility:

- `pslist`: Lists running processes.
- `pstree`: Displays a process tree.
- `dlllist`: Lists loaded DLLs.
- `handles`: Lists open handles.
- `cmdline`: Displays command-line arguments.
- `filescan`: Scans for file objects in memory.
- `malfind`: Finds hidden and injected code.
- `svcscan`: Lists Windows services.
- `connscan`: Scans for network connections.
- `netscan`: Lists network connections.
- `printkey`: Prints registry keys.
- `hivelist`: Lists registry hives.

### Advanced Techniques

Volatility also supports advanced techniques for memory analysis, such as:

- **Process Memory Analysis**: Analyzing the memory of a specific process.
- **Kernel Memory Analysis**: Analyzing the kernel memory.
- **Network Analysis**: Analyzing network connections and traffic.
- **Registry Analysis**: Analyzing the Windows registry.
- **Malware Analysis**: Analyzing malware artifacts in memory.

### Additional Resources

For more information on using Volatility and memory forensics, refer to the following resources:

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [The Art of Memory Forensics](https://www.amazon.com/Art-Memory-Forensics-Detecting-Malware/dp/1118825098)

Happy memory analysis!
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{% endtab %}
{% endtabs %}

### DLLs

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{% endtab %}
{% endtabs %}

### Strings pro Prozess

Volatility ermöglicht es uns zu überprüfen, welchem Prozess eine Zeichenkette gehört.

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{% tab title="vol2" %}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

Es ermöglicht auch die Suche nach Zeichenketten innerhalb eines Prozesses mithilfe des yarascan-Moduls:

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{% endtab %}
{% endtabs %}

### UserAssist

**Windows** speichert Informationen über die von Ihnen ausgeführten Programme mithilfe eines Features namens **UserAssist-Schlüssel** in der Registrierung. Diese Schlüssel protokollieren, wie oft jedes Programm ausgeführt wurde und wann es zuletzt ausgeführt wurde.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{% tab title="vol2" %}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **dem Ziel, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsprofis in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

## Dienstleistungen

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{% tab title="vol2" %}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
## Netzwerk

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
{% endtab %}
{% endtabs %}

## Registrierungshive

### Verfügbare Hives anzeigen

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

Here are some basic Volatility commands that you can use for memory analysis:

- `volatility -f <memory_dump> imageinfo`: This command displays information about the memory dump file, such as the operating system version and profile.
- `volatility -f <memory_dump> --profile=<profile> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump> --profile=<profile> psscan`: This command scans for processes in the memory dump.
- `volatility -f <memory_dump> --profile=<profile> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump> --profile=<profile> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump> --profile=<profile> cmdline -p <pid>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump> --profile=<profile> filescan`: This command scans for file objects in the memory dump.
- `volatility -f <memory_dump> --profile=<profile> netscan`: This command scans for network connections in the memory dump.

### Advanced Volatility Commands

Here are some advanced Volatility commands that you can use for more in-depth memory analysis:

- `volatility -f <memory_dump> --profile=<profile> malfind`: This command scans for injected or modified code in the memory dump.
- `volatility -f <memory_dump> --profile=<profile> apihooks`: This command lists API hooks in the memory dump.
- `volatility -f <memory_dump> --profile=<profile> handles`: This command lists open handles in the memory dump.
- `volatility -f <memory_dump> --profile=<profile> privs`: This command lists the privileges for each process in the memory dump.
- `volatility -f <memory_dump> --profile=<profile> getsids`: This command lists the security identifiers (SIDs) for each process in the memory dump.
- `volatility -f <memory_dump> --profile=<profile> printkey -K <registry_key>`: This command displays the values and subkeys of a specific registry key in the memory dump.
- `volatility -f <memory_dump> --profile=<profile> hivelist`: This command lists the registry hives in the memory dump.

### Volatility Plugins

Volatility also provides a wide range of plugins that can be used for specific memory analysis tasks. Some popular plugins include:

- `volatility -f <memory_dump> --profile=<profile> timeliner`: This plugin creates a timeline of events based on timestamps in the memory dump.
- `volatility -f <memory_dump> --profile=<profile> screenshot`: This plugin extracts screenshots from memory dump.
- `volatility -f <memory_dump> --profile=<profile> dumpfiles -Q <file_extension>`: This plugin extracts files with a specific extension from the memory dump.
- `volatility -f <memory_dump> --profile=<profile> iehistory`: This plugin extracts Internet Explorer browsing history from the memory dump.
- `volatility -f <memory_dump> --profile=<profile> chromehistory`: This plugin extracts Google Chrome browsing history from the memory dump.

### Additional Resources

Here are some additional resources that can help you learn more about memory analysis with Volatility:

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Volatility Cheat Sheet](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage)
- [Volatility Training](https://www.volatilityfoundation.org/training)
- [Volatility Community](https://www.volatilityfoundation.org/community)

Happy memory analysis with Volatility!
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}

### Einen Wert erhalten

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
## Volatility Cheat Sheet

Dieses Cheat Sheet enthält eine Liste der häufig verwendeten Volatility-Befehle und deren Verwendung.

### Volatility-Befehle

#### Allgemeine Befehle

- `volatility -f <dumpfile> imageinfo`: Zeigt Informationen über das Speicherabbild an.
- `volatility -f <dumpfile> --profile=<profile> <command>`: Führt einen Befehl unter Verwendung eines bestimmten Profils aus.
- `volatility -f <dumpfile> --profile=<profile> --output-file=<outputfile> <command>`: Speichert die Ausgabe eines Befehls in einer Datei.

#### Prozesse und Threads

- `volatility -f <dumpfile> --profile=<profile> pslist`: Listet alle aktiven Prozesse auf.
- `volatility -f <dumpfile> --profile=<profile> psscan`: Scannt den Speicher nach Prozessen.
- `volatility -f <dumpfile> --profile=<profile> pstree`: Zeigt die Prozesshierarchie an.
- `volatility -f <dumpfile> --profile=<profile> psxview`: Zeigt versteckte Prozesse an.
- `volatility -f <dumpfile> --profile=<profile> threads`: Listet alle Threads auf.

#### Netzwerk

- `volatility -f <dumpfile> --profile=<profile> connections`: Zeigt aktive Netzwerkverbindungen an.
- `volatility -f <dumpfile> --profile=<profile> connscan`: Scannt den Speicher nach Netzwerkverbindungen.
- `volatility -f <dumpfile> --profile=<profile> sockets`: Zeigt offene Sockets an.

#### Dateisystem

- `volatility -f <dumpfile> --profile=<profile> filescan`: Scannt den Speicher nach Dateien.
- `volatility -f <dumpfile> --profile=<profile> mftparser`: Analysiert die Master File Table (MFT).
- `volatility -f <dumpfile> --profile=<profile> mftparser --output=csv --output-file=<outputfile>`: Speichert die MFT-Analyseergebnisse in einer CSV-Datei.
- `volatility -f <dumpfile> --profile=<profile> filescan | grep -i <keyword>`: Sucht nach Dateien, die ein bestimmtes Schlüsselwort enthalten.

#### Registry

- `volatility -f <dumpfile> --profile=<profile> hivelist`: Listet die geladenen Registrierungshives auf.
- `volatility -f <dumpfile> --profile=<profile> printkey -K <key>`: Zeigt den Inhalt eines bestimmten Registrierungsschlüssels an.
- `volatility -f <dumpfile> --profile=<profile> printkey -K <key> --output-file=<outputfile>`: Speichert den Inhalt eines bestimmten Registrierungsschlüssels in einer Datei.

#### Benutzer und Anmeldeinformationen

- `volatility -f <dumpfile> --profile=<profile> hivescan`: Scannt den Speicher nach Registrierungshives.
- `volatility -f <dumpfile> --profile=<profile> hashdump`: Dumpert die Passwort-Hashes.
- `volatility -f <dumpfile> --profile=<profile> hashdump --output-file=<outputfile>`: Speichert die Passwort-Hashes in einer Datei.
- `volatility -f <dumpfile> --profile=<profile> getsids`: Zeigt die SIDs der Benutzer an.
- `volatility -f <dumpfile> --profile=<profile> getsids -u <username>`: Zeigt die SID eines bestimmten Benutzers an.

#### Systeminformationen

- `volatility -f <dumpfile> --profile=<profile> timeliner`: Erstellt eine Zeitleiste der Ereignisse.
- `volatility -f <dumpfile> --profile=<profile> timeliner --output=body --output-file=<outputfile>`: Speichert die Zeitleiste der Ereignisse in einer Datei.
- `volatility -f <dumpfile> --profile=<profile> getservicesids`: Zeigt die SIDs der Dienste an.
- `volatility -f <dumpfile> --profile=<profile> getservicesids -s <servicename>`: Zeigt die SID eines bestimmten Dienstes an.

### Weitere Ressourcen

- [Volatility-Dokumentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility-Plugins](https://github.com/volatilityfoundation/community/tree/master/plugins)
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% endtab %}
{% endtabs %}

### Dump
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## Dateisystem

### Mounten

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

- `volatility -f <memory_dump_file> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump_file> --profile=<profile_name> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile_name> psscan`: This command scans the memory dump for hidden or terminated processes.
- `volatility -f <memory_dump_file> --profile=<profile_name> dlllist -p <process_id>`: This command lists all loaded DLLs for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> cmdline -p <process_id>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump_file> --profile=<profile_name> dumpfiles -Q <file_object_address> -D <output_directory>`: This command dumps a specific file from the memory dump.

### Advanced Volatility Commands

- `volatility -f <memory_dump_file> --profile=<profile_name> malfind`: This command scans the memory dump for injected or modified code.
- `volatility -f <memory_dump_file> --profile=<profile_name> apihooks`: This command lists all API hooks in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile_name> handles -p <process_id>`: This command lists all open handles for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump_file> --profile=<profile_name> connscan`: This command scans the memory dump for TCP connections.
- `volatility -f <memory_dump_file> --profile=<profile_name> timeliner`: This command creates a timeline of events based on timestamps in the memory dump.

### Memory Analysis Plugins

Volatility provides a wide range of plugins for analyzing different aspects of memory dumps. Some of the most commonly used plugins include:

- `pslist`: Lists all running processes.
- `psscan`: Scans for hidden or terminated processes.
- `dlllist`: Lists loaded DLLs for a specific process.
- `cmdline`: Displays command line arguments for a specific process.
- `filescan`: Scans for file objects.
- `dumpfiles`: Dumps specific files from the memory dump.
- `malfind`: Scans for injected or modified code.
- `apihooks`: Lists API hooks.
- `handles`: Lists open handles for a specific process.
- `netscan`: Scans for network connections.
- `connscan`: Scans for TCP connections.
- `timeliner`: Creates a timeline of events based on timestamps.

### Additional Resources

- [Volatility GitHub repository](https://github.com/volatilityfoundation/volatility)
- [Volatility documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility plugins](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{% endtab %}
{% endtabs %}

### Scannen/dumpen

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Volatility Basic Commands

- `volatility -f <memory_dump_file> imageinfo`: This command displays information about the memory dump file, such as the profile and the operating system version.
- `volatility -f <memory_dump_file> --profile=<profile> <command>`: This command runs a specific Volatility command using the specified profile.
- `volatility -f <memory_dump_file> --profile=<profile> --output-file=<output_file> <command>`: This command runs a specific Volatility command and saves the output to a file.

### Volatility Plugins

Volatility provides a wide range of plugins for analyzing memory dumps. Some commonly used plugins include:

- `pslist`: Lists all running processes.
- `pstree`: Displays the process tree.
- `dlllist`: Lists loaded DLLs.
- `handles`: Lists open handles.
- `cmdline`: Displays the command line arguments of processes.
- `filescan`: Scans for file objects in memory.
- `malfind`: Finds hidden and injected code.

To use a plugin, run the following command: `volatility -f <memory_dump_file> --profile=<profile> <plugin_name>`. Replace `<plugin_name>` with the name of the desired plugin.

### Volatility Advanced Techniques

- **Process Memory Analysis**: Analyze the memory of a specific process using the `procdump` plugin.
- **Network Connections Analysis**: Analyze network connections using the `netscan` and `connscan` plugins.
- **Registry Analysis**: Analyze the Windows registry using the `hivelist`, `printkey`, and `hashdump` plugins.
- **File System Analysis**: Analyze the file system using the `mftparser`, `usnjrnl`, and `filescan` plugins.
- **Malware Analysis**: Analyze malware using the `malfind`, `yarascan`, and `virustotal` plugins.

### Volatility Resources

- Official Volatility GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
- Volatility documentation: [https://github.com/volatilityfoundation/volatility/wiki](https://github.com/volatilityfoundation/volatility/wiki)
- Volatility plugins repository: [https://github.com/volatilityfoundation/community](https://github.com/volatilityfoundation/community)

### Volatility Cheat Sheet

#### Volatility Installation

Um Volatility zu installieren, befolgen Sie diese Schritte:

1. Laden Sie die neueste Version von Volatility aus dem offiziellen GitHub-Repository herunter: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Entpacken Sie die heruntergeladene Datei in ein Verzeichnis Ihrer Wahl.
3. Öffnen Sie ein Terminal und navigieren Sie zum Verzeichnis, in dem Sie Volatility entpackt haben.
4. Führen Sie den Befehl `python setup.py install` aus, um Volatility zu installieren.

#### Grundlegende Volatility-Befehle

- `volatility -f <memory_dump_file> imageinfo`: Dieser Befehl zeigt Informationen über die Memory-Dump-Datei an, wie das Profil und die Betriebssystemversion.
- `volatility -f <memory_dump_file> --profile=<profile> <command>`: Dieser Befehl führt einen bestimmten Volatility-Befehl mit dem angegebenen Profil aus.
- `volatility -f <memory_dump_file> --profile=<profile> --output-file=<output_file> <command>`: Dieser Befehl führt einen bestimmten Volatility-Befehl aus und speichert die Ausgabe in einer Datei.

#### Volatility-Plugins

Volatility bietet eine Vielzahl von Plugins zur Analyse von Memory-Dumps. Einige häufig verwendete Plugins sind:

- `pslist`: Listet alle laufenden Prozesse auf.
- `pstree`: Zeigt den Prozessbaum an.
- `dlllist`: Listet geladene DLLs auf.
- `handles`: Listet offene Handles auf.
- `cmdline`: Zeigt die Befehlszeilenargumente von Prozessen an.
- `filescan`: Sucht nach Dateiobjekten im Speicher.
- `malfind`: Findet versteckten und injizierten Code.

Um ein Plugin zu verwenden, führen Sie den folgenden Befehl aus: `volatility -f <memory_dump_file> --profile=<profile> <plugin_name>`. Ersetzen Sie `<plugin_name>` durch den Namen des gewünschten Plugins.

#### Fortgeschrittene Volatility-Techniken

- **Analyse des Prozessspeichers**: Analysieren Sie den Speicher eines bestimmten Prozesses mithilfe des `procdump`-Plugins.
- **Analyse von Netzwerkverbindungen**: Analysieren Sie Netzwerkverbindungen mithilfe der Plugins `netscan` und `connscan`.
- **Registry-Analyse**: Analysieren Sie die Windows-Registry mithilfe der Plugins `hivelist`, `printkey` und `hashdump`.
- **Dateisystemanalyse**: Analysieren Sie das Dateisystem mithilfe der Plugins `mftparser`, `usnjrnl` und `filescan`.
- **Malware-Analyse**: Analysieren Sie Malware mithilfe der Plugins `malfind`, `yarascan` und `virustotal`.

#### Volatility-Ressourcen

- Offizielles Volatility-GitHub-Repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
- Volatility-Dokumentation: [https://github.com/volatilityfoundation/volatility/wiki](https://github.com/volatilityfoundation/volatility/wiki)
- Volatility-Plugins-Repository: [https://github.com/volatilityfoundation/community](https://github.com/volatilityfoundation/community)
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{% endtab %}
{% endtabs %}

### Masterdateitabelle

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. It includes commands and techniques for analyzing memory dumps to extract valuable information during forensic investigations.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required dependencies using pip: `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository: `git clone https://github.com/volatilityfoundation/volatility.git`.
4. Navigate to the Volatility directory: `cd volatility`.
5. Run Volatility using the command `python vol.py`.

### Basic Usage

To analyze a memory dump with Volatility, use the following command:

```
python vol.py -f <memory_dump> <plugin_name>
```

Replace `<memory_dump>` with the path to the memory dump file and `<plugin_name>` with the name of the plugin you want to use for analysis.

### Common Plugins

Here are some commonly used plugins in Volatility:

- `pslist`: Lists running processes.
- `pstree`: Displays a process tree.
- `dlllist`: Lists loaded DLLs.
- `handles`: Lists open handles.
- `cmdline`: Displays command-line arguments.
- `filescan`: Scans for file objects in memory.
- `malfind`: Finds hidden and injected code.
- `svcscan`: Lists Windows services.
- `connections`: Lists network connections.
- `netscan`: Scans for network artifacts.

### Advanced Techniques

Volatility also provides advanced techniques for memory analysis, such as:

- **Process Memory Analysis**: Analyzing the memory of a specific process.
- **Kernel Memory Analysis**: Analyzing the kernel memory.
- **Network Memory Analysis**: Analyzing network-related artifacts in memory.
- **Malware Analysis**: Analyzing memory for signs of malware.

### Additional Resources

For more information on using Volatility and memory forensics, refer to the following resources:

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [The Art of Memory Forensics](https://www.amazon.com/Art-Memory-Forensics-Detecting-Malware/dp/1118825098)

### Conclusion

This cheat sheet provides a starting point for using Volatility in memory forensics. By leveraging the power of Volatility and its plugins, you can extract valuable information from memory dumps to aid in forensic investigations.
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

Das **NTFS-Dateisystem** verwendet eine wichtige Komponente namens _Master File Table_ (MFT). Diese Tabelle enthält mindestens einen Eintrag für jede Datei auf einem Volume, einschließlich der MFT selbst. Wichtige Details zu jeder Datei, wie **Größe, Zeitstempel, Berechtigungen und tatsächliche Daten**, sind in den MFT-Einträgen oder in Bereichen außerhalb des MFT, aber von diesen Einträgen referenziert, enthalten. Weitere Details finden Sie in der [offiziellen Dokumentation](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table).

### SSL-Schlüssel/Zertifikate

{% tabs %}
{% tab title="vol3" %}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{% tab title="vol2" %}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
## Malware

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{% endtab %}
{% endtabs %}

### Scannen mit yara

Verwenden Sie dieses Skript, um alle yara-Malware-Regeln von GitHub herunterzuladen und zusammenzuführen: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
Erstellen Sie das Verzeichnis _**rules**_ und führen Sie es aus. Dadurch wird eine Datei namens _**malware\_rules.yar**_ erstellt, die alle yara-Regeln für Malware enthält.
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{% tab title="vol2" %}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{% endtab %}
{% endtabs %}

## MISC

### Externe Plugins

Wenn Sie externe Plugins verwenden möchten, stellen Sie sicher, dass die Ordner, die mit den Plugins zusammenhängen, der erste verwendete Parameter sind.
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

- `volatility -f <memory_dump_file> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump_file> --profile=<profile_name> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile_name> psscan`: This command scans the memory dump for hidden or terminated processes.
- `volatility -f <memory_dump_file> --profile=<profile_name> dlllist -p <process_id>`: This command lists all loaded DLLs for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> cmdline -p <process_id>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump_file> --profile=<profile_name> dumpfiles -Q <file_object_address> -D <output_directory>`: This command dumps a specific file from the memory dump.

### Advanced Volatility Commands

- `volatility -f <memory_dump_file> --profile=<profile_name> malfind`: This command scans the memory dump for injected or modified code.
- `volatility -f <memory_dump_file> --profile=<profile_name> apihooks`: This command lists all API hooks in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile_name> handles -p <process_id>`: This command lists all open handles for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump_file> --profile=<profile_name> connscan`: This command scans the memory dump for TCP connections.
- `volatility -f <memory_dump_file> --profile=<profile_name> timeliner`: This command creates a timeline of events based on timestamps in the memory dump.

### Memory Analysis Plugins

Volatility provides a wide range of plugins for analyzing different aspects of memory dumps. Some of the most commonly used plugins include:

- `pslist`: Lists all running processes.
- `psscan`: Scans for hidden or terminated processes.
- `dlllist`: Lists loaded DLLs for a specific process.
- `cmdline`: Displays command line arguments for a specific process.
- `filescan`: Scans for file objects.
- `dumpfiles`: Dumps specific files from the memory dump.
- `malfind`: Scans for injected or modified code.
- `apihooks`: Lists API hooks.
- `handles`: Lists open handles for a specific process.
- `netscan`: Scans for network connections.
- `connscan`: Scans for TCP connections.
- `timeliner`: Creates a timeline of events based on timestamps.

### Additional Resources

- [Volatility GitHub repository](https://github.com/volatilityfoundation/volatility)
- [Volatility documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility plugins](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

Laden Sie es von [https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns) herunter
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexe

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{% tab title="vol2" %}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{% endtab %}
{% endtabs %}

### Symbolische Links

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

- `volatility -f <memory_dump_file> imageinfo`: This command displays information about the memory dump file, such as the profile and the operating system version.
- `volatility -f <memory_dump_file> --profile=<profile> <command>`: This command runs a specific Volatility command using the specified profile.
- `volatility -f <memory_dump_file> --profile=<profile> --output-file=<output_file> <command>`: This command runs a specific Volatility command and saves the output to a file.

### Memory Analysis

- `volatility -f <memory_dump_file> --profile=<profile> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> psscan`: This command scans for hidden or terminated processes in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> pstree`: This command displays the process tree in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> dlllist -p <pid>`: This command lists the loaded DLLs for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile> handles -p <pid>`: This command lists the open handles for a specific process.

### Network Analysis

- `volatility -f <memory_dump_file> --profile=<profile> connections`: This command lists the network connections in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> connscan`: This command scans for hidden or terminated network connections in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> netscan`: This command scans for network artifacts in the memory dump.

### File Analysis

- `volatility -f <memory_dump_file> --profile=<profile> filescan`: This command scans for file objects in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> dumpfiles -Q <address_range>`: This command dumps files from the memory dump based on the specified address range.

### Registry Analysis

- `volatility -f <memory_dump_file> --profile=<profile> hivelist`: This command lists the registry hives in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> printkey -K <key_path>`: This command prints the values and subkeys of a specific registry key.

### Malware Analysis

- `volatility -f <memory_dump_file> --profile=<profile> malfind`: This command scans for injected or hidden code in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile> malprocfind`: This command scans for processes associated with known malware in the memory dump.

### Plugin Usage

- `volatility -f <memory_dump_file> --profile=<profile> --plugins=<plugin_directory> <plugin_name>`: This command runs a specific Volatility plugin using the specified profile and plugin directory.

### Additional Resources

- Volatility GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
- Volatility documentation: [https://github.com/volatilityfoundation/volatility/wiki](https://github.com/volatilityfoundation/volatility/wiki)

{% endtab %}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

Es ist möglich, **die Bash-History aus dem Speicher auszulesen**. Sie könnten auch die Datei _.bash\_history_ dumpen, aber wenn sie deaktiviert wurde, werden Sie froh sein, dass Sie dieses Volatility-Modul verwenden können.

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp linux.bash.Bash
```
## Volatility Cheat Sheet

Dieses Cheat Sheet enthält eine Liste der häufig verwendeten Volatility-Befehle und deren Verwendung.

### Volatility-Befehle

#### Allgemeine Befehle

- `volatility -f <dumpfile> imageinfo`: Zeigt Informationen über das Speicherabbild an.
- `volatility -f <dumpfile> --profile=<profile> <command>`: Führt einen Befehl unter Verwendung eines bestimmten Profils aus.
- `volatility -f <dumpfile> --profile=<profile> --output-file=<outputfile> <command>`: Speichert die Ausgabe eines Befehls in einer Datei.

#### Prozesse und Threads

- `volatility -f <dumpfile> --profile=<profile> pslist`: Listet alle aktiven Prozesse auf.
- `volatility -f <dumpfile> --profile=<profile> psscan`: Scannt den Speicher nach Prozessen.
- `volatility -f <dumpfile> --profile=<profile> pstree`: Zeigt die Prozesshierarchie an.
- `volatility -f <dumpfile> --profile=<profile> psxview`: Zeigt versteckte Prozesse an.
- `volatility -f <dumpfile> --profile=<profile> threads`: Listet alle Threads auf.

#### Netzwerk

- `volatility -f <dumpfile> --profile=<profile> connections`: Zeigt aktive Netzwerkverbindungen an.
- `volatility -f <dumpfile> --profile=<profile> connscan`: Scannt den Speicher nach Netzwerkverbindungen.
- `volatility -f <dumpfile> --profile=<profile> sockets`: Zeigt offene Sockets an.

#### Dateisystem

- `volatility -f <dumpfile> --profile=<profile> filescan`: Scannt den Speicher nach Dateien.
- `volatility -f <dumpfile> --profile=<profile> mftparser`: Analysiert die Master File Table (MFT).
- `volatility -f <dumpfile> --profile=<profile> mftparser --output=csv --output-file=<outputfile>`: Speichert die MFT-Analyseergebnisse in einer CSV-Datei.
- `volatility -f <dumpfile> --profile=<profile> filescan | grep -i <keyword>`: Sucht nach Dateien, die ein bestimmtes Schlüsselwort enthalten.

#### Registry

- `volatility -f <dumpfile> --profile=<profile> hivelist`: Listet die geladenen Registrierungshives auf.
- `volatility -f <dumpfile> --profile=<profile> printkey -K <key>`: Zeigt den Inhalt eines bestimmten Registrierungsschlüssels an.
- `volatility -f <dumpfile> --profile=<profile> printkey -K <key> --output-file=<outputfile>`: Speichert den Inhalt eines bestimmten Registrierungsschlüssels in einer Datei.

#### Benutzer und Anmeldeinformationen

- `volatility -f <dumpfile> --profile=<profile> hivescan`: Scannt den Speicher nach Registrierungshives.
- `volatility -f <dumpfile> --profile=<profile> hashdump`: Dumpert die Passwort-Hashes.
- `volatility -f <dumpfile> --profile=<profile> hashdump --output-file=<outputfile>`: Speichert die Passwort-Hashes in einer Datei.
- `volatility -f <dumpfile> --profile=<profile> getsids`: Zeigt die Sicherheits-IDs (SIDs) der Benutzer an.

#### DLLs und Treiber

- `volatility -f <dumpfile> --profile=<profile> dlllist`: Listet alle geladenen DLLs auf.
- `volatility -f <dumpfile> --profile=<profile> driverirp`: Zeigt Informationen über die Treiber-IRPs an.

#### Systeminformationen

- `volatility -f <dumpfile> --profile=<profile> getservicesids`: Zeigt die Sicherheits-IDs (SIDs) der Dienste an.
- `volatility -f <dumpfile> --profile=<profile> getsids`: Zeigt die Sicherheits-IDs (SIDs) der Benutzer an.
- `volatility -f <dumpfile> --profile=<profile> getsids -U`: Zeigt die Sicherheits-IDs (SIDs) der Benutzer und Gruppen an.
- `volatility -f <dumpfile> --profile=<profile> getsids -G`: Zeigt die Sicherheits-IDs (SIDs) der Gruppen an.

### Weitere Ressourcen

- [Volatility-Dokumentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility-Plugins](https://github.com/volatilityfoundation/community/tree/master/plugins)
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{% endtab %}
{% endtabs %}

### Zeitachse

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

- `volatility -f <memory_dump_file> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump_file> --profile=<profile_name> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile_name> psscan`: This command scans the memory dump for hidden or terminated processes.
- `volatility -f <memory_dump_file> --profile=<profile_name> dlllist -p <process_id>`: This command lists all loaded DLLs for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> cmdline -p <process_id>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump_file> --profile=<profile_name> dumpfiles -Q <file_object_address> -D <output_directory>`: This command dumps a specific file from the memory dump.

### Advanced Volatility Commands

- `volatility -f <memory_dump_file> --profile=<profile_name> malfind`: This command scans the memory dump for injected or modified code.
- `volatility -f <memory_dump_file> --profile=<profile_name> apihooks`: This command lists all API hooks in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile_name> handles -p <process_id>`: This command lists all open handles for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump_file> --profile=<profile_name> connscan`: This command scans the memory dump for TCP and UDP connections.
- `volatility -f <memory_dump_file> --profile=<profile_name> timeliner`: This command creates a timeline of events based on timestamps in the memory dump.

### Memory Analysis Plugins

Volatility provides a wide range of plugins for analyzing different aspects of memory dumps. Some of the most commonly used plugins include:

- `pslist`: Lists all running processes.
- `psscan`: Scans for hidden or terminated processes.
- `dlllist`: Lists loaded DLLs for a specific process.
- `cmdline`: Displays command line arguments for a specific process.
- `filescan`: Scans for file objects.
- `dumpfiles`: Dumps specific files from the memory dump.
- `malfind`: Scans for injected or modified code.
- `apihooks`: Lists API hooks.
- `handles`: Lists open handles for a specific process.
- `netscan`: Scans for network connections.
- `connscan`: Scans for TCP and UDP connections.
- `timeliner`: Creates a timeline of events based on timestamps.

### Additional Resources

- [Volatility GitHub repository](https://github.com/volatilityfoundation/volatility)
- [Volatility documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility plugins](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### Treiber

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
## Volatility Cheat Sheet

### Volatility Installation

To install Volatility, follow these steps:

1. Download the latest version of Volatility from the official GitHub repository: [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)
2. Extract the downloaded file to a directory of your choice.
3. Open a terminal and navigate to the directory where you extracted Volatility.
4. Run the command `python setup.py install` to install Volatility.

### Basic Volatility Commands

- `volatility -f <memory_dump_file> imageinfo`: This command displays information about the memory dump file, such as the operating system version and architecture.
- `volatility -f <memory_dump_file> --profile=<profile_name> pslist`: This command lists all running processes in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile_name> psscan`: This command scans the memory dump for hidden or terminated processes.
- `volatility -f <memory_dump_file> --profile=<profile_name> dlllist -p <process_id>`: This command lists all loaded DLLs for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> cmdline -p <process_id>`: This command displays the command line arguments for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> filescan`: This command scans the memory dump for file objects.
- `volatility -f <memory_dump_file> --profile=<profile_name> dumpfiles -Q <file_object_address> -D <output_directory>`: This command dumps a specific file from the memory dump.

### Advanced Volatility Commands

- `volatility -f <memory_dump_file> --profile=<profile_name> malfind`: This command scans the memory dump for injected or modified code.
- `volatility -f <memory_dump_file> --profile=<profile_name> apihooks`: This command lists all API hooks in the memory dump.
- `volatility -f <memory_dump_file> --profile=<profile_name> handles -p <process_id>`: This command lists all open handles for a specific process.
- `volatility -f <memory_dump_file> --profile=<profile_name> netscan`: This command scans the memory dump for network connections.
- `volatility -f <memory_dump_file> --profile=<profile_name> connscan`: This command scans the memory dump for TCP and UDP connections.
- `volatility -f <memory_dump_file> --profile=<profile_name> timeliner`: This command creates a timeline of events based on timestamps in the memory dump.

### Additional Resources

- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility Plugins](https://github.com/volatilityfoundation/community)

### References

- [Volatility Cheat Sheet](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage#cheat-sheet)
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### Zwischenablage abrufen
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### IE-Verlauf abrufen

Um den Internet Explorer-Verlauf abzurufen, können Sie den folgenden Befehl verwenden:

```bash
volatility -f <memory_dump> iehistory
```

Ersetzen Sie `<memory_dump>` durch den Pfad zur Speicherabbilddatei, die Sie analysieren möchten.

Dieser Befehl extrahiert den Verlauf des Internet Explorers aus dem Speicherabbild und zeigt Informationen wie besuchte URLs, Titel der besuchten Seiten, Zeitstempel und andere relevante Daten an.
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### Notizbuchtext abrufen

```
volatility -f <memory_dump> notepad
```

Dieser Befehl extrahiert den Text, der in der Anwendung Notepad im Speicherdump gespeichert ist.
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### Screenshot
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### Master Boot Record (MBR)

Der Master Boot Record (MBR) ist ein spezieller Bereich auf einer Festplatte, der Informationen über die Partitionierung und das Starten des Betriebssystems enthält. Er befindet sich im ersten Sektor der Festplatte und besteht aus einem Bootloader und einer Partitionstabelle.

#### Analyse des MBR

Um den MBR zu analysieren, können Sie die folgenden Volatility-Befehle verwenden:

- `mbrparser`: Dieser Befehl analysiert den MBR und gibt Informationen über die Partitionstabelle und den Bootloader aus.

Beispiel:

```
volatility -f memory_dump.raw mbrparser
```

#### Verdächtige Aktivitäten im MBR

Einige verdächtige Aktivitäten im MBR können auf eine Malware-Infektion oder eine Manipulation hinweisen. Hier sind einige Anzeichen für verdächtige Aktivitäten:

- Änderungen in der Partitionstabelle: Wenn sich die Partitionstabelle plötzlich ändert oder unbekannte Partitionen hinzugefügt werden, kann dies auf eine Malware-Infektion hinweisen.
- Modifizierter Bootloader: Wenn der Bootloader im MBR verändert wurde, kann dies darauf hindeuten, dass ein Angreifer versucht hat, das Betriebssystem zu manipulieren oder eine Hintertür einzurichten.
- Bootkit-Infektion: Ein Bootkit ist eine Art von Malware, die den Bootloader infiziert und es Angreifern ermöglicht, Kontrolle über das System zu erlangen. Wenn verdächtige Aktivitäten im MBR festgestellt werden, sollten Sie nach Anzeichen für eine Bootkit-Infektion suchen.

#### Gegenmaßnahmen

Um den MBR vor Angriffen zu schützen, können Sie die folgenden Maßnahmen ergreifen:

- Aktualisieren Sie Ihr Betriebssystem und Ihre Sicherheitssoftware regelmäßig, um bekannte Schwachstellen zu beheben.
- Verwenden Sie eine zuverlässige Antivirensoftware, um Malware-Infektionen zu erkennen und zu entfernen.
- Seien Sie vorsichtig beim Herunterladen und Öffnen von Dateien aus unsicheren Quellen.
- Überprüfen Sie regelmäßig den MBR auf verdächtige Aktivitäten und führen Sie gegebenenfalls eine forensische Analyse durch.

#### Fazit

Die Analyse des MBR kann wichtige Informationen über die Partitionierung und das Starten des Betriebssystems liefern. Durch die Überwachung und Untersuchung verdächtiger Aktivitäten im MBR können Sie potenzielle Bedrohungen erkennen und geeignete Gegenmaßnahmen ergreifen, um Ihr System zu schützen.
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
Der **Master Boot Record (MBR)** spielt eine entscheidende Rolle bei der Verwaltung der logischen Partitionen eines Speichermediums, die mit unterschiedlichen [Dateisystemen](https://de.wikipedia.org/wiki/Dateisystem) strukturiert sind. Er enthält nicht nur Informationen zur Partitionslayout, sondern enthält auch ausführbaren Code, der als Bootloader fungiert. Dieser Bootloader initiiert entweder direkt den OS-Zweistufen-Ladevorgang (siehe [Zweistufiger Bootloader](https://de.wikipedia.org/wiki/Zweistufiger_Bootloader)) oder arbeitet in Harmonie mit dem [Volume Boot Record](https://de.wikipedia.org/wiki/Volume_boot_record) (VBR) jeder Partition. Für vertiefte Kenntnisse siehe die [MBR Wikipedia-Seite](https://de.wikipedia.org/wiki/Master_boot_record).

## Referenzen
* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
​* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **der Mission, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsprofis in jeder Disziplin.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repos senden.

</details>
