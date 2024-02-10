# macOS Netzwerkdienste und Protokolle

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Remote-Zugriffsdienste

Dies sind die gängigen macOS-Dienste, um auf sie remote zuzugreifen.\
Sie können diese Dienste in `Systemeinstellungen` --> `Freigabe` aktivieren/deaktivieren.

* **VNC**, bekannt als "Bildschirmfreigabe" (tcp:5900)
* **SSH**, genannt "Remote-Anmeldung" (tcp:22)
* **Apple Remote Desktop** (ARD) oder "Remote-Verwaltung" (tcp:3283, tcp:5900)
* **AppleEvent**, bekannt als "Remote Apple Event" (tcp:3031)

Überprüfen Sie, ob einer dieser Dienste aktiviert ist, indem Sie Folgendes ausführen:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) ist eine verbesserte Version von [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing), die speziell für macOS entwickelt wurde und zusätzliche Funktionen bietet. Eine bemerkenswerte Schwachstelle in ARD ist die Authentifizierungsmethode für das Steuerungsbildschirm-Passwort, die nur die ersten 8 Zeichen des Passworts verwendet und daher anfällig für [Brute-Force-Angriffe](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) mit Tools wie Hydra oder [GoRedShell](https://github.com/ahhh/GoRedShell/) ist, da standardmäßig keine Rate-Limits vorhanden sind.

Verwundbare Instanzen können mit dem `vnc-info`-Skript von **nmap** identifiziert werden. Dienste, die `VNC Authentication (2)` unterstützen, sind aufgrund der 8-Zeichen-Passwortabschneidung besonders anfällig für Brute-Force-Angriffe.

Um ARD für verschiedene administrative Aufgaben wie Privileg-Eskalation, GUI-Zugriff oder Benutzerüberwachung zu aktivieren, verwenden Sie den folgenden Befehl:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD bietet vielseitige Steuerungsebenen, einschließlich Beobachtung, gemeinsamer Steuerung und vollständiger Steuerung, wobei Sitzungen auch nach Änderung des Benutzerpassworts bestehen bleiben. Es ermöglicht das direkte Senden von Unix-Befehlen und deren Ausführung als Root für administrative Benutzer. Die Planung von Aufgaben und die Remote-Spotlight-Suche sind bemerkenswerte Funktionen, die die Suche nach sensiblen Dateien über mehrere Maschinen hinweg erleichtern.

## Bonjour-Protokoll

Bonjour, eine von Apple entwickelte Technologie, ermöglicht es **Geräten im selben Netzwerk, die angebotenen Dienste der anderen Geräte zu erkennen**. Auch bekannt als Rendezvous, **Zero Configuration** oder Zeroconf, ermöglicht es einem Gerät, einem TCP/IP-Netzwerk beizutreten, **automatisch eine IP-Adresse zu wählen** und seine Dienste an andere Netzwerkgeräte zu senden.

Zero Configuration Networking, bereitgestellt von Bonjour, stellt sicher, dass Geräte Folgendes können:
* **Automatisch eine IP-Adresse erhalten**, auch in Abwesenheit eines DHCP-Servers.
* **Namens-zu-Adress-Übersetzung** durchführen, ohne einen DNS-Server zu benötigen.
* **Dienste** im Netzwerk **entdecken**.

Geräte, die Bonjour verwenden, weisen sich selbst eine **IP-Adresse aus dem Bereich 169.254/16** zu und überprüfen deren Eindeutigkeit im Netzwerk. Macs verwalten einen Routing-Tabelleneintrag für dieses Subnetz, der mit `netstat -rn | grep 169` überprüft werden kann.

Für DNS verwendet Bonjour das **Multicast DNS (mDNS)-Protokoll**. mDNS arbeitet über **Port 5353/UDP** und verwendet **Standard-DNS-Abfragen**, zielt jedoch auf die **Multicast-Adresse 224.0.0.251** ab. Auf diese Weise können alle lauschenden Geräte im Netzwerk die Abfragen empfangen und darauf antworten, um ihre Einträge zu aktualisieren.

Beim Beitritt zum Netzwerk wählt jedes Gerät selbst einen Namen, der in der Regel mit **.local** endet und vom Hostnamen oder zufällig generiert sein kann.

Die Dienstsuche im Netzwerk wird durch **DNS Service Discovery (DNS-SD)** erleichtert. Mit dem Format von DNS SRV-Einträgen nutzt DNS-SD **DNS PTR-Einträge**, um die Auflistung mehrerer Dienste zu ermöglichen. Ein Client, der einen bestimmten Dienst sucht, fordert einen PTR-Eintrag für `<Service>.<Domain>` an und erhält eine Liste von PTR-Einträgen im Format `<Instance>.<Service>.<Domain>`, wenn der Dienst von mehreren Hosts verfügbar ist.

Das Dienstprogramm `dns-sd` kann zur **Entdeckung und Werbung von Netzwerkdiensten** verwendet werden. Hier sind einige Beispiele für dessen Verwendung:

### Suche nach SSH-Diensten

Um nach SSH-Diensten im Netzwerk zu suchen, wird der folgende Befehl verwendet:
```bash
dns-sd -B _ssh._tcp
```
Dieser Befehl startet das Durchsuchen von _ssh._tcp-Diensten und gibt Details wie Zeitstempel, Flags, Schnittstelle, Domäne, Diensttyp und Instanzname aus.

### Werbung für einen HTTP-Dienst

Um einen HTTP-Dienst zu bewerben, können Sie Folgendes verwenden:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Dieser Befehl registriert einen HTTP-Dienst namens "Index" auf Port 80 mit einem Pfad von `/index.html`.

Um dann nach HTTP-Diensten im Netzwerk zu suchen:
```bash
dns-sd -B _http._tcp
```
Wenn ein Dienst startet, gibt er seine Verfügbarkeit an alle Geräte im Subnetz bekannt, indem er seine Präsenz multicastet. Geräte, die an diesen Diensten interessiert sind, müssen keine Anfragen senden, sondern einfach auf diese Ankündigungen hören.

Für eine benutzerfreundlichere Oberfläche kann die App **Discovery - DNS-SD Browser**, die im Apple App Store erhältlich ist, die auf Ihrem lokalen Netzwerk angebotenen Dienste visualisieren.

Alternativ können benutzerdefinierte Skripte geschrieben werden, um Dienste mithilfe der `python-zeroconf`-Bibliothek zu durchsuchen und zu entdecken. Das [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf)-Skript zeigt das Erstellen eines Dienstbrowsers für `_http._tcp.local.`-Dienste und das Drucken von hinzugefügten oder entfernten Diensten an:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Deaktivieren von Bonjour
Wenn es Bedenken hinsichtlich der Sicherheit oder aus anderen Gründen gibt, Bonjour zu deaktivieren, kann dies mit dem folgenden Befehl erfolgen:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Referenzen

* [**Das Mac Hacker-Handbuch**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
