# BloodHound & Andere AD Enum Tools

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks-Repository](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud-Repository](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) stammt aus der Sysinternal Suite:

> Ein fortschrittlicher Active Directory (AD) Viewer und Editor. Sie können AD Explorer verwenden, um eine AD-Datenbank einfach zu durchsuchen, bevorzugte Standorte festzulegen, Objekteigenschaften und Attribute ohne Öffnen von Dialogfeldern anzuzeigen, Berechtigungen zu bearbeiten, das Schema eines Objekts anzuzeigen und komplexe Suchvorgänge auszuführen, die Sie speichern und erneut ausführen können.

### Snapshots

AD Explorer kann Snapshots eines AD erstellen, sodass Sie es offline überprüfen können.\
Es kann verwendet werden, um Offline-Schwachstellen zu entdecken oder verschiedene Zustände der AD-Datenbank im Laufe der Zeit zu vergleichen.

Sie benötigen den Benutzernamen, das Passwort und die Richtung, um eine Verbindung herzustellen (jeder AD-Benutzer ist erforderlich).

Um einen Snapshot von AD zu erstellen, gehen Sie zu `File` --> `Create Snapshot` und geben Sie einen Namen für den Snapshot ein.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) ist ein Tool, das verschiedene Artefakte aus einer AD-Umgebung extrahiert und kombiniert. Die Informationen können in einem **speziell formatierten** Microsoft Excel **Bericht** präsentiert werden, der Zusammenfassungsansichten mit Metriken enthält, um die Analyse zu erleichtern und ein ganzheitliches Bild des aktuellen Zustands der Ziel-AD-Umgebung zu liefern.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

Von [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound ist eine Single-Page-Javascript-Webanwendung, die auf [Linkurious](http://linkurio.us/) aufbaut, mit [Electron](http://electron.atom.io/) kompiliert ist und eine von einem C#-Datenkollektor gespeiste Neo4j-Datenbank verwendet.

BloodHound verwendet Graphentheorie, um die versteckten und oft unbeabsichtigten Beziehungen innerhalb einer Active Directory- oder Azure-Umgebung aufzudecken. Angreifer können BloodHound verwenden, um hochkomplexe Angriffspfade zu identifizieren, die sonst nur schwer zu erkennen wären. Verteidiger können BloodHound verwenden, um diese Angriffspfade zu identifizieren und zu beseitigen. Sowohl Blue- als auch Red-Teams können BloodHound verwenden, um ein tieferes Verständnis für Privilegienbeziehungen in einer Active Directory- oder Azure-Umgebung zu erlangen.

Also ist [Bloodhound](https://github.com/BloodHoundAD/BloodHound) ein erstaunliches Tool, das automatisch eine Domäne aufzählt, alle Informationen speichert, mögliche Privileg-Eskalationspfade findet und alle Informationen mithilfe von Graphen anzeigt.

Bloodhound besteht aus 2 Hauptteilen: **Ingestors** und der **Visualisierungsanwendung**.

Die **Ingestors** werden verwendet, um die Domäne aufzulisten und alle Informationen in einem Format zu extrahieren, das von der Visualisierungsanwendung verstanden wird.

Die **Visualisierungsanwendung verwendet Neo4j**, um anzuzeigen, wie alle Informationen miteinander zusammenhängen und verschiedene Möglichkeiten zur Eskalation von Privilegien in der Domäne anzuzeigen.

### Installation
Nach der Erstellung von BloodHound CE wurde das gesamte Projekt für eine einfache Verwendung mit Docker aktualisiert. Der einfachste Weg, um loszulegen, besteht darin, die vorkonfigurierte Docker Compose-Konfiguration zu verwenden.

1. Installieren Sie Docker Compose. Dies sollte mit der [Docker Desktop](https://www.docker.com/products/docker-desktop/) Installation enthalten sein.
2. Führen Sie aus:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Suchen Sie das zufällig generierte Passwort in der Terminalausgabe von Docker Compose.
4. Öffnen Sie einen Browser und navigieren Sie zu http://localhost:8080/ui/login. Melden Sie sich mit dem Benutzernamen "admin" und dem zufällig generierten Passwort aus den Protokollen an.

Danach müssen Sie das zufällig generierte Passwort ändern und haben die neue Benutzeroberfläche bereit, von der aus Sie die Ingestors direkt herunterladen können.

### SharpHound

Es gibt mehrere Optionen, aber wenn Sie SharpHound von einem PC ausführen möchten, der der Domäne beigetreten ist, und dabei Ihren aktuellen Benutzer verwenden und alle verfügbaren Informationen extrahieren möchten, können Sie Folgendes tun:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Weitere Informationen zur **CollectionMethod** und zur Schleifensitzung finden Sie [hier](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Wenn Sie SharpHound mit verschiedenen Anmeldeinformationen ausführen möchten, können Sie eine CMD-Netonly-Sitzung erstellen und SharpHound von dort ausführen:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Erfahren Sie mehr über Bloodhound auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) ist ein Tool zum Auffinden von **Schwachstellen** in Active Directory, die mit **Gruppenrichtlinien** verbunden sind. \
Sie müssen **group3r ausführen** von einem Host innerhalb der Domäne unter Verwendung **eines beliebigen Domänenbenutzers**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **bewertet den Sicherheitszustand einer AD-Umgebung** und erstellt einen übersichtlichen **Bericht** mit Diagrammen.

Um es auszuführen, können Sie die ausführbare Datei `PingCastle.exe` starten und es wird eine **interaktive Sitzung** gestartet, die ein Menü mit Optionen anzeigt. Die Standardoption, die verwendet werden sollte, ist **`healthcheck`**, mit der eine grundlegende **Übersicht** der **Domäne** erstellt wird und **Fehlkonfigurationen** und **Schwachstellen** gefunden werden.&#x20;

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks-Repository](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud-Repository](https://github.com/carlospolop/hacktricks-cloud) senden**.

</details>
