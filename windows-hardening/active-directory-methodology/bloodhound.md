# BloodHound & Andere AD Enum Tools

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) ist aus der Sysinternal Suite:

> Ein fortgeschrittener Active Directory (AD) Viewer und Editor. Du kannst AD Explorer verwenden, um eine AD-Datenbank einfach zu navigieren, bevorzugte Standorte zu definieren, Objektattribute und -eigenschaften ohne das Öffnen von Dialogfeldern anzuzeigen, Berechtigungen zu bearbeiten, das Schema eines Objekts anzuzeigen und komplexe Suchen auszuführen, die du speichern und erneut ausführen kannst.

### Snapshots

AD Explorer kann Snapshots eines AD erstellen, sodass du es offline überprüfen kannst.\
Es kann verwendet werden, um Schwachstellen offline zu entdecken oder um verschiedene Zustände der AD-Datenbank über die Zeit zu vergleichen.

Du benötigst den Benutzernamen, das Passwort und die Richtung, um eine Verbindung herzustellen (jeder AD-Benutzer ist erforderlich).

Um einen Snapshot von AD zu erstellen, gehe zu `Datei` --> `Snapshot erstellen` und gib einen Namen für den Snapshot ein.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) ist ein Tool, das verschiedene Artefakte aus einer AD-Umgebung extrahiert und kombiniert. Die Informationen können in einem **speziell formatierten** Microsoft Excel **Bericht** präsentiert werden, der Zusammenfassungsansichten mit Metriken enthält, um die Analyse zu erleichtern und ein ganzheitliches Bild des aktuellen Zustands der Ziel-AD-Umgebung zu bieten.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

Von [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound ist eine einseitige Javascript-Webanwendung, die auf [Linkurious](http://linkurio.us/) basiert, mit [Electron](http://electron.atom.io/) kompiliert wurde und eine [Neo4j](https://neo4j.com/) Datenbank verwendet, die von einem C# Datenkollektor gespeist wird.

BloodHound verwendet Graphentheorie, um die verborgenen und oft unbeabsichtigten Beziehungen innerhalb einer Active Directory- oder Azure-Umgebung aufzudecken. Angreifer können BloodHound verwenden, um hochkomplexe Angriffswege leicht zu identifizieren, die sonst nur schwer zu erkennen wären. Verteidiger können BloodHound nutzen, um dieselben Angriffswege zu identifizieren und zu beseitigen. Sowohl Blue- als auch Red-Teams können BloodHound verwenden, um ein tieferes Verständnis der Berechtigungsbeziehungen in einer Active Directory- oder Azure-Umgebung zu erlangen.

So ist [Bloodhound](https://github.com/BloodHoundAD/BloodHound) ein erstaunliches Tool, das automatisch eine Domäne auflisten, alle Informationen speichern, mögliche Privilegieneskalationspfade finden und alle Informationen mithilfe von Grafiken anzeigen kann.

BloodHound besteht aus 2 Hauptteilen: **Ingestoren** und der **Visualisierungsanwendung**.

Die **Ingestoren** werden verwendet, um **die Domäne aufzulisten und alle Informationen** in einem Format zu extrahieren, das die Visualisierungsanwendung versteht.

Die **Visualisierungsanwendung verwendet Neo4j**, um zu zeigen, wie alle Informationen miteinander verbunden sind und um verschiedene Möglichkeiten zur Eskalation von Berechtigungen in der Domäne anzuzeigen.

### Installation
Nach der Erstellung von BloodHound CE wurde das gesamte Projekt zur Benutzerfreundlichkeit mit Docker aktualisiert. Der einfachste Weg, um zu beginnen, ist die Verwendung der vorkonfigurierten Docker Compose-Konfiguration.

1. Installieren Sie Docker Compose. Dies sollte mit der Installation von [Docker Desktop](https://www.docker.com/products/docker-desktop/) enthalten sein.
2. Führen Sie aus:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Lokalisieren Sie das zufällig generierte Passwort in der Terminalausgabe von Docker Compose.  
4. Navigieren Sie in einem Browser zu http://localhost:8080/ui/login. Melden Sie sich mit dem Benutzernamen admin und dem zufällig generierten Passwort aus den Protokollen an.

Danach müssen Sie das zufällig generierte Passwort ändern, und Sie haben die neue Benutzeroberfläche bereit, von der aus Sie die Ingestoren direkt herunterladen können.

### SharpHound

Sie haben mehrere Optionen, aber wenn Sie SharpHound von einem PC ausführen möchten, der der Domäne beigetreten ist, und Ihr aktueller Benutzer ist, und alle Informationen extrahieren möchten, können Sie:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Sie können mehr über **CollectionMethod** und die Schleifensitzung [hier](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained) lesen.

Wenn Sie SharpHound mit anderen Anmeldeinformationen ausführen möchten, können Sie eine CMD netonly-Sitzung erstellen und SharpHound von dort aus ausführen:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Erfahren Sie mehr über Bloodhound auf ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) ist ein Tool, um **Schwachstellen** in Active Directory zu finden, die mit **Gruppenrichtlinien** verbunden sind. \
Sie müssen **group3r** von einem Host innerhalb der Domäne mit **einem beliebigen Domänenbenutzer** ausführen.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **bewertet die Sicherheitslage einer AD-Umgebung** und bietet einen schönen **Bericht** mit Grafiken.

Um es auszuführen, kann die Binary `PingCastle.exe` ausgeführt werden, und es wird eine **interaktive Sitzung** gestartet, die ein Menü mit Optionen präsentiert. Die Standardoption, die verwendet werden sollte, ist **`healthcheck`**, die eine Basislinie **Übersicht** über die **Domäne** erstellt und **Fehlkonfigurationen** und **Schwachstellen** findet.&#x20;

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
