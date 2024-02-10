# Geräte in anderen Organisationen einschreiben

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Einführung

Wie [**zuvor erwähnt**](./#what-is-mdm-mobile-device-management)**,** wird zur Einschreibung eines Geräts in eine Organisation **nur eine Seriennummer benötigt, die zu dieser Organisation gehört**. Sobald das Gerät eingeschrieben ist, installieren mehrere Organisationen sensible Daten auf dem neuen Gerät: Zertifikate, Anwendungen, WLAN-Passwörter, VPN-Konfigurationen [und so weiter](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daher kann dies ein gefährlicher Einstiegspunkt für Angreifer sein, wenn der Einschreibungsprozess nicht richtig geschützt ist.

**Im Folgenden finden Sie eine Zusammenfassung der Forschungsergebnisse [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Weitere technische Details finden Sie dort!**

## Überblick über DEP und MDM-Binäranalyse

Diese Forschung untersucht die mit dem Device Enrollment Program (DEP) und dem Mobile Device Management (MDM) auf macOS verbundenen Binärdateien. Zu den wichtigsten Komponenten gehören:

- **`mdmclient`**: Kommuniziert mit MDM-Servern und löst DEP-Check-ins auf macOS-Versionen vor 10.13.4 aus.
- **`profiles`**: Verwaltet Konfigurationsprofile und löst DEP-Check-ins auf macOS-Versionen 10.13.4 und höher aus.
- **`cloudconfigurationd`**: Verwaltet DEP-API-Kommunikation und ruft Geräte-Einschreibungsprofile ab.

DEP-Check-ins verwenden die Funktionen `CPFetchActivationRecord` und `CPGetActivationRecord` aus dem privaten Configuration Profiles-Framework, um den Aktivierungsdatensatz abzurufen, wobei `CPFetchActivationRecord` über XPC mit `cloudconfigurationd` zusammenarbeitet.

## Reverse Engineering des Tesla-Protokolls und des Absinthe-Schemas

Der DEP-Check-in beinhaltet, dass `cloudconfigurationd` eine verschlüsselte, signierte JSON-Payload an _iprofiles.apple.com/macProfile_ sendet. Die Payload enthält die Seriennummer des Geräts und die Aktion "RequestProfileConfiguration". Das verwendete Verschlüsselungsschema wird intern als "Absinthe" bezeichnet. Die Entschlüsselung dieses Schemas ist komplex und erfordert zahlreiche Schritte, was zur Erforschung alternativer Methoden führte, um beliebige Seriennummern in der Anforderung des Aktivierungsdatensatzes einzufügen.

## Proxying von DEP-Anfragen

Versuche, DEP-Anfragen an _iprofiles.apple.com_ mit Tools wie Charles Proxy abzufangen und zu ändern, wurden durch die Verschlüsselung der Payload und die SSL/TLS-Sicherheitsmaßnahmen behindert. Durch Aktivieren der Konfiguration `MCCloudConfigAcceptAnyHTTPSCertificate` kann jedoch die Überprüfung des Serverzertifikats umgangen werden, obwohl die verschlüsselte Natur der Payload eine Änderung der Seriennummer ohne den Entschlüsselungsschlüssel verhindert.

## Instrumentierung von System-Binärdateien, die mit DEP interagieren

Die Instrumentierung von System-Binärdateien wie `cloudconfigurationd` erfordert das Deaktivieren des System Integrity Protection (SIP) auf macOS. Mit deaktiviertem SIP können Tools wie LLDB verwendet werden, um sich an Systemprozesse anzuhängen und möglicherweise die Seriennummer zu ändern, die in den DEP-API-Interaktionen verwendet wird. Diese Methode ist vorzuziehen, da sie die Komplexität von Berechtigungen und Code-Signierung vermeidet.

**Ausnutzung der Instrumentierung von Binärdateien:**
Die Modifikation der DEP-Anforderungspayload vor der JSON-Serialisierung in `cloudconfigurationd` erwies sich als wirksam. Der Prozess umfasste:

1. Anhängen von LLDB an `cloudconfigurationd`.
2. Lokalisieren des Punkts, an dem die Systemseriennummer abgerufen wird.
3. Einfügen einer beliebigen Seriennummer in den Speicher, bevor die Payload verschlüsselt und gesendet wird.

Diese Methode ermöglichte das Abrufen vollständiger DEP-Profile für beliebige Seriennummern und zeigte eine potenzielle Sicherheitslücke auf.

### Automatisierung der Instrumentierung mit Python

Der Ausnutzungsprozess wurde mit Python und der LLDB-API automatisiert, sodass beliebige Seriennummern programmgesteuert eingefügt und entsprechende DEP-Profile abgerufen werden konnten.

### Mögliche Auswirkungen von DEP- und MDM-Schwachstellen

Die Forschung hat erhebliche Sicherheitsbedenken aufgezeigt:

1. **Informationspreisgabe**: Durch Bereitstellung einer DEP-registrierten Seriennummer können sensible organisatorische Informationen, die im DEP-Profil enthalten sind, abgerufen werden.
2. **Betrügerische DEP-Einschreibung**: Ohne ordnungsgemäße Authentifizierung kann ein Angreifer mit einer DEP-registrierten Seriennummer ein betrügerisches Gerät in den MDM-Server einer Organisation einschreiben und möglicherweise Zugriff auf sensible Daten und Netzwerkressourcen erhalten.

Zusammenfassend lässt sich sagen, dass DEP und MDM leistungsstarke Tools zur Verwaltung von Apple-Geräten in Unternehmensumgebungen bieten, aber auch potenzielle Angriffsvektoren darstellen, die gesichert und überwacht werden müssen.



<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
