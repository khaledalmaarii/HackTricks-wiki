# Schattenanmeldeinformationen

<details>

<summary>Lernen Sie das Hacken von AWS von Grund auf mit <a href="https://training.hacktricks.xyz/courses/arte">htARTE (HackTricks AWS Red Team Expert)</a>!</summary>

* Arbeiten Sie in einem Cybersecurity-Unternehmen? Möchten Sie Ihr Unternehmen in HackTricks bewerben? Oder möchten Sie Zugriff auf die neueste Version von PEASS oder HackTricks im PDF-Format haben? Überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [The PEASS Family](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver NFTs.
* Holen Sie sich das offizielle PEASS & HackTricks-Merchandise.
* Treten Sie der [💬](https://emojipedia.org/speech-balloon/) [Discord-Gruppe](https://discord.gg/hRep4RUj7f) oder der [Telegramm-Gruppe](https://t.me/peass) bei oder folgen Sie mir auf Twitter 🐦[@carlospolopm](https://twitter.com/hacktricks_live).
* Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud) senden.

</details>

## Einführung <a href="#3f17" id="3f17"></a>

**Überprüfen Sie den Originalbeitrag für [alle Informationen zu dieser Technik](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Zusammenfassend: Wenn Sie auf die Eigenschaft **msDS-KeyCredentialLink** eines Benutzers/Computers schreiben können, können Sie den **NT-Hash dieses Objekts abrufen**.

In dem Beitrag wird eine Methode beschrieben, um **öffentliche-private Schlüsselauthentifizierungsanmeldeinformationen** einzurichten, um ein eindeutiges **Service Ticket** zu erhalten, das den NTLM-Hash des Ziels enthält. Dieser Prozess beinhaltet das verschlüsselte NTLM_SUPPLEMENTAL_CREDENTIAL innerhalb des Privilege Attribute Certificate (PAC), das entschlüsselt werden kann.

### Voraussetzungen

Um diese Technik anzuwenden, müssen bestimmte Bedingungen erfüllt sein:
- Mindestens ein Windows Server 2016-Domänencontroller ist erforderlich.
- Der Domänencontroller muss über ein Serverauthentifizierungsdigitalzertifikat verfügen.
- Die Active Directory muss auf dem Funktionslevel von Windows Server 2016 sein.
- Ein Konto mit delegierten Rechten zur Änderung des Attributs msDS-KeyCredentialLink des Zielobjekts ist erforderlich.

## Missbrauch

Der Missbrauch von Key Trust für Computerobjekte umfasst Schritte, die über das Erlangen eines Ticket Granting Ticket (TGT) und des NTLM-Hashs hinausgehen. Die Optionen umfassen:
1. Erstellen eines **RC4 Silver Tickets**, um als privilegierte Benutzer auf dem beabsichtigten Host zu agieren.
2. Verwendung des TGT mit **S4U2Self** zur Nachahmung von **privilegierten Benutzern**, was Änderungen am Service Ticket erfordert, um eine Dienstklasse zum Dienstnamen hinzuzufügen.

Ein wesentlicher Vorteil des Missbrauchs von Key Trust besteht darin, dass er auf den vom Angreifer generierten privaten Schlüssel beschränkt ist, was die Delegation an potenziell gefährdete Konten vermeidet und nicht die Erstellung eines Computerkontos erfordert, das möglicherweise schwer zu entfernen ist.

## Tools

### [Whisker](https://github.com/eladshamir/Whisker)

Es basiert auf DSInternals und bietet eine C#-Schnittstelle für diesen Angriff. Whisker und sein Python-Gegenstück **pyWhisker** ermöglichen die Manipulation des Attributs `msDS-KeyCredentialLink`, um die Kontrolle über Active Directory-Konten zu erlangen. Diese Tools unterstützen verschiedene Operationen wie Hinzufügen, Auflisten, Entfernen und Löschen von Schlüsselanmeldeinformationen vom Zielobjekt.

Die Funktionen von **Whisker** umfassen:
- **Hinzufügen**: Generiert ein Schlüsselpaar und fügt eine Schlüsselanmeldeinformation hinzu.
- **Auflisten**: Zeigt alle Schlüsselanmeldeinformationseinträge an.
- **Entfernen**: Löscht eine bestimmte Schlüsselanmeldeinformation.
- **Löschen**: Löscht alle Schlüsselanmeldeinformationen, was möglicherweise die legitime Verwendung von WHfB stört.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Es erweitert die Funktionalität von Whisker auf **UNIX-basierte Systeme** und nutzt Impacket und PyDSInternals für umfassende Exploit-Fähigkeiten, einschließlich Auflistung, Hinzufügen und Entfernen von KeyCredentials sowie Importieren und Exportieren im JSON-Format.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray zielt darauf ab, **GenericWrite/GenericAll-Berechtigungen auszunutzen, die breite Benutzergruppen möglicherweise über Domänenobjekte haben**, um ShadowCredentials weitreichend anzuwenden. Es beinhaltet das Einloggen in die Domäne, das Überprüfen des funktionalen Levels der Domäne, das Auflisten von Domänenobjekten und den Versuch, KeyCredentials für TGT-Erwerb und NT-Hash-Enthüllung hinzuzufügen. Bereinigungsoptionen und rekursive Ausbeutungstaktiken verbessern ihre Nützlichkeit.


## Referenzen

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS oder HackTricks als PDF-Download** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>
