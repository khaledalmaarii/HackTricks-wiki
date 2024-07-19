# Shadow Credentials

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

## Intro <a href="#3f17" id="3f17"></a>

**Check the original post for [all the information about this technique](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Als **Zusammenfassung**: Wenn Sie in der Lage sind, auf die **msDS-KeyCredentialLink**-Eigenschaft eines Benutzers/Computers zu schreiben, können Sie den **NT-Hash dieses Objekts** abrufen.

Im Beitrag wird eine Methode beschrieben, um **öffentliche-private Schlüssel-Authentifizierungsanmeldeinformationen** einzurichten, um ein einzigartiges **Service Ticket** zu erwerben, das den NTLM-Hash des Ziels enthält. Dieser Prozess umfasst die verschlüsselten NTLM_SUPPLEMENTAL_CREDENTIAL innerhalb des Privilege Attribute Certificate (PAC), das entschlüsselt werden kann.

### Anforderungen

Um diese Technik anzuwenden, müssen bestimmte Bedingungen erfüllt sein:
- Es wird mindestens ein Windows Server 2016 Domänencontroller benötigt.
- Der Domänencontroller muss ein digitales Zertifikat für die Serverauthentifizierung installiert haben.
- Das Active Directory muss sich auf dem Funktionsniveau Windows Server 2016 befinden.
- Ein Konto mit delegierten Rechten zur Modifikation des msDS-KeyCredentialLink-Attributs des Zielobjekts ist erforderlich.

## Missbrauch

Der Missbrauch von Key Trust für Computerobjekte umfasst Schritte über den Erhalt eines Ticket Granting Ticket (TGT) und den NTLM-Hash hinaus. Die Optionen umfassen:
1. Erstellen eines **RC4-Silbertickets**, um als privilegierte Benutzer auf dem beabsichtigten Host zu agieren.
2. Verwendung des TGT mit **S4U2Self** zur Identitätsübernahme von **privilegierten Benutzern**, was Änderungen am Service Ticket erfordert, um eine Dienstklasse zum Dienstnamen hinzuzufügen.

Ein wesentlicher Vorteil des Missbrauchs von Key Trust ist die Beschränkung auf den vom Angreifer generierten privaten Schlüssel, wodurch eine Delegation an potenziell anfällige Konten vermieden wird und keine Erstellung eines Computeraccounts erforderlich ist, was schwierig zu entfernen sein könnte.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Es basiert auf DSInternals und bietet eine C#-Schnittstelle für diesen Angriff. Whisker und sein Python-Pendant, **pyWhisker**, ermöglichen die Manipulation des `msDS-KeyCredentialLink`-Attributs, um die Kontrolle über Active Directory-Konten zu erlangen. Diese Tools unterstützen verschiedene Operationen wie das Hinzufügen, Auflisten, Entfernen und Löschen von Schlüsselanmeldeinformationen vom Zielobjekt.

**Whisker**-Funktionen umfassen:
- **Add**: Generiert ein Schlüsselpaar und fügt eine Schlüsselanmeldeinformation hinzu.
- **List**: Zeigt alle Einträge der Schlüsselanmeldeinformationen an.
- **Remove**: Löscht eine angegebene Schlüsselanmeldeinformation.
- **Clear**: Löscht alle Schlüsselanmeldeinformationen, was die legitime Nutzung von WHfB stören könnte.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Es erweitert die Whisker-Funktionalität für **UNIX-basierte Systeme** und nutzt Impacket und PyDSInternals für umfassende Exploitationsmöglichkeiten, einschließlich Auflisten, Hinzufügen und Entfernen von KeyCredentials sowie dem Importieren und Exportieren im JSON-Format.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray zielt darauf ab, **GenericWrite/GenericAll-Berechtigungen auszunutzen, die breite Benutzergruppen möglicherweise über Domänenobjekte haben**, um ShadowCredentials umfassend anzuwenden. Es umfasst das Anmelden an der Domäne, das Überprüfen des funktionalen Niveaus der Domäne, das Auflisten von Domänenobjekten und den Versuch, KeyCredentials für den TGT-Erwerb und die Offenlegung des NT-Hashes hinzuzufügen. Aufräumoptionen und rekursive Ausnutzungstaktiken erhöhen seinen Nutzen.


## References

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

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
