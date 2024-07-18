# macOS Sensible Orte & Interessante Daemons

{% hint style="success" %}
Lernen & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>
{% endhint %}

## Passwörter

### Shadow-Passwörter

Das Shadow-Passwort wird zusammen mit der Benutzerkonfiguration in Plist-Dateien gespeichert, die sich in **`/var/db/dslocal/nodes/Default/users/`** befinden.\
Mit dem folgenden Oneliner können **alle Informationen über die Benutzer** (einschließlich Hash-Informationen) abgerufen werden:

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Skripte wie dieses hier**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) oder [**dieses hier**](https://github.com/octomagon/davegrohl.git) können verwendet werden, um den Hash in **hashcat-Format** umzuwandeln.

Ein alternativer One-Liner, der Anmeldeinformationen aller Nicht-Service-Konten im hashcat-Format `-m 7100` (macOS PBKDF2-SHA512) ausgibt:

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Schlüsselbund-Dump

Beachten Sie, dass bei der Verwendung des security-Binärs zum **Dumpen der entschlüsselten Passwörter** mehrere Aufforderungen den Benutzer auffordern, diese Operation zu erlauben.
```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Basierend auf diesem Kommentar [juuso/keychaindump#10 (Kommentar)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) scheint es, dass diese Tools in Big Sur nicht mehr funktionieren.
{% endhint %}

### Keychaindump Übersicht

Ein Tool namens **keychaindump** wurde entwickelt, um Passwörter aus macOS-Schlüsselbunden zu extrahieren, stößt jedoch auf Einschränkungen in neueren macOS-Versionen wie Big Sur, wie in einer [Diskussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) angegeben. Die Verwendung von **keychaindump** erfordert, dass der Angreifer Zugriff erhält und Berechtigungen auf **root**-Ebene eskaliert. Das Tool nutzt die Tatsache aus, dass der Schlüsselbund standardmäßig beim Benutzerlogin entsperrt ist, um Anwendungen den Zugriff darauf zu ermöglichen, ohne wiederholt das Passwort des Benutzers anzufordern. Wenn ein Benutzer jedoch entscheidet, den Schlüsselbund nach jeder Verwendung zu sperren, wird **keychaindump** wirkungslos.

**Keychaindump** arbeitet, indem es einen bestimmten Prozess namens **securityd** ins Visier nimmt, den Apple als Daemon für Autorisierungs- und kryptografische Operationen beschreibt, der für den Zugriff auf den Schlüsselbund unerlässlich ist. Der Extraktionsprozess beinhaltet die Identifizierung eines **Master Key**, der aus dem Anmeldepasswort des Benutzers abgeleitet ist. Dieser Schlüssel ist entscheidend für das Lesen der Schlüsselbunddatei. Um den **Master Key** zu lokalisieren, durchsucht **keychaindump** den Speicherheap von **securityd**, indem es den Befehl `vmmap` verwendet, um potenzielle Schlüssel in Bereichen zu finden, die als `MALLOC_TINY` markiert sind. Der folgende Befehl wird verwendet, um diese Speicherorte zu inspizieren:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nach Identifizierung potenzieller Master-Schlüssel durchsucht **keychaindump** die Heaps nach einem spezifischen Muster (`0x0000000000000018`), das auf einen Kandidaten für den Master-Schlüssel hinweist. Weitere Schritte, einschließlich der Entschleierung, sind erforderlich, um diesen Schlüssel zu nutzen, wie im Quellcode von **keychaindump** beschrieben. Analysten, die sich auf diesen Bereich konzentrieren, sollten beachten, dass die entscheidenden Daten zur Entschlüsselung des Schlüsselbunds im Speicher des **securityd**-Prozesses gespeichert sind. Ein Beispielbefehl zum Ausführen von **keychaindump** lautet:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kann verwendet werden, um die folgenden Arten von Informationen aus einem OSX-Schlüsselbund auf forensisch korrekte Weise zu extrahieren:

* Gehashtes Keychain-Passwort, geeignet zum Knacken mit [hashcat](https://hashcat.net/hashcat/) oder [John the Ripper](https://www.openwall.com/john/)
* Internetpasswörter
* Generische Passwörter
* Private Schlüssel
* Öffentliche Schlüssel
* X509-Zertifikate
* Sichere Notizen
* Appleshare-Passwörter

Mit dem Schlüsselbund-Entsperrpasswort, einem mit [volafox](https://github.com/n0fate/volafox) oder [volatility](https://github.com/volatilityfoundation/volatility) erhaltenen Master-Key oder einer Entsperrdatei wie SystemKey wird Chainbreaker auch Klartextpasswörter bereitstellen.

Ohne eine dieser Methoden zum Entsperren des Schlüsselbunds zeigt Chainbreaker alle anderen verfügbaren Informationen an.

#### **Schlüsselbundschlüssel dumpen**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Schlüsselbundschlüssel (mit Passwörtern) mit SystemKey auslesen**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Schlüsselbundschlüssel (mit Passwörtern) ausgeben und den Hash knacken**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dumpen von Schlüsseln im Schlüsselbund (mit Passwörtern) mit Speicherabbild**

[Befolgen Sie diese Schritte](../#dumping-memory-with-osxpmem), um ein **Speicherabbild** durchzuführen
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Schlüsselbundschlüssel (mit Passwörtern) mithilfe des Benutzerpassworts ausgeben**

Wenn Sie das Benutzerpasswort kennen, können Sie es verwenden, um **Schlüsselbünde des Benutzers auszugeben und zu entschlüsseln**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Die **kcpassword**-Datei ist eine Datei, die das **Anmeldepasswort des Benutzers** enthält, jedoch nur, wenn der Systembesitzer die **automatische Anmeldung aktiviert** hat. Daher wird der Benutzer automatisch angemeldet, ohne nach einem Passwort gefragt zu werden (was nicht sehr sicher ist).

Das Passwort wird in der Datei **`/etc/kcpassword`** mit dem Schlüssel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** xor-verknüpft. Wenn das Passwort des Benutzers länger als der Schlüssel ist, wird der Schlüssel wiederverwendet.\
Dies macht das Passwort ziemlich einfach wiederherzustellen, zum Beispiel mit Skripten wie [**diesem hier**](https://gist.github.com/opshope/32f65875d45215c3677d). 

## Interessante Informationen in Datenbanken

### Nachrichten
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Benachrichtigungen

Die Benachrichtigungsdaten finden Sie in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Die meisten interessanten Informationen werden im **Blob** sein. Sie müssen also diesen Inhalt **extrahieren** und ihn in ein **menschlich lesbares** Format **umwandeln** oder **`strings`** verwenden. Um darauf zuzugreifen, können Sie Folgendes tun:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Hinweise

Die **Notizen** der Benutzer finden sich in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Einstellungen

In macOS befinden sich die Einstellungen von Apps in **`$HOME/Library/Preferences`** und in iOS in `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.&#x20;

In macOS kann das CLI-Tool **`defaults`** verwendet werden, um die Einstellungsdatei zu **ändern**.

**`/usr/sbin/cfprefsd`** beansprucht die XPC-Dienste `com.apple.cfprefsd.daemon` und `com.apple.cfprefsd.agent` und kann aufgerufen werden, um Aktionen wie das Ändern von Einstellungen auszuführen.

## Systembenachrichtigungen

### Darwin-Benachrichtigungen

Der Hauptdaemon für Benachrichtigungen ist **`/usr/sbin/notifyd`**. Um Benachrichtigungen zu empfangen, müssen Clients sich über den `com.apple.system.notification_center` Mach-Port registrieren (überprüfen Sie sie mit `sudo lsmp -p <pid notifyd>`). Der Daemon ist konfigurierbar mit der Datei `/etc/notify.conf`.

Die Namen, die für Benachrichtigungen verwendet werden, sind eindeutige Reverse-DNS-Notationen, und wenn eine Benachrichtigung an eine von ihnen gesendet wird, erhalten die Client(s), die angegeben haben, dass sie damit umgehen können, diese.

Es ist möglich, den aktuellen Status zu dumpen (und alle Namen zu sehen), indem das Signal SIGUSR2 an den notifyd-Prozess gesendet und die generierte Datei gelesen wird: `/var/run/notifyd_<pid>.status`:
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Verteilter Benachrichtigungsdienst

Der **Verteilte Benachrichtigungsdienst**, dessen Hauptbinary **`/usr/sbin/distnoted`** ist, ist eine weitere Möglichkeit, Benachrichtigungen zu senden. Er stellt einige XPC-Dienste bereit und führt einige Überprüfungen durch, um Clients zu verifizieren.

### Apple Push-Benachrichtigungen (APN)

In diesem Fall können Anwendungen sich für **Themen** registrieren. Der Client generiert ein Token, indem er Apples Server über **`apsd`** kontaktiert.\
Dann werden auch Anbieter ein Token generiert haben und in der Lage sein, sich mit Apples Servern zu verbinden, um Nachrichten an die Clients zu senden. Diese Nachrichten werden lokal von **`apsd`** empfangen, der die Benachrichtigung an die darauf wartende Anwendung weiterleitet.

Die Einstellungen befinden sich in `/Library/Preferences/com.apple.apsd.plist`.

Es gibt eine lokale Datenbank von Nachrichten in macOS unter `/Library/Application\ Support/ApplePushService/aps.db` und in iOS unter `/var/mobile/Library/ApplePushService`. Sie hat 3 Tabellen: `incoming_messages`, `outgoing_messages` und `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Es ist auch möglich, Informationen über den Daemon und Verbindungen mithilfe von:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Benutzerbenachrichtigungen

Dies sind Benachrichtigungen, die der Benutzer auf dem Bildschirm sehen sollte:

- **`CFUserNotification`**: Diese API bietet eine Möglichkeit, auf dem Bildschirm ein Popup mit einer Nachricht anzuzeigen.
- **Das Bulletin Board**: Dies zeigt auf iOS ein Banner an, das verschwindet und im Notification Center gespeichert wird.
- **`NSUserNotificationCenter`**: Dies ist das Bulletin Board in MacOS. Die Datenbank mit den Benachrichtigungen befindet sich in `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`
