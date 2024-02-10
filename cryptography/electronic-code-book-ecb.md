<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


# ECB

(ECB) Electronic Code Book - symmetrisches Verschlüsselungsverfahren, bei dem jeder Block des Klartexts durch den Block des Geheimtexts ersetzt wird. Es ist das **einfachste** Verschlüsselungsverfahren. Die Hauptidee besteht darin, den Klartext in **Blöcke von N Bits** (abhängig von der Größe des Eingabedatenblocks, des Verschlüsselungsalgorithmus) aufzuteilen und dann jeden Block des Klartexts mit dem einzigen Schlüssel zu verschlüsseln (entschlüsseln).

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Die Verwendung von ECB hat mehrere Sicherheitsimplikationen:

* **Blöcke aus verschlüsselter Nachricht können entfernt werden**
* **Blöcke aus verschlüsselter Nachricht können verschoben werden**

# Erkennung der Schwachstelle

Stellen Sie sich vor, Sie melden sich mehrmals bei einer Anwendung an und erhalten **immer denselben Cookie**. Dies liegt daran, dass der Cookie der Anwendung **`<Benutzername>|<Passwort>`** ist.\
Dann generieren Sie zwei neue Benutzer, beide mit dem **gleichen langen Passwort** und **fast** dem **gleichen** **Benutzernamen**.\
Sie stellen fest, dass die **Blöcke von 8B**, in denen die **Informationen beider Benutzer** gleich sind, **gleich** sind. Sie vermuten, dass dies daran liegen könnte, dass **ECB verwendet wird**.

Wie im folgenden Beispiel. Beachten Sie, wie diese **2 decodierten Cookies** mehrmals den Block **`\x23U\xE45K\xCB\x21\xC8`** enthalten.
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Dies liegt daran, dass der **Benutzername und das Passwort dieser Cookies mehrmals den Buchstaben "a"** enthalten haben (zum Beispiel). Die **unterschiedlichen Blöcke** sind Blöcke, die **mindestens ein unterschiedliches Zeichen** enthalten (vielleicht das Trennzeichen "|" oder einen notwendigen Unterschied im Benutzernamen).

Nun muss der Angreifer nur noch herausfinden, ob das Format `<Benutzername><Trennzeichen><Passwort>` oder `<Passwort><Trennzeichen><Benutzername>` ist. Dazu kann er einfach **mehrere Benutzernamen** mit **ähnlichen und langen Benutzernamen und Passwörtern generieren**, bis er das Format und die Länge des Trennzeichens findet:

| Länge des Benutzernamens: | Länge des Passworts: | Länge von Benutzername+Passwort: | Länge des Cookies (nach dem Decodieren): |
| ------------------------ | -------------------- | --------------------------------- | --------------------------------------- |
| 2                        | 2                    | 4                                 | 8                                       |
| 3                        | 3                    | 6                                 | 8                                       |
| 3                        | 4                    | 7                                 | 8                                       |
| 4                        | 4                    | 8                                 | 16                                      |
| 7                        | 7                    | 14                                | 16                                      |

# Ausnutzung der Schwachstelle

## Entfernen ganzer Blöcke

Nachdem das Format des Cookies bekannt ist (`<Benutzername>|<Passwort>`), um den Benutzernamen `admin` zu imitieren, erstellen Sie einen neuen Benutzer namens `aaaaaaaaadmin`, erhalten Sie den Cookie und decodieren Sie ihn:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Wir können das zuvor erstellte Muster `\x23U\xE45K\xCB\x21\xC8` mit dem Benutzernamen sehen, der nur `a` enthielt.\
Dann können Sie den ersten Block von 8B entfernen und Sie erhalten einen gültigen Cookie für den Benutzernamen `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Verschieben von Blöcken

In vielen Datenbanken ist es gleich, nach `WHERE username='admin';` oder nach `WHERE username='admin    ';` zu suchen _(Beachten Sie die zusätzlichen Leerzeichen)_

Eine weitere Möglichkeit, den Benutzer `admin` zu imitieren, besteht darin:

* Generieren Sie einen Benutzernamen, der `len(<username>) + len(<delimiter>) % len(block)` entspricht. Mit einer Blockgröße von `8B` können Sie einen Benutzernamen namens `username       ` generieren, wobei das Trennzeichen `|` den Chunk `<username><delimiter>` erzeugt, der 2 Blöcke von 8Bs erzeugt.
* Generieren Sie dann ein Passwort, das eine genaue Anzahl von Blöcken enthält, die den Benutzernamen, den wir imitieren möchten, und Leerzeichen enthalten, z. B.: `admin   `

Das Cookie dieses Benutzers besteht aus 3 Blöcken: den ersten 2 Blöcken des Benutzernamens + Trennzeichen und dem dritten Block des Passworts (das den Benutzernamen fälscht): `username       |admin   `

**Ersetzen Sie dann einfach den ersten Block durch den letzten und Sie werden den Benutzer `admin` imitieren: `admin          |username`**

## Referenzen

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))


<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
