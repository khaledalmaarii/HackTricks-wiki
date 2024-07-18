{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys einreichen.

</details>
{% endhint %}


# ECB

(ECB) Electronic Code Book - symmetrisches Verschlüsselungsschema, das **jeden Block des Klartexts** durch den **Block des Geheimtexts** ersetzt. Es ist das **einfachste** Verschlüsselungsschema. Die Hauptidee besteht darin, den Klartext in **Blöcke von N Bits** (abhängig von der Größe des Eingabedatenblocks, des Verschlüsselungsalgorithmus) aufzuteilen und dann jeden Block des Klartexts mit dem einzigen Schlüssel zu verschlüsseln (entschlüsseln).

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Die Verwendung von ECB hat mehrere Sicherheitsimplikationen:

* **Blöcke aus der verschlüsselten Nachricht können entfernt werden**
* **Blöcke aus der verschlüsselten Nachricht können verschoben werden**

# Erkennung der Schwachstelle

Stellen Sie sich vor, Sie melden sich mehrmals bei einer Anwendung an und erhalten **immer denselben Cookie**. Dies liegt daran, dass der Cookie der Anwendung **`<Benutzername>|<Passwort>`** ist.\
Dann erstellen Sie zwei neue Benutzer, beide mit dem **gleichen langen Passwort** und **fast** dem **gleichen** **Benutzernamen**.\
Sie stellen fest, dass die **Blöcke von 8B**, in denen die **Informationen beider Benutzer** gleich sind, **gleich** sind. Dann stellen Sie sich vor, dass dies daran liegen könnte, dass **ECB verwendet wird**.

Wie im folgenden Beispiel. Beachten Sie, wie diese **2 decodierten Cookies** mehrmals den Block **`\x23U\xE45K\xCB\x21\xC8`** enthalten.
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Das liegt daran, dass der **Benutzername und das Passwort dieser Cookies mehrmals den Buchstaben "a" enthalten** (zum Beispiel). Die **Blöcke**, die **unterschiedlich** sind, sind Blöcke, die **mindestens 1 unterschiedliches Zeichen** enthielten (vielleicht das Trennzeichen "|" oder einen notwendigen Unterschied im Benutzernamen).

Nun muss der Angreifer nur noch herausfinden, ob das Format `<Benutzername><Trennzeichen><Passwort>` oder `<Passwort><Trennzeichen><Benutzername>` ist. Um das zu tun, kann er einfach **mehrere Benutzernamen** mit **ähnlichen und langen Benutzernamen und Passwörtern generieren, bis er das Format und die Länge des Trennzeichens findet:**

| Benutzername Länge: | Passwort Länge: | Benutzername+Passwort Länge: | Länge des Cookies (nach dem Dekodieren): |
| ------------------- | ---------------- | ---------------------------- | ---------------------------------------- |
| 2                   | 2                | 4                            | 8                                        |
| 3                   | 3                | 6                            | 8                                        |
| 3                   | 4                | 7                            | 8                                        |
| 4                   | 4                | 8                            | 16                                       |
| 7                   | 7                | 14                           | 16                                       |

# Ausnutzung der Schwachstelle

## Entfernen ganzer Blöcke

Nachdem das Format des Cookies bekannt ist (`<Benutzername>|<Passwort>`), um den Benutzernamen `admin` zu übernehmen, erstellen Sie einen neuen Benutzer namens `aaaaaaaaadmin` und erhalten Sie den Cookie und dekodieren Sie ihn:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Wir können das Muster `\x23U\xE45K\xCB\x21\xC8`, das zuvor mit dem Benutzernamen erstellt wurde, der nur `a` enthielt, sehen.\
Dann können Sie den ersten Block von 8B entfernen und Sie erhalten ein gültiges Cookie für den Benutzernamen `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Verschieben von Blöcken

In vielen Datenbanken ist es gleich, nach `WHERE username='admin';` oder nach `WHERE username='admin    ';` zu suchen _(Beachten Sie die zusätzlichen Leerzeichen)_

Eine weitere Möglichkeit, den Benutzer `admin` zu imitieren, wäre:

* Generieren Sie einen Benutzernamen, der folgendes erfüllt: `len(<Benutzername>) + len(<Trennzeichen) % len(Block)`. Mit einer Blockgröße von `8B` können Sie einen Benutzernamen namens `Benutzername       ` generieren, wobei das Trennzeichen `|` den Chunk `<Benutzername><Trennzeichen>` 2 Blöcke von 8Bs generieren wird.
* Generieren Sie dann ein Passwort, das eine genaue Anzahl von Blöcken ausfüllt, die den Benutzernamen enthalten, den wir imitieren möchten, und Leerzeichen, wie z.B.: `admin   `

Das Cookie dieses Benutzers wird aus 3 Blöcken bestehen: die ersten 2 Blöcke sind die Blöcke des Benutzernamens + Trennzeichen und der dritte Block des Passworts (das den Benutzernamen fälscht): `Benutzername       |admin   `

**Dann ersetzen Sie einfach den ersten Block durch den letzten und werden den Benutzer `admin` imitieren: `admin          |Benutzername`**

## Referenzen

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))
