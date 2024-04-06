# Padding Oracle

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## CBC - Cipher Block Chaining

Im CBC-Modus wird der **vorherige verschlüsselte Block als IV** verwendet, um mit dem nächsten Block zu XOR:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Um CBC zu entschlüsseln, werden die **gegensätzlichen** **Operationen** durchgeführt:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Beachten Sie, dass ein **Verschlüsselungs**-**Schlüssel** und ein **IV** verwendet werden müssen.

## Nachrichten-Padding

Da die Verschlüsselung in **festen** **Blockgrößen** durchgeführt wird, ist in der Regel ein Padding im **letzten** **Block** erforderlich, um seine Länge zu vervollständigen.\
In der Regel wird **PKCS7** verwendet, das ein Padding generiert, das die **Anzahl** der **benötigten Bytes** wiederholt, um den Block zu vervollständigen. Wenn zum Beispiel dem letzten Block 3 Bytes fehlen, wird das Padding `\x03\x03\x03` sein.

Schauen wir uns weitere Beispiele mit **2 Blöcken der Länge 8 Bytes** an:

| Byte #0 | Byte #1 | Byte #2 | Byte #3 | Byte #4 | Byte #5 | Byte #6 | Byte #7 | Byte #0  | Byte #1  | Byte #2  | Byte #3  | Byte #4  | Byte #5  | Byte #6  | Byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Beachten Sie, wie im letzten Beispiel der **letzte Block voll war, sodass ein weiterer Block nur mit Padding generiert wurde**.

## Padding Oracle

Wenn eine Anwendung verschlüsselte Daten entschlüsselt, entschlüsselt sie zuerst die Daten; dann entfernt sie das Padding. Während der Bereinigung des Paddings, wenn ein **ungültiges Padding ein erkennbares Verhalten auslöst**, haben Sie eine **Padding-Oracle-Schwachstelle**. Das erkennbare Verhalten kann ein **Fehler**, ein **Fehlen von Ergebnissen** oder eine **langsamere Antwort** sein.

Wenn Sie dieses Verhalten erkennen, können Sie die **verschlüsselten Daten entschlüsseln** und sogar **beliebigen Klartext verschlüsseln**.

### Wie man ausnutzt

Sie könnten [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) verwenden, um diese Art von Schwachstelle auszunutzen oder einfach...

```
sudo apt-get install padbuster
```

Um zu testen, ob das Cookie einer Website anfällig ist, könnten Sie Folgendes versuchen:

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```

**Kodierung 0** bedeutet, dass **base64** verwendet wird (aber andere sind verfügbar, überprüfen Sie das Hilfemenü).

Sie könnten auch diese Schwachstelle **ausnutzen, um neue Daten zu verschlüsseln**. Zum Beispiel, stellen Sie sich vor, der Inhalt des Cookies lautet "**\_**user=MyUsername**\_**", dann könnten Sie es zu "\_user=administrator\_" ändern und Privilegien in der Anwendung eskalieren. Sie könnten dies auch mit `paduster` tun, indem Sie den Parameter -plaintext\*\* angeben:

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```

Wenn die Website anfällig ist, wird `padbuster` automatisch versuchen, den Zeitpunkt des Padding-Fehlers zu finden. Sie können jedoch auch die Fehlermeldung mit dem **-error**-Parameter angeben.

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```

### Die Theorie

Zusammenfassend kann man beginnen, die verschlüsselten Daten zu entschlüsseln, indem man die richtigen Werte errät, die verwendet werden können, um alle verschiedenen Paddings zu erstellen. Dann beginnt der Padding-Oracle-Angriff damit, Bytes vom Ende bis zum Anfang zu entschlüsseln, indem geraten wird, welcher Wert der richtige ist, der ein Padding von 1, 2, 3 usw. erzeugt.

![](<../.gitbook/assets/image (629) (1) (1).png>)

Stellen Sie sich vor, Sie haben einen verschlüsselten Text, der aus 2 Blöcken besteht, die aus den Bytes von E0 bis E15 gebildet werden. Um den letzten Block (E8 bis E15) zu entschlüsseln, durchläuft der gesamte Block die "Blockchiffre-Entschlüsselung" und erzeugt die Zwischenbytes I0 bis I15. Schließlich wird jedes Zwischenbyte mit den vorherigen verschlüsselten Bytes (E0 bis E7) XOR-verknüpft. Also:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Nun ist es möglich, `E7` zu ändern, bis `C15` `0x01` ist, was auch ein korrektes Padding ist. In diesem Fall gilt also: `\x01 = I15 ^ E'7`

Daher lässt sich `I15` berechnen, indem man `E'7` findet: `I15 = 0x01 ^ E'7`

Damit können wir `C15` berechnen: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Nachdem wir `C15` kennen, ist es nun möglich, `C14` zu berechnen, aber diesmal wird das Padding `\x02\x02` per Brute-Force ermittelt.

Dieser Brute-Force ist genauso komplex wie der vorherige, da es möglich ist, das `E''15` zu berechnen, dessen Wert 0x02 ist: `E''7 = \x02 ^ I15`, also muss nur das `E'14` gefunden werden, das ein `C14` gleich `0x02` erzeugt. Dann werden die gleichen Schritte durchgeführt, um C14 zu entschlüsseln: `C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`

**Folgen Sie dieser Kette, bis Sie den gesamten verschlüsselten Text entschlüsselt haben.**

### Erkennung der Schwachstelle

Registrieren Sie ein Konto und melden Sie sich mit diesem Konto an.\
Wenn Sie sich **mehrmals anmelden** und jedes Mal das **gleiche Cookie** erhalten, gibt es wahrscheinlich **etwas** **falsch** in der Anwendung. Das zurückgesendete Cookie sollte jedes Mal, wenn Sie sich anmelden, eindeutig sein. Wenn das Cookie **immer** das **gleiche** ist, wird es wahrscheinlich immer gültig sein und es gibt **keine Möglichkeit, es ungültig zu machen**.

Wenn Sie nun versuchen, das Cookie zu **ändern**, erhalten Sie einen **Fehler** von der Anwendung.\
Aber wenn Sie das Padding per Brute-Force (z.B. mit PadBuster) erzwingen, können Sie ein anderes Cookie erhalten, das für einen anderen Benutzer gültig ist. Dieses Szenario ist höchstwahrscheinlich anfällig für PadBuster.

### Referenzen

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
