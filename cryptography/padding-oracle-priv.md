{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>
{% endhint %}

# CBC - Cipher Block Chaining

Im CBC-Modus wird der **vorherige verschlüsselte Block als IV** verwendet, um mit dem nächsten Block zu XOR-en:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

Um CBC zu entschlüsseln, werden die **gegenteiligen Operationen** durchgeführt:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Beachten Sie, dass ein **Verschlüsselungs**-**Schlüssel** und ein **IV** verwendet werden müssen.

# Nachrichten-Padding

Da die Verschlüsselung in **festen** **Blockgrößen** durchgeführt wird, ist in **letztem** **Block** normalerweise ein Padding erforderlich, um seine Länge zu vervollständigen.\
Normalerweise wird **PKCS7** verwendet, das ein Padding generiert, das die **Anzahl** der **benötigten Bytes** zum **Vervollständigen** des Blocks **wiederholt**. Wenn beispielsweise im letzten Block 3 Bytes fehlen, wird das Padding `\x03\x03\x03` sein.

Schauen wir uns weitere Beispiele mit **2 Blöcken der Länge 8 Bytes** an:

| Byte #0 | Byte #1 | Byte #2 | Byte #3 | Byte #4 | Byte #5 | Byte #6 | Byte #7 | Byte #0  | Byte #1  | Byte #2  | Byte #3  | Byte #4  | Byte #5  | Byte #6  | Byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Beachten Sie, wie im letzten Beispiel der **letzte Block voll war, sodass ein weiterer nur mit Padding generiert wurde**.

# Padding-Oracle

Wenn eine Anwendung verschlüsselte Daten entschlüsselt, wird sie zuerst die Daten entschlüsseln; dann wird sie das Padding entfernen. Während der Bereinigung des Paddings, wenn ein **ungültiges Padding ein erkennbares Verhalten auslöst**, haben Sie eine **Padding-Oracle-Schwachstelle**. Das erkennbare Verhalten kann ein **Fehler**, ein **Fehlen von Ergebnissen** oder eine **langsamere Antwort** sein.

Wenn Sie dieses Verhalten erkennen, können Sie die **verschlüsselten Daten entschlüsseln** und sogar **beliebigen Klartext verschlüsseln**.

## Wie man ausnutzt

Sie könnten [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) verwenden, um diese Art von Schwachstelle auszunutzen oder einfach
```
sudo apt-get install padbuster
```
Um zu testen, ob das Cookie einer Website anfällig ist, könnten Sie Folgendes versuchen:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0** bedeutet, dass **base64** verwendet wird (aber andere sind verfügbar, überprüfen Sie das Hilfemenü).

Sie könnten auch **diese Schwachstelle ausnutzen, um neue Daten zu verschlüsseln. Zum Beispiel, stellen Sie sich vor, der Inhalt des Cookies lautet "**_**user=MyUsername**_**", dann könnten Sie es in "\_user=administrator\_" ändern und Privilegien innerhalb der Anwendung eskalieren. Sie könnten dies auch mit `padbuster` tun, indem Sie den Parameter -plaintext** angeben:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Wenn die Website anfällig ist, wird `padbuster` automatisch versuchen, den Zeitpunkt zu finden, an dem der Padding-Fehler auftritt. Sie können jedoch auch die Fehlermeldung angeben, indem Sie den Parameter **-error** verwenden.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## Die Theorie

Zusammengefasst können Sie beginnen, die verschlüsselten Daten zu entschlüsseln, indem Sie die korrekten Werte erraten, die verwendet werden können, um alle verschiedenen **Paddings** zu erstellen. Dann wird der Padding-Oracle-Angriff beginnen, Bytes vom Ende zum Anfang zu entschlüsseln, indem geraten wird, welcher der korrekte Wert ist, der ein Padding von 1, 2, 3 usw. erstellt.

![](<../.gitbook/assets/image (629) (1) (1).png>)

Stellen Sie sich vor, Sie haben einen verschlüsselten Text, der **2 Blöcke** umfasst, die aus den Bytes von **E0 bis E15** gebildet sind. Um den **letzten Block** (**E8** bis **E15**) zu **entschlüsseln**, durchläuft der gesamte Block die "Blockchiffre-Entschlüsselung", wodurch die **Zwischenbytes I0 bis I15** generiert werden. Schließlich wird jedes Zwischenbyte mit den vorherigen verschlüsselten Bytes (E0 bis E7) **XORed**. Also:

- `C15 = D(E15) ^ E7 = I15 ^ E7`
- `C14 = I14 ^ E6`
- `C13 = I13 ^ E5`
- `C12 = I12 ^ E4`
- ...

Nun ist es möglich, `E7` zu **ändern, bis `C15` `0x01` ist**, was auch ein korrektes Padding sein wird. Also, in diesem Fall: `\x01 = I15 ^ E'7`

Daher, wenn man E'7 findet, ist es **möglich, I15 zu berechnen**: `I15 = 0x01 ^ E'7`

Das ermöglicht es uns, **C15 zu berechnen**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Nachdem **C15** bekannt ist, ist es nun möglich, **C14 zu berechnen**, aber dieses Mal durch Brute-Force des Paddings `\x02\x02`.

Dieser BF ist genauso komplex wie der vorherige, da es möglich ist, das `E''15` zu berechnen, dessen Wert 0x02 ist: `E''7 = \x02 ^ I15`, sodass es nur noch erforderlich ist, den **`E'14`** zu finden, der ein **`C14` gleich `0x02`** erzeugt. Dann die gleichen Schritte ausführen, um C14 zu entschlüsseln: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Folgen Sie dieser Kette, bis Sie den gesamten verschlüsselten Text entschlüsseln.**

## Erkennung der Schwachstelle

Registrieren Sie ein Konto und melden Sie sich mit diesem Konto an. Wenn Sie sich **viele Male anmelden** und immer das **gleiche Cookie** erhalten, gibt es wahrscheinlich **etwas** **Falsches** in der Anwendung. Das zurückgesendete Cookie sollte jedes Mal, wenn Sie sich anmelden, **eindeutig** sein. Wenn das Cookie **immer** das **gleiche** ist, wird es wahrscheinlich immer gültig sein und es wird **keinen Weg geben, es ungültig zu machen**.

Wenn Sie nun versuchen, das **Cookie zu ändern**, erhalten Sie einen **Fehler** von der Anwendung. Wenn Sie jedoch das Padding brute-forcen (zum Beispiel mit PadBuster), gelingt es Ihnen, ein anderes Cookie zu erhalten, das für einen anderen Benutzer gültig ist. Dieses Szenario ist höchstwahrscheinlich anfällig für PadBuster.

## Referenzen

- [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)
