# Erkennung von Phishing

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys einreichen.

</details>

## Einführung

Um einen Phishing-Versuch zu erkennen, ist es wichtig, die **Phishing-Techniken zu verstehen, die heutzutage verwendet werden**. Auf der übergeordneten Seite dieses Beitrags finden Sie diese Informationen. Wenn Sie also nicht wissen, welche Techniken heute verwendet werden, empfehle ich Ihnen, zur übergeordneten Seite zu gehen und zumindest diesen Abschnitt zu lesen.

Dieser Beitrag basiert auf der Idee, dass die **Angreifer versuchen werden, die Domain des Opfers irgendwie zu imitieren oder zu verwenden**. Wenn Ihre Domain beispielsweise `beispiel.com` heißt und Sie aus irgendeinem Grund mit einer völlig anderen Domain wie `duhastdieLotteriegewonnen.com` geangelt werden, werden diese Techniken dies nicht aufdecken.

## Domainnamenvariationen

Es ist ziemlich **einfach**, diese **Phishing**-Versuche aufzudecken, die einen **ähnlichen Domainnamen** in der E-Mail verwenden werden.\
Es reicht aus, eine Liste der wahrscheinlichsten Phishing-Namen zu **generieren**, die ein Angreifer verwenden könnte, und zu **überprüfen**, ob sie **registriert** sind oder ob sie verwendet werden.

### Auffinden verdächtiger Domains

Hierfür können Sie eines der folgenden Tools verwenden. Beachten Sie, dass diese Tools auch automatisch DNS-Anfragen durchführen, um zu überprüfen, ob der Domain eine IP zugewiesen ist:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Eine kurze Erklärung dieser Technik finden Sie auf der übergeordneten Seite. Oder lesen Sie die Originalforschung unter** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Beispielsweise kann eine 1-Bit-Änderung in der Domain microsoft.com dazu führen, dass sie in _windnws.com._ umgewandelt wird.\
**Angreifer können so viele bit-flipping-Domains wie möglich registrieren, die mit dem Opfer in Verbindung stehen, um legitime Benutzer auf ihre Infrastruktur umzuleiten**.

**Alle möglichen bit-flipping-Domains sollten ebenfalls überwacht werden.**

### Grundlegende Überprüfungen

Sobald Sie eine Liste potenziell verdächtiger Domainnamen haben, sollten Sie diese **überprüfen** (hauptsächlich die Ports HTTP und HTTPS), um zu **sehen, ob sie ein ähnliches Anmeldeformular** wie das der Opferdomain verwenden.\
Sie könnten auch den Port 3333 überprüfen, um zu sehen, ob er geöffnet ist und eine Instanz von `gophish` ausgeführt wird.\
Es ist auch interessant zu wissen, **wie alt jede entdeckte verdächtige Domain ist**, je jünger sie ist, desto riskanter ist sie.\
Sie können auch **Screenshots** der HTTP- und/oder HTTPS-verdächtigen Webseite machen, um zu sehen, ob sie verdächtig ist, und in diesem Fall **darauf zugreifen, um genauer hinzusehen**.

### Fortgeschrittene Überprüfungen

Wenn Sie einen Schritt weiter gehen möchten, empfehle ich Ihnen, diese verdächtigen Domains regelmäßig zu **überwachen und nach weiteren zu suchen** (jeden Tag? Es dauert nur wenige Sekunden/Minuten). Sie sollten auch die offenen **Ports** der zugehörigen IPs **überprüfen** und nach Instanzen von `gophish` oder ähnlichen Tools suchen (ja, auch Angreifer machen Fehler) und die HTTP- und HTTPS-Webseiten der verdächtigen Domains und Subdomains **überwachen**, um zu sehen, ob sie ein Anmeldeformular von den Webseiten des Opfers kopiert haben.\
Um dies zu **automatisieren**, empfehle ich, eine Liste von Anmeldeformularen der Domains des Opfers zu haben, die verdächtigen Webseiten zu durchsuchen und jedes gefundene Anmeldeformular innerhalb der verdächtigen Domains mit jedem Anmeldeformular der Domain des Opfers unter Verwendung von etwas wie `ssdeep` zu vergleichen.\
Wenn Sie die Anmeldeformulare der verdächtigen Domains gefunden haben, können Sie versuchen, **Junk-Anmeldeinformationen zu senden** und **überprüfen, ob Sie zur Domain des Opfers umgeleitet werden**.

## Domainnamen mit Schlüsselwörtern

Die übergeordnete Seite erwähnt auch eine Technik der Domainnamenvariation, bei der der **Domainname des Opfers in eine größere Domain** eingefügt wird (z. B. paypal-financial.com für paypal.com).

### Zertifikatstransparenz

Es ist nicht möglich, den vorherigen "Brute-Force"-Ansatz zu verfolgen, aber es ist tatsächlich **möglich, solche Phishing-Versuche** auch dank der Zertifikatstransparenz aufzudecken. Jedes Mal, wenn ein Zertifikat von einer CA ausgestellt wird, werden die Details öffentlich gemacht. Dies bedeutet, dass es durch das Lesen der Zertifikatstransparenz oder sogar durch die Überwachung **möglich ist, Domains zu finden, die ein Schlüsselwort in ihrem Namen verwenden**. Wenn ein Angreifer beispielsweise ein Zertifikat für [https://paypal-financial.com](https://paypal-financial.com) generiert, ist es möglich, das Schlüsselwort "paypal" im Zertifikat zu finden und zu wissen, dass eine verdächtige E-Mail verwendet wird.

Der Beitrag [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) schlägt vor, dass Sie Censys verwenden können, um nach Zertifikaten zu suchen, die ein bestimmtes Schlüsselwort betreffen, und nach Datum (nur "neue" Zertifikate) und nach dem CA-Aussteller "Let's Encrypt" filtern:

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1115).png>)

Sie können jedoch "das Gleiche" mit der kostenlosen Website [**crt.sh**](https://crt.sh) tun. Sie können nach dem **Schlüsselwort suchen** und die Ergebnisse **nach Datum und CA filtern**, wenn Sie möchten.

![](<../../.gitbook/assets/image (519).png>)

Mit dieser letzten Option können Sie sogar das Feld Matching Identities verwenden, um zu sehen, ob eine Identität von der echten Domain mit einer der verdächtigen Domains übereinstimmt (beachten Sie, dass eine verdächtige Domain ein falsch positiv sein kann).

**Eine weitere Alternative** ist das fantastische Projekt namens [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream bietet einen Echtzeit-Stream von neu generierten Zertifikaten, den Sie verwenden können, um bestimmte Schlüsselwörter in (nahezu) Echtzeit zu erkennen. Tatsächlich gibt es ein Projekt namens [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher), das genau das tut.
### **Neue Domains**

**Eine letzte Alternative** besteht darin, eine Liste von **neu registrierten Domains** für einige TLDs zu sammeln ([Whoxy](https://www.whoxy.com/newly-registered-domains/) bietet einen solchen Service) und **die Schlüsselwörter in diesen Domains zu überprüfen**. Allerdings verwenden lange Domains in der Regel ein oder mehrere Subdomains, daher wird das Schlüsselwort nicht im FLD erscheinen und Sie werden die Phishing-Subdomain nicht finden können.
