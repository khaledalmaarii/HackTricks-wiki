# AD CS Kontopersistenz

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>

**Dies ist eine kurze Zusammenfassung der Kapitel zur Maschinenpersistenz aus der großartigen Forschung von [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## **Verständnis des Diebstahls von Benutzeranmeldeinformationen mit Zertifikaten - PERSIST1**

In einem Szenario, in dem ein Zertifikat, das die Domänenauthentifizierung ermöglicht, von einem Benutzer angefordert werden kann, hat ein Angreifer die Möglichkeit, dieses Zertifikat zu **anfordern** und **zu stehlen**, um eine **persistente Zugriffsmöglichkeit** in einem Netzwerk aufrechtzuerhalten. Standardmäßig erlaubt die `User`-Vorlage in Active Directory solche Anfragen, obwohl sie manchmal deaktiviert sein kann.

Mit einem Tool namens [**Certify**](https://github.com/GhostPack/Certify) kann man nach gültigen Zertifikaten suchen, die einen dauerhaften Zugriff ermöglichen:
```bash
Certify.exe find /clientauth
```
Es wird hervorgehoben, dass die Stärke eines Zertifikats in seiner Fähigkeit liegt, sich als den Benutzer zu **authentifizieren**, dem es gehört, unabhängig von etwaigen Passwortänderungen, solange das Zertifikat **gültig** bleibt.

Zertifikate können über eine grafische Benutzeroberfläche mit `certmgr.msc` oder über die Befehlszeile mit `certreq.exe` angefordert werden. Mit **Certify** wird der Prozess zur Zertifikatsanforderung wie folgt vereinfacht:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Nach erfolgreicher Anfrage wird ein Zertifikat zusammen mit seinem privaten Schlüssel im `.pem`-Format generiert. Um dies in eine `.pfx`-Datei umzuwandeln, die auf Windows-Systemen verwendet werden kann, wird der folgende Befehl verwendet:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Die `.pfx`-Datei kann dann auf ein Zielsystem hochgeladen und mit einem Tool namens [**Rubeus**](https://github.com/GhostPack/Rubeus) verwendet werden, um ein Ticket Granting Ticket (TGT) für den Benutzer anzufordern und den Zugriff des Angreifers so lange zu verlängern, wie das Zertifikat **gültig** ist (in der Regel ein Jahr):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Eine wichtige Warnung wird geteilt, wie diese Technik in Kombination mit einer anderen Methode, die im Abschnitt **THEFT5** beschrieben wird, einem Angreifer ermöglicht, dauerhaft den **NTLM-Hash** eines Kontos zu erhalten, ohne mit dem Local Security Authority Subsystem Service (LSASS) zu interagieren und aus einem nicht erhöhten Kontext heraus, was eine unauffälligere Methode für langfristigen Zugriff auf Anmeldedaten bietet.

## **Erhalten von Maschinenpersistenz mit Zertifikaten - PERSIST2**

Eine andere Methode besteht darin, das Maschinenkonto eines kompromittierten Systems für ein Zertifikat zu registrieren, wobei die standardmäßige `Machine`-Vorlage verwendet wird, die solche Aktionen ermöglicht. Wenn ein Angreifer erhöhte Privilegien auf einem System erlangt, kann er das **SYSTEM**-Konto verwenden, um Zertifikate anzufordern und somit eine Form von **Persistenz** zu erreichen:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Dieser Zugriff ermöglicht es dem Angreifer, sich als Maschinenkonto bei **Kerberos** anzumelden und **S4U2Self** zu nutzen, um Kerberos-Diensttickets für jeden Dienst auf dem Host zu erhalten. Dadurch erhält der Angreifer dauerhaften Zugriff auf die Maschine.

## **Erweiterung der Persistenz durch Zertifikatserneuerung - PERSIST3**

Die letzte besprochene Methode beinhaltet die Nutzung der **Gültigkeitsdauer** und **Erneuerungsperioden** von Zertifikatvorlagen. Durch die **Erneuerung** eines Zertifikats vor dessen Ablauf kann ein Angreifer die Authentifizierung bei Active Directory aufrechterhalten, ohne zusätzliche Ticketanmeldungen durchführen zu müssen, die Spuren auf dem Zertifizierungsstellen (CA)-Server hinterlassen könnten.

Dieser Ansatz ermöglicht eine **erweiterte Persistenz** und minimiert das Risiko einer Entdeckung durch weniger Interaktionen mit dem CA-Server und die Vermeidung der Erzeugung von Artefakten, die Administratoren auf den Eindringling aufmerksam machen könnten.

<details>

<summary><strong>Erlernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
