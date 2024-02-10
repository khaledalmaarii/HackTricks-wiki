<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>


Für eine Phishing-Bewertung kann es manchmal nützlich sein, eine Website vollständig **zu klonen**.

Beachten Sie, dass Sie der geklonten Website auch einige Payloads hinzufügen können, wie z.B. einen BeEF-Hook, um das Tab des Benutzers "zu kontrollieren".

Es gibt verschiedene Tools, die Sie für diesen Zweck verwenden können:

## wget
```text
wget -mk -nH
```
## goclone

`goclone` is a command-line tool that allows you to clone a website for phishing purposes. It is a powerful tool that automates the process of creating a replica of a target website, which can be used to trick users into revealing their sensitive information.

To use `goclone`, follow these steps:

1. Install `goclone` by running the following command:
   ```
   go get github.com/ReddyyZ/goclone
   ```

2. Once `goclone` is installed, navigate to the directory where you want to clone the website.

3. Run the following command to clone the website:
   ```
   goclone -url <target_url>
   ```

   Replace `<target_url>` with the URL of the website you want to clone.

4. `goclone` will create a replica of the target website in the current directory. The cloned website will have the same structure and content as the original website.

5. You can now use the cloned website for phishing attacks. Make sure to host the cloned website on a server or a cloud platform, and send phishing emails or messages to the target users.

It is important to note that phishing is illegal and unethical. This tool is provided for educational purposes only, and should not be used for any malicious activities. Always obtain proper authorization before conducting any security testing or penetration testing activities.
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Social Engineering Toolkit

Das Social Engineering Toolkit (SET) ist ein leistungsstarkes Framework, das speziell für Social Engineering-Angriffe entwickelt wurde. Es bietet eine Vielzahl von Tools und Funktionen, mit denen Hacker verschiedene Phishing-Techniken durchführen können, um Zugriff auf vertrauliche Informationen zu erlangen.

### Klonen einer Website

Das Klonen einer Website ist eine gängige Methode im Bereich des Phishings. Dabei wird eine exakte Kopie einer legitimen Website erstellt, um Benutzer dazu zu verleiten, ihre Anmeldedaten oder andere vertrauliche Informationen preiszugeben.

#### Schritt 1: Zielwebsite auswählen

Wählen Sie die Website aus, die Sie klonen möchten. Dies kann beispielsweise eine beliebte E-Mail-Plattform, ein soziales Netzwerk oder ein Online-Banking-Portal sein.

#### Schritt 2: SET starten

Starten Sie das Social Engineering Toolkit (SET) und wählen Sie die Option "Website Attack Vectors" aus dem Hauptmenü.

#### Schritt 3: Option "Credential Harvester Attack Method" auswählen

Wählen Sie die Option "Credential Harvester Attack Method" aus dem Menü der Website-Angriffsvektoren.

#### Schritt 4: Option "Site Cloner" auswählen

Wählen Sie die Option "Site Cloner" aus dem Menü der Angriffsmethoden.

#### Schritt 5: URL der Zielwebsite eingeben

Geben Sie die URL der Zielwebsite ein, die Sie klonen möchten.

#### Schritt 6: Option "Site Cloner" konfigurieren

Konfigurieren Sie den Site Cloner, indem Sie die gewünschten Einstellungen für den Klonprozess festlegen. Dies umfasst die Auswahl des Speicherorts für die geklonte Website und die Festlegung des Phishing-Angriffs.

#### Schritt 7: Phishing-Angriff durchführen

Führen Sie den Phishing-Angriff durch, indem Sie den generierten Link an die potenziellen Opfer senden. Wenn sie auf den Link klicken und ihre Anmeldedaten eingeben, werden diese Informationen in einer Datei gespeichert, die Sie später abrufen können.

#### Schritt 8: Zugriff auf die erfassten Anmeldedaten

Greifen Sie auf die erfassten Anmeldedaten zu, indem Sie die entsprechende Datei im SET-Verzeichnis öffnen.

Das Klonen einer Website ist eine effektive Methode, um an vertrauliche Informationen zu gelangen. Es ist jedoch wichtig zu beachten, dass Phishing-Angriffe illegal sind und nur zu Bildungszwecken oder mit ausdrücklicher Zustimmung des Eigentümers der Zielwebsite durchgeführt werden sollten.
```bash
#https://github.com/trustedsec/social-engineer-toolkit
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
