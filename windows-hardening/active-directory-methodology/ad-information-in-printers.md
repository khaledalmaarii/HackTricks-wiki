<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>


Es gibt mehrere Blogs im Internet, die **die Gefahren aufzeigen, Drucker mit LDAP und Standard-/schwachen Anmeldeinformationen zu konfigurieren**.\
Dies liegt daran, dass ein Angreifer den Drucker dazu bringen könnte, sich gegen einen gefälschten LDAP-Server zu authentifizieren (in der Regel reicht ein `nc -vv -l -p 444` aus) und die Druckeranmeldeinformationen **im Klartext zu erfassen**.

Darüber hinaus enthalten mehrere Drucker **Protokolle mit Benutzernamen** oder können sogar in der Lage sein, **alle Benutzernamen** vom Domänencontroller herunterzuladen.

All diese **sensiblen Informationen** und das häufige **Fehlen von Sicherheitsmaßnahmen** machen Drucker für Angreifer sehr interessant.

Einige Blogs zu diesem Thema:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Druckerkonfiguration
- **Standort**: Die Liste der LDAP-Server befindet sich unter: `Netzwerk > LDAP-Einstellung > LDAP-Einrichtung`.
- **Verhalten**: Die Benutzeroberfläche ermöglicht LDAP-Serveränderungen ohne erneute Eingabe von Anmeldeinformationen, um den Benutzerkomfort zu erhöhen, birgt jedoch Sicherheitsrisiken.
- **Ausnutzung**: Die Ausnutzung besteht darin, die LDAP-Serveradresse auf eine kontrollierte Maschine umzuleiten und die Funktion "Verbindung testen" zu nutzen, um Anmeldeinformationen zu erfassen.

## Erfassen von Anmeldeinformationen

**Für detailliertere Schritte siehe die ursprüngliche [Quelle](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Methode 1: Netcat-Listener
Ein einfacher Netcat-Listener könnte ausreichen:
```bash
sudo nc -k -v -l -p 386
```
### Methode 2: Vollständiger LDAP-Server mit Slapd
Ein zuverlässigerer Ansatz besteht darin, einen vollständigen LDAP-Server einzurichten, da der Drucker eine Nullbindung gefolgt von einer Abfrage durchführt, bevor er eine Anmeldebindung versucht.

1. **Einrichtung des LDAP-Servers**: Die Anleitung folgt den Schritten aus [dieser Quelle](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Wichtige Schritte**:
- OpenLDAP installieren.
- Admin-Passwort konfigurieren.
- Grundlegende Schemas importieren.
- Domänenname in der LDAP-Datenbank festlegen.
- LDAP TLS konfigurieren.
3. **Ausführung des LDAP-Dienstes**: Sobald eingerichtet, kann der LDAP-Dienst mit folgendem Befehl ausgeführt werden:
```bash
slapd -d 2
```
## Referenzen
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
