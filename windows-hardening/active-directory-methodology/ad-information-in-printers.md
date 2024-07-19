{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


Es gibt mehrere Blogs im Internet, die **die Gefahren hervorheben, wenn Drucker mit LDAP und Standard-/schwachen** Anmeldeinformationen konfiguriert sind.\
Das liegt daran, dass ein Angreifer **den Drucker dazu bringen könnte, sich gegen einen bösartigen LDAP-Server zu authentifizieren** (typischerweise reicht ein `nc -vv -l -p 444`) und die Drucker-**Anmeldeinformationen im Klartext** abzufangen.

Außerdem enthalten mehrere Drucker **Protokolle mit Benutzernamen** oder könnten sogar in der Lage sein, **alle Benutzernamen** vom Domänencontroller herunterzuladen.

All diese **sensiblen Informationen** und der allgemeine **Mangel an Sicherheit** machen Drucker für Angreifer sehr interessant.

Einige Blogs zu diesem Thema:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Druckerkonfiguration
- **Standort**: Die LDAP-Serverliste befindet sich unter: `Netzwerk > LDAP-Einstellungen > LDAP einrichten`.
- **Verhalten**: Die Benutzeroberfläche ermöglicht Änderungen am LDAP-Server, ohne die Anmeldeinformationen erneut einzugeben, was die Benutzerfreundlichkeit erhöht, aber Sicherheitsrisiken birgt.
- **Ausnutzung**: Die Ausnutzung besteht darin, die LDAP-Serveradresse auf eine kontrollierte Maschine umzuleiten und die Funktion "Verbindung testen" zu nutzen, um Anmeldeinformationen abzufangen.

## Anmeldeinformationen abfangen

**Für detailliertere Schritte siehe die ursprüngliche [Quelle](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Methode 1: Netcat Listener
Ein einfacher Netcat-Listener könnte ausreichen:
```bash
sudo nc -k -v -l -p 386
```
Allerdings variiert der Erfolg dieser Methode.

### Methode 2: Vollständiger LDAP-Server mit Slapd
Ein zuverlässigerer Ansatz besteht darin, einen vollständigen LDAP-Server einzurichten, da der Drucker eine Nullbindung durchführt, gefolgt von einer Abfrage, bevor er versucht, eine Anmeldeinformation zu binden.

1. **LDAP-Server-Einrichtung**: Der Leitfaden folgt den Schritten aus [dieser Quelle](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Wichtige Schritte**:
- OpenLDAP installieren.
- Admin-Passwort konfigurieren.
- Grundlegende Schemata importieren.
- Domainnamen in der LDAP-Datenbank festlegen.
- LDAP TLS konfigurieren.
3. **Ausführung des LDAP-Dienstes**: Nach der Einrichtung kann der LDAP-Dienst mit folgendem Befehl ausgeführt werden:
```bash
slapd -d 2
```
## Referenzen
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
