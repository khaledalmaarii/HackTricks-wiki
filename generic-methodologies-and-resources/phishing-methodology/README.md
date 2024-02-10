# Phishing-Methodik

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Methodik

1. Opfer erkunden
1. Wählen Sie die **Opferdomäne** aus.
2. Führen Sie eine grundlegende Web-Enumeration durch, indem Sie nach Anmeldeportalen suchen, die vom Opfer verwendet werden, und entscheiden Sie, welches Sie **imitieren** werden.
3. Verwenden Sie einige **OSINT**, um E-Mails zu **finden**.
2. Umgebung vorbereiten
1. **Kaufen Sie die Domain**, die Sie für die Phishing-Bewertung verwenden werden.
2. **Konfigurieren Sie den E-Mail-Dienst** in Bezug auf die Aufzeichnungen (SPF, DMARC, DKIM, rDNS)
3. Konfigurieren Sie den VPS mit **gophish**
3. Kampagne vorbereiten
1. Bereiten Sie die **E-Mail-Vorlage** vor.
2. Bereiten Sie die **Webseite** vor, um die Anmeldeinformationen zu stehlen.
4. Starten Sie die Kampagne!

## Generieren Sie ähnliche Domainnamen oder kaufen Sie eine vertrauenswürdige Domain

### Techniken zur Variation des Domainnamens

* **Schlüsselwort**: Der Domainname enthält ein wichtiges **Schlüsselwort** der Originaldomain (z. B. zelster.com-management.com).
* **Bindestrich-Subdomäne**: Ändern Sie den **Punkt durch einen Bindestrich** einer Subdomäne (z. B. www-zelster.com).
* **Neue TLD**: Gleiche Domain mit einer **neuen TLD** (z. B. zelster.org)
* **Homoglyph**: Es ersetzt einen Buchstaben im Domainnamen durch **Buchstaben, die ähnlich aussehen** (z. B. zelfser.com).
* **Transposition**: Es tauscht zwei Buchstaben im Domainnamen aus (z. B. zelster.com).
* **Singularisierung/Pluralisierung**: Fügt am Ende des Domainnamens ein "s" hinzu oder entfernt es (z. B. zeltsers.com).
* **Auslassung**: Es entfernt einen der Buchstaben aus dem Domainnamen (z. B. zelser.com).
* **Wiederholung**: Es wiederholt einen der Buchstaben im Domainnamen (z. B. zeltsser.com).
* **Ersetzung**: Ähnlich wie Homoglyph, aber weniger unauffällig. Es ersetzt einen der Buchstaben im Domainnamen, möglicherweise durch einen Buchstaben in der Nähe des Originalbuchstabens auf der Tastatur (z. B. zektser.com).
* **Subdomäne**: Führen Sie einen **Punkt** im Domainnamen ein (z. B. ze.lster.com).
* **Einfügung**: Es fügt einen Buchstaben in den Domainnamen ein (z. B. zerltser.com).
* **Fehlender Punkt**: Hängen Sie die TLD an den Domainnamen an. (z. B. zelstercom.com)

**Automatische Tools**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Es besteht die **Möglichkeit, dass eines der gespeicherten Bits oder Bits in der Kommunikation automatisch umgedreht** wird, aufgrund verschiedener Faktoren wie Sonneneruptionen, kosmische Strahlung oder Hardwarefehler.

Wenn dieses Konzept auf DNS-Anfragen angewendet wird, ist es möglich, dass die vom DNS-Server empfangene **Domain nicht mit der ursprünglich angeforderten Domain übereinstimmt**.

Beispielsweise kann eine einzelne Bit-Änderung in der Domain "windows.com" diese in "windnws.com" ändern.

Angreifer können dies ausnutzen, indem sie mehrere Bit-Flipping-Domains registrieren, die der Domain des Opfers ähnlich sind. Ihre Absicht besteht darin, legitime Benutzer auf ihre eigene Infrastruktur umzuleiten.

Weitere Informationen finden Sie unter [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kauf einer vertrauenswürdigen Domain

Sie können auf [https://www.expireddomains.net/](https://www.expireddomains.net) nach einer abgelaufenen Domain suchen, die Sie verwenden könnten.\
Um sicherzustellen, dass die abgelaufene Domain, die Sie kaufen möchten, **bereits eine gute SEO hat**, können Sie überprüfen, wie sie kategorisiert ist:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## E-Mails entdecken

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% kostenlos)
* [https://phonebook.cz/](https://phonebook.cz) (100% kostenlos)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Um weitere gültige E-Mail-Adressen zu **entdecken** oder die bereits entdeckten zu **überprüfen**, können Sie überprüfen, ob Sie die SMTP-Server des Opfers per Brute-Force angreifen können. [Erfahren Sie hier, wie Sie E-Mail-Adressen überprüfen/entdecken können](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Vergessen Sie außerdem nicht, dass Sie, wenn die Benutzer **ein Webportal verwenden, um auf ihre E-Mails zuzugreifen**, überprüfen können, ob es anfällig für **Benutzernamen-Brute-Force** ist, und die Schwachstelle bei Bedarf ausnutzen können.

## Konfigurieren von GoPhish

### Installation

Sie können es von [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) herunterladen.

Laden Sie es herunter und entpacken Sie es in `/opt/gophish` und führen Sie `/opt/gophish/gophish` aus.\
Ihnen wird ein Passwort für den Admin-Benutzer auf Port 3333 in der Ausgabe angezeigt. Greifen Sie daher auf diesen Port zu und verwenden Sie diese Anmeldeinformationen, um das Admin-Passwort zu ändern. Möglicherweise müssen Sie diesen Port auf local tunneln:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguration

**Konfiguration des TLS-Zertifikats**

Vor diesem Schritt sollten Sie bereits die **Domain gekauft** haben, die Sie verwenden möchten, und sie muss auf die **IP des VPS** zeigen, auf dem Sie **gophish** konfigurieren.
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**Mail-Konfiguration**

Beginnen Sie mit der Installation: `apt-get install postfix`

Fügen Sie dann die Domain zu den folgenden Dateien hinzu:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

Ändern Sie auch die Werte der folgenden Variablen in der Datei **/etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Ändern Sie schließlich die Dateien **`/etc/hostname`** und **`/etc/mailname`** auf Ihren Domain-Namen und **starten Sie Ihren VPS neu.**

Erstellen Sie nun einen **DNS A-Eintrag** für `mail.<domain>`, der auf die **IP-Adresse** des VPS zeigt, und einen **DNS MX-Eintrag**, der auf `mail.<domain>` zeigt.

Nun testen wir das Senden einer E-Mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish-Konfiguration**

Stoppen Sie die Ausführung von Gophish und konfigurieren Sie es.\
Ändern Sie `/opt/gophish/config.json` wie folgt (beachten Sie die Verwendung von https):
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**Konfigurieren Sie den Gophish-Dienst**

Um den Gophish-Dienst zu erstellen, damit er automatisch gestartet und als Dienst verwaltet werden kann, können Sie die Datei `/etc/init.d/gophish` mit dem folgenden Inhalt erstellen:
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
Beenden Sie die Konfiguration des Dienstes und überprüfen Sie ihn, indem Sie Folgendes tun:
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## Konfiguration des Mail-Servers und der Domain

### Warten und legitim sein

Je älter eine Domain ist, desto unwahrscheinlicher ist es, dass sie als Spam erkannt wird. Daher sollten Sie so lange wie möglich warten (mindestens 1 Woche), bevor Sie die Phishing-Bewertung durchführen. Darüber hinaus wird die Reputation besser, wenn Sie eine Seite über einen reputablen Sektor erstellen.

Beachten Sie, dass Sie trotzdem alles jetzt konfigurieren können, auch wenn Sie eine Woche warten müssen.

### Reverse DNS (rDNS) Eintrag konfigurieren

Legen Sie einen rDNS (PTR) Eintrag fest, der die IP-Adresse des VPS in den Domainnamen auflöst.

### Sender Policy Framework (SPF) Eintrag

Sie müssen **einen SPF-Eintrag für die neue Domain konfigurieren**. Wenn Sie nicht wissen, was ein SPF-Eintrag ist, [**lesen Sie diese Seite**](../../network-services-pentesting/pentesting-smtp/#spf).

Sie können [https://www.spfwizard.net/](https://www.spfwizard.net) verwenden, um Ihre SPF-Richtlinie zu generieren (verwenden Sie die IP-Adresse der VPS-Maschine).

![](<../../.gitbook/assets/image (388).png>)

Dies ist der Inhalt, der in einem TXT-Eintrag innerhalb der Domain festgelegt werden muss:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### DMARC-Eintrag (Domain-based Message Authentication, Reporting & Conformance)

Sie müssen **einen DMARC-Eintrag für die neue Domain konfigurieren**. Wenn Sie nicht wissen, was ein DMARC-Eintrag ist, [**lesen Sie diese Seite**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Sie müssen einen neuen DNS TXT-Eintrag erstellen, der auf den Hostnamen `_dmarc.<domain>` verweist, mit folgendem Inhalt:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Sie müssen **eine DKIM für die neue Domain konfigurieren**. Wenn Sie nicht wissen, was ein DMARC-Eintrag ist, [**lesen Sie diese Seite**](../../network-services-pentesting/pentesting-smtp/#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Sie müssen beide B64-Werte, die der DKIM-Schlüssel generiert, verketten:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Testen Sie Ihre E-Mail-Konfiguration

Sie können dies mit [https://www.mail-tester.com/](https://www.mail-tester.com) tun.\
Greifen Sie einfach auf die Seite zu und senden Sie eine E-Mail an die Ihnen gegebene Adresse:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Sie können auch **Ihre E-Mail-Konfiguration überprüfen**, indem Sie eine E-Mail an `check-auth@verifier.port25.com` senden und **die Antwort lesen** (hierfür müssen Sie den Port **25** öffnen und die Antwort in der Datei _/var/mail/root_ überprüfen, wenn Sie die E-Mail als root senden).\
Stellen Sie sicher, dass Sie alle Tests bestehen:
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
Sie können auch eine **Nachricht an ein von Ihnen kontrolliertes Gmail-Konto** senden und die **Header der E-Mail** in Ihrem Gmail-Posteingang überprüfen. `dkim=pass` sollte im Header-Feld `Authentication-Results` vorhanden sein.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Entfernen aus der Spamhaus-Blacklist

Die Seite [www.mail-tester.com](www.mail-tester.com) kann Ihnen anzeigen, ob Ihre Domain von Spamhaus blockiert wird. Sie können Ihre Domain/IP unter [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/) entfernen lassen.

### Entfernen aus der Microsoft-Blacklist

Sie können Ihre Domain/IP unter [https://sender.office.com/](https://sender.office.com) entfernen lassen.

## GoPhish-Kampagne erstellen und starten

### Versandprofil

* Geben Sie einen **Namen zur Identifizierung** des Absenderprofils ein.
* Entscheiden Sie, von welchem Konto aus Sie die Phishing-E-Mails senden möchten. Vorschläge: _noreply, support, servicedesk, salesforce..._
* Sie können Benutzername und Passwort leer lassen, stellen Sie jedoch sicher, dass Sie die Option "Zertifikatsfehler ignorieren" aktiviert haben.

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
Es wird empfohlen, die Funktion "**Test-E-Mail senden**" zu verwenden, um zu überprüfen, ob alles funktioniert.\
Ich empfehle, die Test-E-Mails an 10-Minuten-E-Mail-Adressen zu senden, um zu vermeiden, dass Sie beim Testen auf die Blacklist gesetzt werden.
{% endhint %}

### E-Mail-Vorlage

* Geben Sie einen **Namen zur Identifizierung** der Vorlage ein.
* Schreiben Sie dann einen **Betreff** (nichts Außergewöhnliches, nur etwas, das Sie in einer regulären E-Mail erwarten würden).
* Stellen Sie sicher, dass Sie "**Tracking-Bild hinzufügen**" aktiviert haben.
* Schreiben Sie die **E-Mail-Vorlage** (Sie können Variablen verwenden, wie im folgenden Beispiel):
```markup
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
Hinweis: **Um die Glaubwürdigkeit der E-Mail zu erhöhen**, wird empfohlen, eine Signatur aus einer E-Mail des Kunden zu verwenden. Vorschläge:

* Senden Sie eine E-Mail an eine **nicht existierende Adresse** und prüfen Sie, ob die Antwort eine Signatur enthält.
* Suchen Sie nach **öffentlichen E-Mails** wie info@ex.com oder press@ex.com oder public@ex.com und senden Sie ihnen eine E-Mail und warten Sie auf die Antwort.
* Versuchen Sie, **eine gültige entdeckte** E-Mail zu kontaktieren und warten Sie auf die Antwort.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
Die E-Mail-Vorlage ermöglicht auch das **Anhängen von Dateien zum Versenden**. Wenn Sie auch NTLM-Herausforderungen stehlen möchten, indem Sie speziell erstellte Dateien/Dokumente verwenden, [lesen Sie diese Seite](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Zielseite

* Geben Sie einen **Namen** ein.
* **Schreiben Sie den HTML-Code** der Webseite. Beachten Sie, dass Sie Webseiten **importieren** können.
* Markieren Sie **Erfasste übermittelte Daten** und **Erfasste Passwörter**.
* Legen Sie eine **Weiterleitung** fest.

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Normalerweise müssen Sie den HTML-Code der Seite ändern und einige Tests lokal durchführen (vielleicht mit einem Apache-Server), **bis Ihnen die Ergebnisse gefallen**. Schreiben Sie dann diesen HTML-Code in das Feld.\
Beachten Sie, dass Sie, wenn Sie **statische Ressourcen** für das HTML benötigen (vielleicht einige CSS- und JS-Seiten), diese unter _**/opt/gophish/static/endpoint**_ speichern und dann über _**/static/\<filename>**_ darauf zugreifen können.
{% endhint %}

{% hint style="info" %}
Bei der Weiterleitung könnten Sie die Benutzer **auf die legitime Hauptwebseite** des Opfers umleiten oder sie zum Beispiel auf _/static/migration.html_ umleiten, einen **drehenden Kreis** ([**https://loading.io/**](https://loading.io)) für 5 Sekunden anzeigen und dann angeben, dass der Vorgang erfolgreich war.
{% endhint %}

### Benutzer & Gruppen

* Geben Sie einen Namen ein.
* **Importieren Sie die Daten** (beachten Sie, dass Sie für die Verwendung der Vorlage für das Beispiel den Vornamen, Nachnamen und die E-Mail-Adresse jedes Benutzers benötigen).

![](<../../.gitbook/assets/image (395).png>)

### Kampagne

Erstellen Sie schließlich eine Kampagne, indem Sie einen Namen, die E-Mail-Vorlage, die Zielseite, die URL, das Versandprofil und die Gruppe auswählen. Beachten Sie, dass die URL der Link ist, der an die Opfer gesendet wird.

Beachten Sie, dass das **Versandprofil ermöglicht, eine Test-E-Mail zu senden, um zu sehen, wie die endgültige Phishing-E-Mail aussieht**:

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Ich würde empfehlen, die Test-E-Mails an 10-Minuten-E-Mail-Adressen zu senden, um zu vermeiden, dass Sie beim Testen auf die schwarze Liste gesetzt werden.
{% endhint %}

Sobald alles bereit ist, starten Sie einfach die Kampagne!

## Website-Klonen

Wenn Sie aus irgendeinem Grund die Website klonen möchten, überprüfen Sie die folgende Seite:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Backdoored-Dokumente & Dateien

Bei einigen Phishing-Bewertungen (hauptsächlich für Red Teams) möchten Sie möglicherweise auch **Dateien senden, die eine Art Hintertür enthalten** (vielleicht eine C2 oder einfach etwas, das eine Authentifizierung auslöst).\
Schauen Sie sich die folgende Seite für einige Beispiele an:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Über Proxy MitM

Der vorherige Angriff ist ziemlich clever, da Sie eine echte Website vortäuschen und die vom Benutzer festgelegten Informationen sammeln. Leider ermöglichen Ihnen diese Informationen nicht, den getäuschten Benutzer zu impersonieren, wenn er das falsche Passwort eingegeben hat oder wenn die von Ihnen gefälschte Anwendung mit 2FA konfiguriert ist.

Hier kommen Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) ins Spiel. Dieses Tool ermöglicht es Ihnen, einen MitM-ähnlichen Angriff zu generieren. Im Wesentlichen funktioniert der Angriff folgendermaßen:

1. Sie **täuschen das Login**-Formular der echten Webseite vor.
2. Der Benutzer **sendet** seine **Anmeldeinformationen** an Ihre gefälschte Seite und das Tool sendet sie an die echte Webseite, **um zu überprüfen, ob die Anmeldeinformationen funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, fordert die MitM-Seite die Eingabe auf und sobald der **Benutzer sie eingibt**, sendet das Tool sie an die echte Webseite.
4. Sobald der Benutzer authentifiziert ist, haben Sie (als Angreifer) **die Anmeldeinformationen, die 2FA, das Cookie und alle Informationen** jeder Interaktion erfasst, während das Tool einen MitM durchführt.

### Über VNC

Was ist, wenn Sie den Benutzer anstelle einer bösartigen Seite, die genauso aussieht wie die Originalseite, zu einer **VNC-Sitzung mit einem Browser, der mit der echten Webseite verbunden ist**, senden? Sie können sehen, was er tut, das Passwort stehlen, die verwendete MFA, die Cookies...\
Dies können Sie mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) tun.

## Erkennen der Erkennung

Offensichtlich ist eine der besten Möglichkeiten zu wissen, ob Sie erwischt wurden, das **Suchen Ihres Domänennamens in Blacklists**. Wenn er dort aufgeführt ist, wurde Ihre Domäne irgendwie als verdächtig erkannt.\
Eine einfache Möglichkeit, zu überprüfen, ob Ihre Domäne in einer Blacklist aufgeführt ist, besteht darin, [https://malwareworld.com/](https://malwareworld.com) zu verwenden.

Es gibt jedoch andere Möglichkeiten zu wissen, ob das Opfer **aktiv nach verdächtiger Phishing-Aktivität im Internet sucht**, wie in folgendem Abschnitt erklärt:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Sie können eine Domain mit einem sehr ähnlichen Namen wie der Domain des Opfers **kaufen** und/oder ein Zertifikat für eine **Subdomain** einer von Ihnen kontrollierten Domain **generieren**, die das **Schlüsselwort** der Domain des Opfers enthält. Wenn das **Opfer** eine Art **DNS- oder HTTP-Interaktion** mit ihnen durchführt, wissen Sie, dass **es aktiv nach verdächtigen Domänen sucht**, und Sie müssen sehr unauffällig sein.

### Bewertung des Phishings

Verwenden Sie [**Phishious**](https://github.com/Rices/Phishious), um zu bewerten, ob Ihre E-Mail im Spam-Ordner landet oder ob sie blockiert oder erfolgreich ist.

## Referenzen

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-
