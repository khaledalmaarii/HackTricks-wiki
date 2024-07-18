# Phishing Methodology

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

## Methodology

1. Recon die Zielperson
1. Wählen Sie die **Zieldomain**.
2. Führen Sie eine grundlegende Webenumeration durch, **um nach Anmeldeportalen** zu suchen, die von der Zielperson verwendet werden, und **entscheiden** Sie, welches Sie **nachahmen** möchten.
3. Verwenden Sie einige **OSINT**, um **E-Mails zu finden**.
2. Bereiten Sie die Umgebung vor
1. **Kaufen Sie die Domain**, die Sie für die Phishing-Bewertung verwenden möchten.
2. **Konfigurieren Sie die E-Mail-Dienste** bezogene Datensätze (SPF, DMARC, DKIM, rDNS).
3. Konfigurieren Sie den VPS mit **gophish**.
3. Bereiten Sie die Kampagne vor
1. Bereiten Sie die **E-Mail-Vorlage** vor.
2. Bereiten Sie die **Webseite** vor, um die Anmeldedaten zu stehlen.
4. Starten Sie die Kampagne!

## Generieren Sie ähnliche Domainnamen oder kaufen Sie eine vertrauenswürdige Domain

### Techniken zur Variation von Domainnamen

* **Schlüsselwort**: Der Domainname **enthält** ein wichtiges **Schlüsselwort** der ursprünglichen Domain (z.B. zelster.com-management.com).
* **getrennter Subdomain**: Ändern Sie den **Punkt in einen Bindestrich** einer Subdomain (z.B. www-zelster.com).
* **Neue TLD**: Dieselbe Domain mit einer **neuen TLD** (z.B. zelster.org).
* **Homoglyph**: Es **ersetzt** einen Buchstaben im Domainnamen durch **Buchstaben, die ähnlich aussehen** (z.B. zelfser.com).
* **Transposition:** Es **tauscht zwei Buchstaben** innerhalb des Domainnamens (z.B. zelsetr.com).
* **Singularisierung/Pluralisierung**: Fügt ein „s“ am Ende des Domainnamens hinzu oder entfernt es (z.B. zeltsers.com).
* **Auslassung**: Es **entfernt einen** der Buchstaben aus dem Domainnamen (z.B. zelser.com).
* **Wiederholung:** Es **wiederholt einen** der Buchstaben im Domainnamen (z.B. zeltsser.com).
* **Ersetzung**: Wie Homoglyph, aber weniger heimlich. Es ersetzt einen der Buchstaben im Domainnamen, möglicherweise durch einen Buchstaben in der Nähe des ursprünglichen Buchstabens auf der Tastatur (z.B. zektser.com).
* **Subdominiert**: Fügen Sie einen **Punkt** innerhalb des Domainnamens ein (z.B. ze.lster.com).
* **Einfügung**: Es **fügt einen Buchstaben** in den Domainnamen ein (z.B. zerltser.com).
* **Fehlender Punkt**: Hängen Sie die TLD an den Domainnamen an. (z.B. zelstercom.com)

**Automatische Werkzeuge**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webseiten**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Es besteht die **Möglichkeit, dass einige Bits, die gespeichert oder in Kommunikation sind, automatisch umgeschaltet werden** aufgrund verschiedener Faktoren wie Sonnenstürme, kosmische Strahlen oder Hardwarefehler.

Wenn dieses Konzept auf DNS-Anfragen **angewendet wird**, ist es möglich, dass die **Domain, die vom DNS-Server empfangen wird**, nicht die gleiche ist wie die ursprünglich angeforderte Domain.

Zum Beispiel kann eine einzige Bitänderung in der Domain "windows.com" sie in "windnws.com" ändern.

Angreifer können **dies ausnutzen, indem sie mehrere Bit-Flipping-Domains registrieren**, die der Domain des Opfers ähnlich sind. Ihre Absicht ist es, legitime Benutzer auf ihre eigene Infrastruktur umzuleiten.

Für weitere Informationen lesen Sie [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kaufen Sie eine vertrauenswürdige Domain

Sie können auf [https://www.expireddomains.net/](https://www.expireddomains.net) nach einer abgelaufenen Domain suchen, die Sie verwenden könnten.\
Um sicherzustellen, dass die abgelaufene Domain, die Sie kaufen möchten, **bereits eine gute SEO hat**, können Sie nachsehen, wie sie kategorisiert ist in:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Entdecken von E-Mails

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% kostenlos)
* [https://phonebook.cz/](https://phonebook.cz) (100% kostenlos)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Um **mehr** gültige E-Mail-Adressen zu **entdecken** oder die bereits entdeckten zu **verifizieren**, können Sie überprüfen, ob Sie die SMTP-Server des Opfers brute-forcen können. [Erfahren Sie hier, wie Sie E-Mail-Adressen verifizieren/entdecken](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Vergessen Sie außerdem nicht, dass, wenn die Benutzer **ein beliebiges Webportal verwenden, um auf ihre E-Mails zuzugreifen**, Sie überprüfen können, ob es anfällig für **Benutzername-Brute-Force** ist, und die Schwachstelle, wenn möglich, ausnutzen.

## Konfigurieren von GoPhish

### Installation

Sie können es von [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) herunterladen.

Laden Sie es herunter und entpacken Sie es in `/opt/gophish` und führen Sie `/opt/gophish/gophish` aus.\
Sie erhalten ein Passwort für den Admin-Benutzer auf Port 3333 in der Ausgabe. Greifen Sie daher auf diesen Port zu und verwenden Sie diese Anmeldeinformationen, um das Admin-Passwort zu ändern. Möglicherweise müssen Sie diesen Port auf lokal tunneln:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguration

**TLS-Zertifikat-Konfiguration**

Bevor Sie diesen Schritt ausführen, sollten Sie **bereits die Domain** gekauft haben, die Sie verwenden möchten, und sie muss auf die **IP des VPS** zeigen, auf dem Sie **gophish** konfigurieren.
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

Starten Sie die Installation: `apt-get install postfix`

Fügen Sie dann die Domain zu den folgenden Dateien hinzu:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Ändern Sie auch die Werte der folgenden Variablen in /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Schließlich ändern Sie die Dateien **`/etc/hostname`** und **`/etc/mailname`** in Ihren Domainnamen und **starten Sie Ihren VPS neu.**

Erstellen Sie nun einen **DNS A-Eintrag** von `mail.<domain>`, der auf die **IP-Adresse** des VPS zeigt, und einen **DNS MX**-Eintrag, der auf `mail.<domain>` zeigt.

Jetzt testen wir, um eine E-Mail zu senden:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish-Konfiguration**

Stoppen Sie die Ausführung von gophish und lassen Sie uns es konfigurieren.\
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
**Gophish-Dienst konfigurieren**

Um den Gophish-Dienst zu erstellen, damit er automatisch gestartet und als Dienst verwaltet werden kann, können Sie die Datei `/etc/init.d/gophish` mit folgendem Inhalt erstellen:
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
Fahren Sie fort mit der Konfiguration des Dienstes und überprüfen Sie ihn, indem Sie:
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
## Konfigurieren des Mailservers und der Domain

### Warten & legitim sein

Je älter eine Domain ist, desto unwahrscheinlicher ist es, dass sie als Spam erkannt wird. Daher sollten Sie so viel Zeit wie möglich warten (mindestens 1 Woche) vor der Phishing-Bewertung. Darüber hinaus wird die Reputation besser, wenn Sie eine Seite über einen reputationswürdigen Sektor erstellen.

Beachten Sie, dass Sie, auch wenn Sie eine Woche warten müssen, jetzt alles konfigurieren können.

### Konfigurieren des Reverse DNS (rDNS) Eintrags

Setzen Sie einen rDNS (PTR) Eintrag, der die IP-Adresse des VPS auf den Domainnamen auflöst.

### Sender Policy Framework (SPF) Eintrag

Sie müssen **einen SPF-Eintrag für die neue Domain konfigurieren**. Wenn Sie nicht wissen, was ein SPF-Eintrag ist, [**lesen Sie diese Seite**](../../network-services-pentesting/pentesting-smtp/#spf).

Sie können [https://www.spfwizard.net/](https://www.spfwizard.net) verwenden, um Ihre SPF-Richtlinie zu generieren (verwenden Sie die IP der VPS-Maschine).

![](<../../.gitbook/assets/image (1037).png>)

Dies ist der Inhalt, der in einem TXT-Eintrag innerhalb der Domain gesetzt werden muss:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

Sie müssen **einen DMARC-Eintrag für die neue Domain konfigurieren**. Wenn Sie nicht wissen, was ein DMARC-Eintrag ist, [**lesen Sie diese Seite**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Sie müssen einen neuen DNS TXT-Eintrag erstellen, der auf den Hostnamen `_dmarc.<domain>` mit folgendem Inhalt zeigt:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Sie müssen **ein DKIM für die neue Domain konfigurieren**. Wenn Sie nicht wissen, was ein DMARC-Eintrag ist, [**lesen Sie diese Seite**](../../network-services-pentesting/pentesting-smtp/#dkim).

Dieses Tutorial basiert auf: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Sie müssen beide B64-Werte, die der DKIM-Schlüssel generiert, verketten:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Testen Sie Ihre E-Mail-Konfigurationsbewertung

Sie können dies tun, indem Sie [https://www.mail-tester.com/](https://www.mail-tester.com)\
Greifen Sie einfach auf die Seite zu und senden Sie eine E-Mail an die Adresse, die sie Ihnen geben:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Sie können auch **Ihre E-Mail-Konfiguration überprüfen**, indem Sie eine E-Mail an `check-auth@verifier.port25.com` senden und **die Antwort lesen** (dafür müssen Sie den Port **25** **öffnen** und die Antwort in der Datei _/var/mail/root_ sehen, wenn Sie die E-Mail als root senden).\
Überprüfen Sie, ob Sie alle Tests bestehen:
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
Sie könnten auch eine **Nachricht an ein Gmail unter Ihrer Kontrolle** senden und die **E-Mail-Header** in Ihrem Gmail-Posteingang überprüfen. `dkim=pass` sollte im `Authentication-Results` Headerfeld vorhanden sein.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Entfernen von der Spamhaus-Blacklist

Die Seite [www.mail-tester.com](https://www.mail-tester.com) kann Ihnen anzeigen, ob Ihre Domain von Spamhaus blockiert wird. Sie können anfordern, dass Ihre Domain/IP entfernt wird unter: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Entfernen von der Microsoft-Blacklist

​​Sie können anfordern, dass Ihre Domain/IP entfernt wird unter [https://sender.office.com/](https://sender.office.com).

## Erstellen & Starten einer GoPhish-Kampagne

### Versandprofil

* Setzen Sie einen **Namen zur Identifizierung** des Absenderprofils
* Entscheiden Sie, von welchem Konto Sie die Phishing-E-Mails senden werden. Vorschläge: _noreply, support, servicedesk, salesforce..._
* Sie können den Benutzernamen und das Passwort leer lassen, aber stellen Sie sicher, dass Sie die Option "Zertifikatfehler ignorieren" aktivieren.

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

{% hint style="info" %}
Es wird empfohlen, die Funktion "**Test-E-Mail senden**" zu verwenden, um zu testen, ob alles funktioniert.\
Ich würde empfehlen, **die Test-E-Mails an 10min-Mail-Adressen zu senden**, um zu vermeiden, dass Sie beim Testen auf die Blacklist gelangen.
{% endhint %}

### E-Mail-Vorlage

* Setzen Sie einen **Namen zur Identifizierung** der Vorlage
* Schreiben Sie dann einen **Betreff** (nichts Ungewöhnliches, nur etwas, das Sie in einer regulären E-Mail erwarten würden)
* Stellen Sie sicher, dass Sie "**Tracking-Bild hinzufügen**" aktiviert haben
* Schreiben Sie die **E-Mail-Vorlage** (Sie können Variablen wie im folgenden Beispiel verwenden):
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
Beachten Sie, dass **um die Glaubwürdigkeit der E-Mail zu erhöhen**, empfohlen wird, eine Signatur aus einer E-Mail des Kunden zu verwenden. Vorschläge:

* Senden Sie eine E-Mail an eine **nicht existierende Adresse** und überprüfen Sie, ob die Antwort eine Signatur enthält.
* Suchen Sie nach **öffentlichen E-Mails** wie info@ex.com oder press@ex.com oder public@ex.com und senden Sie ihnen eine E-Mail und warten Sie auf die Antwort.
* Versuchen Sie, **eine gültige entdeckte** E-Mail zu kontaktieren und warten Sie auf die Antwort.

![](<../../.gitbook/assets/image (80).png>)

{% hint style="info" %}
Die E-Mail-Vorlage ermöglicht es auch, **Dateien anzuhängen**. Wenn Sie auch NTLM-Herausforderungen mit speziell gestalteten Dateien/Dokumenten stehlen möchten, [lesen Sie diese Seite](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Landing Page

* Schreiben Sie einen **Namen**
* **Schreiben Sie den HTML-Code** der Webseite. Beachten Sie, dass Sie **Webseiten importieren** können.
* Markieren Sie **Eingereichte Daten erfassen** und **Passwörter erfassen**
* Setzen Sie eine **Weiterleitung**

![](<../../.gitbook/assets/image (826).png>)

{% hint style="info" %}
In der Regel müssen Sie den HTML-Code der Seite ändern und einige Tests lokal durchführen (vielleicht mit einem Apache-Server), **bis Ihnen die Ergebnisse gefallen.** Schreiben Sie dann diesen HTML-Code in das Feld.\
Beachten Sie, dass Sie, wenn Sie **statische Ressourcen** für das HTML verwenden müssen (vielleicht einige CSS- und JS-Seiten), diese in _**/opt/gophish/static/endpoint**_ speichern können und dann von _**/static/\<dateiname>**_ darauf zugreifen können.
{% endhint %}

{% hint style="info" %}
Für die Weiterleitung könnten Sie **die Benutzer zur legitimen Hauptwebseite** des Opfers weiterleiten oder sie beispielsweise zu _/static/migration.html_ umleiten, einen **Ladebildschirm** ([**https://loading.io/**](https://loading.io)**) für 5 Sekunden anzeigen und dann angeben, dass der Prozess erfolgreich war**.
{% endhint %}

### Benutzer & Gruppen

* Setzen Sie einen Namen
* **Importieren Sie die Daten** (beachten Sie, dass Sie die Vorlage für das Beispiel benötigen, um den Vornamen, Nachnamen und die E-Mail-Adresse jedes Benutzers zu verwenden)

![](<../../.gitbook/assets/image (163).png>)

### Kampagne

Erstellen Sie schließlich eine Kampagne, indem Sie einen Namen, die E-Mail-Vorlage, die Landing Page, die URL, das Versandprofil und die Gruppe auswählen. Beachten Sie, dass die URL der Link ist, der an die Opfer gesendet wird.

Beachten Sie, dass das **Versandprofil es ermöglicht, eine Test-E-Mail zu senden, um zu sehen, wie die endgültige Phishing-E-Mail aussieht**:

![](<../../.gitbook/assets/image (192).png>)

{% hint style="info" %}
Ich würde empfehlen, **die Test-E-Mails an 10min-Mail-Adressen zu senden**, um zu vermeiden, dass Sie beim Testen auf eine schwarze Liste gesetzt werden.
{% endhint %}

Sobald alles bereit ist, starten Sie einfach die Kampagne!

## Website-Klonen

Wenn Sie aus irgendeinem Grund die Website klonen möchten, überprüfen Sie die folgende Seite:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Hintertür-Dokumente & -Dateien

In einigen Phishing-Bewertungen (hauptsächlich für Red Teams) möchten Sie möglicherweise auch **Dateien senden, die eine Art von Hintertür enthalten** (vielleicht ein C2 oder vielleicht nur etwas, das eine Authentifizierung auslöst).\
Überprüfen Sie die folgende Seite für einige Beispiele:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Via Proxy MitM

Der vorherige Angriff ist ziemlich clever, da Sie eine echte Website fälschen und die Informationen sammeln, die der Benutzer eingibt. Leider, wenn der Benutzer das richtige Passwort nicht eingegeben hat oder wenn die gefälschte Anwendung mit 2FA konfiguriert ist, **erlaubt Ihnen diese Information nicht, den getäuschten Benutzer zu impersonieren**.

Hier sind Tools wie [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) und [**muraena**](https://github.com/muraenateam/muraena) nützlich. Dieses Tool ermöglicht es Ihnen, einen MitM-ähnlichen Angriff zu generieren. Grundsätzlich funktioniert der Angriff folgendermaßen:

1. Sie **imitieren das Anmeldeformular** der echten Webseite.
2. Der Benutzer **sendet** seine **Anmeldeinformationen** an Ihre gefälschte Seite und das Tool sendet diese an die echte Webseite, **um zu überprüfen, ob die Anmeldeinformationen funktionieren**.
3. Wenn das Konto mit **2FA** konfiguriert ist, wird die MitM-Seite danach fragen, und sobald der **Benutzer es eingibt**, sendet das Tool es an die echte Webseite.
4. Sobald der Benutzer authentifiziert ist, haben Sie (als Angreifer) die **Anmeldeinformationen, die 2FA, das Cookie und alle Informationen** jeder Interaktion erfasst, während das Tool einen MitM durchführt.

### Via VNC

Was wäre, wenn Sie anstatt **das Opfer auf eine bösartige Seite** mit dem gleichen Aussehen wie die Originalseite zu senden, ihn zu einer **VNC-Sitzung mit einem Browser, der mit der echten Webseite verbunden ist,** senden? Sie können sehen, was er tut, das Passwort, die verwendete MFA, die Cookies stehlen...\
Sie können dies mit [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) tun.

## Erkennung der Erkennung

Offensichtlich ist eine der besten Möglichkeiten zu wissen, ob Sie enttarnt wurden, **Ihre Domain in schwarzen Listen zu durchsuchen**. Wenn sie aufgeführt ist, wurde Ihre Domain irgendwie als verdächtig erkannt.\
Eine einfache Möglichkeit zu überprüfen, ob Ihre Domain in einer schwarzen Liste erscheint, ist die Verwendung von [https://malwareworld.com/](https://malwareworld.com).

Es gibt jedoch auch andere Möglichkeiten zu wissen, ob das Opfer **aktiv nach verdächtigen Phishing-Aktivitäten in der Wildnis sucht**, wie in:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Sie können **eine Domain mit einem sehr ähnlichen Namen** zur Domain des Opfers **kaufen und/oder ein Zertifikat** für einen **Subdomain** einer von Ihnen kontrollierten Domain **erstellen**, die das **Schlüsselwort** der Domain des Opfers enthält. Wenn das **Opfer** irgendeine Art von **DNS- oder HTTP-Interaktion** mit ihnen durchführt, wissen Sie, dass **es aktiv nach** verdächtigen Domains sucht und Sie sehr stealthy sein müssen.

### Phishing bewerten

Verwenden Sie [**Phishious** ](https://github.com/Rices/Phishious), um zu bewerten, ob Ihre E-Mail im Spam-Ordner landen wird oder ob sie blockiert oder erfolgreich sein wird.

## Referenzen

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
* [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
