# Metodologia Phishing

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Metodologia

1. Rozpoznaj ofiarę
1. Wybierz **domenę ofiary**.
2. Przeprowadź podstawową enumerację sieci web, **szukając portali logowania** używanych przez ofiarę i **zdecyduj**, który będziesz **udawać**.
3. Wykorzystaj **OSINT**, aby **znaleźć adresy e-mail**.
2. Przygotuj środowisko
1. **Kup domenę**, którą będziesz używać do oceny phishingowej
2. **Skonfiguruj usługę poczty e-mail** związane z rekordami (SPF, DMARC, DKIM, rDNS)
3. Skonfiguruj VPS z **gophish**
3. Przygotuj kampanię
1. Przygotuj **szablon e-maila**
2. Przygotuj **stronę internetową**, aby ukraść dane uwierzytelniające
4. Uruchom kampanię!

## Generowanie podobnych nazw domen lub zakup zaufanej domeny

### Techniki wariacji nazw domen

* **Słowo kluczowe**: Nazwa domeny **zawiera** ważne **słowo kluczowe** oryginalnej domeny (np. zelster.com-management.com).
* **Poddomena z myślnikiem**: Zmień **kropkę na myślnik** w poddomenie (np. www-zelster.com).
* **Nowe TLD**: Ta sama domena, ale z **nowym TLD** (np. zelster.org)
* **Homoglify**: Zastępuje literę w nazwie domeny **literami, które wyglądają podobnie** (np. zelfser.com).
* **Transpozycja**: Zamienia miejscami dwie litery w nazwie domeny (np. zelster.com).
* **Liczba pojedyncza/liczba mnoga**: Dodaje lub usuwa "s" na końcu nazwy domeny (np. zeltsers.com).
* **Pominięcie**: Usuwa jedną literę z nazwy domeny (np. zelser.com).
* **Powtórzenie**: Powtarza jedną literę w nazwie domeny (np. zeltsser.com).
* **Zastąpienie**: Podobne do homoglify, ale mniej skryte. Zastępuje jedną literę w nazwie domeny, być może literą w pobliżu oryginalnej litery na klawiaturze (np. zektser.com).
* **Poddomena**: Wprowadza **kropkę** wewnątrz nazwy domeny (np. ze.lster.com).
* **Wstawienie**: Wstawia literę do nazwy domeny (np. zerltser.com).
* **Brak kropki**: Dołącz TLD do nazwy domeny. (np. zelstercom.com)

**Automatyczne narzędzia**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Strony internetowe**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że jeden z niektórych bitów przechowywanych lub przesyłanych może automatycznie się odwrócić** z powodu różnych czynników, takich jak rozbłyski słoneczne, promieniowanie kosmiczne lub błędy sprzętowe.

Gdy ten koncept jest **zastosowany do żądań DNS**, możliwe jest, że **domena otrzymana przez serwer DNS** nie jest taka sama jak domena początkowo żądana.

Na przykład pojedyncza modyfikacja bitu w domenie "windows.com" może zmienić ją na "windnws.com".

Atakujący mogą **skorzystać z tego, rejestrując wiele domen z odwróconymi bitami**, które są podobne do domeny ofiary. Ich intencją jest przekierowanie prawowitych użytkowników do własnej infrastruktury.

Aby uzyskać więcej informacji, przeczytaj [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Kup zaufaną domenę

Możesz szukać na stronie [https://www.expireddomains.net/](https://www.expireddomains.net) po wygasłej domenie, którą możesz użyć.\
Aby upewnić się, że wygasła domena, którą zamierzasz kupić, **ma już dobrą optymalizację pod kątem SEO**, możesz sprawdzić, jak jest sklasyfikowana w:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Odkrywanie adresów e-mail

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% darmowe)
* [https://phonebook.cz/](https://phonebook.cz) (100% darmowe)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Aby **odkryć więcej** prawidłowych adresów e-mail lub **zweryfikować te**, które już odkryłeś, możesz sprawdzić, czy możesz przeprowadzić atak brute-force na serwery SMTP ofiary. [Dowiedz się, jak zweryfikować/odkryć adres e-mail tutaj](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Ponadto, nie zapomnij, że jeśli użytkownicy korzystają z **jakiejkolwiek strony internetowej do dostępu do swojej poczty**, możesz sprawdzić, czy jest podatna na **brute force nazwy użytkownika**, i wykorzystać tę podatność, jeśli to możliwe.

## Konfiguracja GoPhish

### Instalacja

Możesz go pobrać z [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz i rozpakuj go do folderu `/opt/gophish`, a następnie uruchom `/opt/gophish/gophish`\
Otrzymasz hasło dla użytkownika admin na porcie 3333 w wynikach. Następnie uzyskaj dostęp do tego portu i użyj tych danych uwierzytelniających, aby zmienić hasło administratora. Może być konieczne przekierowanie tego portu na lokalny:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed przystąpieniem do tego kroku powinieneś **już zakupić domenę**, którą zamierzasz użyć, a ta domena musi być **skierowana** na **adres IP VPS**, na którym konfigurujesz **gophish**.
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
**Konfiguracja poczty**

Rozpocznij instalację: `apt-get install postfix`

Następnie dodaj domenę do następujących plików:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Zmień również wartości następujących zmiennych w pliku /etc/postfix/main.cf**

`myhostname = <domena>`\
`mydestination = $myhostname, <domena>, localhost.com, localhost`

Na koniec zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`** na nazwę swojej domeny i **zrestartuj VPS.**

Teraz utwórz **rekord DNS A** dla `mail.<domena>`, wskazujący na **adres IP** VPS, oraz **rekord DNS MX** wskazujący na `mail.<domena>`

Teraz przetestuj wysłanie wiadomości e-mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj wykonanie Gophish i przystąp do konfiguracji.\
Zmodyfikuj `/opt/gophish/config.json` według poniższego wzoru (zwróć uwagę na użycie protokołu https):
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
**Konfiguracja usługi gophish**

Aby utworzyć usługę gophish, która może być uruchamiana automatycznie i zarządzana jako usługa, można utworzyć plik `/etc/init.d/gophish` o następującej zawartości:
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
Zakończ konfigurowanie usługi i sprawdź ją wykonując:
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
## Konfiguracja serwera poczty i domeny

### Poczekaj i bądź wiarygodny

Im starsza domena, tym mniejsze prawdopodobieństwo, że zostanie uznana za spam. Dlatego powinieneś poczekać jak najdłużej (przynajmniej 1 tydzień) przed przeprowadzeniem oceny phishingowej. Ponadto, jeśli umieścisz stronę dotyczącą sektora o dobrej reputacji, uzyskasz lepszą reputację.

Należy jednak zauważyć, że nawet jeśli musisz poczekać tydzień, możesz teraz zakończyć konfigurowanie wszystkiego.

### Skonfiguruj rekord Reverse DNS (rDNS)

Ustaw rekord rDNS (PTR), który przypisuje adres IP VPS do nazwy domeny.

### Rekord Sender Policy Framework (SPF)

**Musisz skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, czym jest rekord SPF, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/#spf).

Możesz skorzystać z [https://www.spfwizard.net/](https://www.spfwizard.net), aby wygenerować politykę SPF (użyj adresu IP maszyny VPS).

![](<../../.gitbook/assets/image (388).png>)

To jest treść, która musi zostać ustawiona w rekordzie TXT w domenie:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekord Domain-based Message Authentication, Reporting & Conformance (DMARC)

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, co to jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Musisz utworzyć nowy rekord DNS TXT, wskazujący na nazwę hosta `_dmarc.<domena>`, o następującej zawartości:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Musisz **skonfigurować DKIM dla nowej domeny**. Jeśli nie wiesz, co to jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/#dkim).

Ten samouczek opiera się na: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Musisz połączyć oba wartości B64, które generuje klucz DKIM:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Sprawdź wynik konfiguracji swojego adresu e-mail

Możesz to zrobić za pomocą [https://www.mail-tester.com/](https://www.mail-tester.com)\
Po prostu przejdź na stronę i wyślij e-mail na adres, który podają:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz również **sprawdzić konfigurację swojej poczty e-mail** wysyłając wiadomość e-mail na adres `check-auth@verifier.port25.com` i **odczytując odpowiedź** (w tym celu będziesz musiał **otworzyć** port **25** i sprawdzić odpowiedź w pliku _/var/mail/root_, jeśli wysyłasz wiadomość jako root).\
Sprawdź, czy przechodzisz wszystkie testy:
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
Możesz również wysłać **wiadomość do konta Gmail pod Twoją kontrolą** i sprawdzić **nagłówki emaila** w swojej skrzynce odbiorczej Gmaila. W polu nagłówka `Authentication-Results` powinno być obecne `dkim=pass`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Usuwanie z listy Spamhouse

Strona [www.mail-tester.com](www.mail-tester.com) może wskazać, czy Twoja domena jest blokowana przez Spamhouse. Możesz poprosić o usunięcie swojej domeny/IP pod adresem: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Usuwanie z listy czarnej Microsoftu

Możesz poprosić o usunięcie swojej domeny/IP pod adresem [https://sender.office.com/](https://sender.office.com).

## Tworzenie i uruchamianie kampanii GoPhish

### Profil wysyłającego

* Ustaw **nazwę identyfikującą** profil wysyłającego
* Zdecyduj, z którego konta będziesz wysyłać wiadomości phishingowe. Sugestie: _noreply, support, servicedesk, salesforce..._
* Możesz pozostawić puste pole dla nazwy użytkownika i hasła, ale upewnij się, że zaznaczono opcję Ignoruj błędy certyfikatu

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
Zaleca się skorzystanie z funkcji "**Wyślij wiadomość testową**" w celu sprawdzenia, czy wszystko działa poprawnie.\
Zalecam **wysyłanie wiadomości testowych na adresy 10minutowych skrzynek pocztowych**, aby uniknąć wpadnięcia na czarną listę podczas testów.
{% endhint %}

### Szablon wiadomości e-mail

* Ustaw **nazwę identyfikującą** szablonu
* Następnie napisz **temat** (nic dziwnego, po prostu coś, czego można się spodziewać w zwykłej wiadomości e-mail)
* Upewnij się, że zaznaczono "**Dodaj obraz śledzący**"
* Napisz **szablon wiadomości e-mail** (możesz używać zmiennych, jak w poniższym przykładzie):
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
Zwróć uwagę, że **w celu zwiększenia wiarygodności wiadomości e-mail**, zaleca się użycie jakiegoś podpisu z wiadomości e-mail od klienta. Sugestie:

* Wyślij e-mail na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera jakiś podpis.
* Szukaj **publicznych adresów e-mail**, takich jak info@ex.com lub press@ex.com lub public@ex.com i wyślij do nich e-mail, a następnie czekaj na odpowiedź.
* Spróbuj skontaktować się z **jakimś odkrytym ważnym** adresem e-mail i czekaj na odpowiedź.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
Szablon wiadomości e-mail umożliwia również **dołączanie plików do wysłania**. Jeśli chcesz również ukraść wyzwania NTLM za pomocą specjalnie przygotowanych plików/dokumentów, [przeczytaj tę stronę](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Strona docelowa

* Wpisz **nazwę**
* **Wpisz kod HTML** strony internetowej. Zauważ, że możesz **importować** strony internetowe.
* Zaznacz opcje **Przechwytywanie przesłanych danych** i **Przechwytywanie haseł**
* Ustaw **przekierowanie**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Zazwyczaj będziesz musiał zmodyfikować kod HTML strony i przeprowadzić testy lokalne (może za pomocą serwera Apache), **aż uzyskasz satysfakcjonujące wyniki**. Następnie wpisz ten kod HTML w polu tekstowym.\
Zauważ, że jeśli potrzebujesz **użyć jakichś statycznych zasobów** dla HTML (może to być jakiś arkusz CSS lub strony JS), możesz je zapisać w _**/opt/gophish/static/endpoint**_ i następnie uzyskać do nich dostęp z _**/static/\<nazwa_pliku>**_
{% endhint %}

{% hint style="info" %}
W przypadku przekierowania możesz **przekierować użytkowników na prawidłową główną stronę internetową** ofiary lub przekierować ich na _/static/migration.html_ na przykład, umieścić **kręcące się koło** ([**https://loading.io/**](https://loading.io)) przez 5 sekund, a następnie wskazać, że proces zakończył się sukcesem.
{% endhint %}

### Użytkownicy i grupy

* Ustaw nazwę
* **Zaimportuj dane** (zauważ, że aby użyć szablonu dla przykładu, potrzebujesz imienia, nazwiska i adresu e-mail każdego użytkownika)

![](<../../.gitbook/assets/image (395).png>)

### Kampania

Na koniec utwórz kampanię, wybierając nazwę, szablon wiadomości e-mail, stronę docelową, URL, profil wysyłania i grupę. Zauważ, że URL będzie linkiem wysłanym do ofiar.

Zauważ, że **Profil wysyłania pozwala na wysłanie testowej wiadomości e-mail, aby zobaczyć, jak będzie wyglądać ostateczna wiadomość phishingowa**:

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Zalecam wysyłanie testowych wiadomości e-mail na adresy 10minutowych skrzynek pocztowych, aby uniknąć czarnolistowania podczas testów.
{% endhint %}

Gdy wszystko jest gotowe, wystarczy uruchomić kampanię!

## Klonowanie stron internetowych

Jeśli z jakiegoś powodu chcesz sklonować stronę internetową, sprawdź następującą stronę:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Dokumenty i pliki z tylnymi drzwiami

W niektórych ocenach phishingowych (głównie dla Red Teamów) będziesz chciał również **wysłać pliki zawierające pewnego rodzaju tylną furtkę** (może to być C2 lub po prostu coś, co wywoła uwierzytelnienie).\
Sprawdź następującą stronę, aby zobaczyć przykłady:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Przez Proxy MitM

Poprzedni atak jest dość sprytny, ponieważ podszywasz się pod prawdziwą stronę internetową i zbierasz informacje wprowadzone przez użytkownika. Niestety, jeśli użytkownik nie podał poprawnego hasła lub jeśli aplikacja, którą podszywasz się, jest skonfigurowana z 2FA, **te informacje nie pozwolą ci podszyć się pod oszukanego użytkownika**.

W takich przypadkach przydatne są narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena). Narzędzia te umożliwiają generowanie ataku typu MitM. W zasadzie atak działa w następujący sposób:

1. **Podszywasz się pod formularz logowania** prawdziwej strony internetowej.
2. Użytkownik **wysyła** swoje **dane uwierzytelniające** do twojej fałszywej strony, a narzędzie wysyła je do prawdziwej strony internetowej, **sprawdzając, czy dane uwierzytelniające są poprawne**.
3. Jeśli konto jest skonfigurowane z **2FA**, strona MitM poprosi o to, a gdy **użytkownik je wprowadzi**, narzędzie prześle je do prawdziwej strony internetowej.
4. Gdy użytkownik zostanie uwierzytelniony, ty (jako atakujący) **przechwycisz dane uwierzytelniające, 2FA, ciasteczka i wszelkie informacje** z każdej interakcji, podczas gdy narzędzie wykonuje atak typu MitM.

### Przez VNC

Co by się stało, gdybyś zamiast **wysyłać ofiarę na złośliwą stronę** o takim samym wyglądzie jak oryginalna, wysłał ją do **sesji VNC z przeglądarką podłączoną do prawdziwej strony internetowej**? Będziesz mógł zobaczyć, co robi, ukraść hasło, użyte MFA, ciasteczka...\
Możesz to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Wykrywanie wykrycia

Oczywiście jednym z najlepszych sposobów, aby dowiedzieć się, czy zostałeś wykryty, jest **wyszukiwanie swojej domeny na czarnych listach**. Jeśli jest tam wymieniona, oznacza to, że twoja domena została uznana za podejrzaną.\
Łatwym sposobem sprawdzenia, czy twoja domena znajduje się na jakiejkolwiek czarnej liście, jest skorzystanie z [https://malwareworld.com/](https://malwareworld.com)

Jednak istnieją inne spos
