# Metodologia Phishing

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

## Metodologia

1. Zbieranie informacji o ofierze
1. Wybierz **domenę ofiary**.
2. Przeprowadź podstawową enumerację sieci w poszukiwaniu **portali logowania** używanych przez ofiarę i **zdecyduj**, który będziesz **podrabiał**.
3. Wykorzystaj **OSINT**, aby **znaleźć adresy e-mail**.
2. Przygotowanie środowiska
1. **Kup domenę**, którą będziesz używać do oceny phishingowej
2. **Skonfiguruj usługę e-mail** związane z rekordami (SPF, DMARC, DKIM, rDNS)
3. Skonfiguruj VPS z **gophish**
3. Przygotowanie kampanii
1. Przygotuj **szablon e-maila**
2. Przygotuj **stronę internetową** do kradzieży danych uwierzytelniających
4. Uruchom kampanię!

## Generowanie podobnych nazw domen lub zakup zaufanej domeny

### Techniki Wariacji Nazw Domen

* **Słowo kluczowe**: Nazwa domeny **zawiera ważne** **słowo kluczowe** oryginalnej domeny (np. zelster.com-management.com).
* **Poddomena z myślnikiem**: Zmiana **kropki na myślnik** poddomeny (np. www-zelster.com).
* **Nowe TLD**: Ta sama domena z użyciem **nowego TLD** (np. zelster.org)
* **Homoglify**: Zastępuje literę w nazwie domeny literami, które **wyglądają podobnie** (np. zelfser.com).
* **Transpozycja:** Zamienia **miejscami dwie litery** w nazwie domeny (np. zelsetr.com).
* **Forma pojedyncza/liczba mnoga**: Dodaje lub usuwa „s” na końcu nazwy domeny (np. zeltsers.com).
* **Pominięcie**: Usuwa jedną z liter z nazwy domeny (np. zelser.com).
* **Powtórzenie**: Powtarza jedną z liter w nazwie domeny (np. zeltsser.com).
* **Zastąpienie**: Podobne do homoglify, ale mniej dyskretne. Zastępuje jedną z liter w nazwie domeny, być może literą w sąsiedztwie oryginalnej litery na klawiaturze (np. zektser.com).
* **Poddomenowane**: Wprowadza **kropkę** w nazwie domeny (np. ze.lster.com).
* **Wstawienie**: Wstawia literę do nazwy domeny (np. zerltser.com).
* **Brak kropki**: Dołącza TLD do nazwy domeny. (np. zelstercom.com)

**Automatyczne Narzędzia**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Strony internetowe**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

Istnieje **możliwość, że jeden z niektórych bitów przechowywanych lub przesyłanych może zostać automatycznie odwrócony** z powodu różnych czynników, takich jak rozbłyski słoneczne, promieniowanie kosmiczne lub błędy sprzętowe.

Gdy ten koncept jest **stosowany do żądań DNS**, możliwe jest, że **domena otrzymana przez serwer DNS** nie jest taka sama jak domena początkowo żądana.

Na przykład pojedyncza modyfikacja bitu w domenie "windows.com" może zmienić ją na "windnws.com."

Atakujący mogą **skorzystać z tego, rejestrując wiele domen z odwróconymi bitami**, które są podobne do domeny ofiary. Ich intencją jest przekierowanie legalnych użytkowników do swojej własnej infrastruktury.

Aby uzyskać więcej informacji, przeczytaj [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Zakup zaufanej domeny

Możesz szukać na stronie [https://www.expireddomains.net/](https://www.expireddomains.net) domeny wygasłej, którą możesz wykorzystać.\
Aby upewnić się, że wygasła domena, którą zamierzasz kupić **ma już dobrą SEO**, możesz sprawdzić, jak jest sklasyfikowana w:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Odkrywanie Adresów E-mail

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% darmowe)
* [https://phonebook.cz/](https://phonebook.cz) (100% darmowe)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Aby **odkryć więcej** prawidłowych adresów e-mail lub **zweryfikować te**, które już odkryłeś, możesz sprawdzić, czy możesz przeprowadzić atak siłowy na serwery SMTP ofiary. [Dowiedz się, jak zweryfikować/odkryć adres e-mail tutaj](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Ponadto, nie zapomnij, że jeśli użytkownicy korzystają z **jakiegokolwiek portalu internetowego do dostępu do swoich maili**, możesz sprawdzić, czy jest podatny na **siłowe łamanie nazwy użytkownika**, i wykorzystać tę podatność, jeśli to możliwe.

## Konfigurowanie GoPhish

### Instalacja

Możesz pobrać go z [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Pobierz i rozpakuj go w `/opt/gophish` i uruchom `/opt/gophish/gophish`\
Otrzymasz hasło dla użytkownika admina na porcie 3333 w wynikach. Następnie uzyskaj dostęp do tego portu i użyj tych danych uwierzytelniających, aby zmienić hasło admina. Może być konieczne przekierowanie tego portu na lokalny:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Konfiguracja

**Konfiguracja certyfikatu TLS**

Przed tym krokiem powinieneś **już zakupić domenę**, którą zamierzasz użyć, a musi ona być **skierowana** na **adres IP VPS**, na którym konfigurujesz **gophish**.
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

**Zmień również wartości następujących zmiennych wewnątrz /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

Na koniec zmodyfikuj pliki **`/etc/hostname`** i **`/etc/mailname`** na nazwę swojej domeny i **zrestartuj swój VPS.**

Teraz utwórz **rekord A DNS** `mail.<domain>` wskazujący na **adres IP** VPS oraz **rekord MX DNS** wskazujący na `mail.<domain>`

Teraz przetestuj wysłanie e-maila:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Konfiguracja Gophish**

Zatrzymaj wykonanie gophish i przejdź do konfiguracji.\
Zmodyfikuj `/opt/gophish/config.json` do następującego (zwróć uwagę na użycie https):
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
**Skonfiguruj usługę gophish**

Aby utworzyć usługę gophish, która może być uruchamiana automatycznie i zarządzana jako usługa, możesz utworzyć plik `/etc/init.d/gophish` o następującej zawartości:
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
## Konfigurowanie serwera poczty i domeny

### Poczekaj i bądź wiarygodny

Im starsza jest domena, tym mniej prawdopodobne jest, że zostanie uznana za spam. Dlatego powinieneś poczekać jak najdłużej (przynajmniej 1 tydzień) przed przeprowadzeniem oceny phishingowej. Ponadto, jeśli umieścisz stronę dotyczącą sektora o dobrej reputacji, uzyskana reputacja będzie lepsza.

Zauważ, że nawet jeśli musisz poczekać tydzień, możesz teraz zakończyć konfigurowanie wszystkiego.

### Skonfiguruj rekord odwrotnego DNS (rDNS)

Ustaw rekord rDNS (PTR), który rozwiąże adres IP VPS na nazwę domeny.

### Rekord polityki nadawcy (SPF)

Musisz **skonfigurować rekord SPF dla nowej domeny**. Jeśli nie wiesz, co to jest rekord SPF, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/#spf).

Możesz skorzystać z [https://www.spfwizard.net/](https://www.spfwizard.net), aby wygenerować swoją politykę SPF (użyj adresu IP maszyny VPS)

![](<../../.gitbook/assets/image (388).png>)

To jest treść, która musi zostać ustawiona w rekordzie TXT w domenie:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Rekord Domain-based Message Authentication, Reporting & Conformance (DMARC)

Musisz **skonfigurować rekord DMARC dla nowej domeny**. Jeśli nie wiesz, co to jest rekord DMARC, [**przeczytaj tę stronę**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Musisz utworzyć nowy rekord DNS TXT wskazujący na nazwę hosta `_dmarc.<domena>` z następującą zawartością:
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

### Sprawdź wynik konfiguracji e-mail

Możesz to zrobić za pomocą [https://www.mail-tester.com/](https://www.mail-tester.com)\
Po prostu przejdź na stronę i wyślij e-mail na podany przez nich adres:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Możesz również **sprawdzić konfigurację swojej poczty e-mail**, wysyłając e-mail na adres `check-auth@verifier.port25.com` i **odczytując odpowiedź** (aby to zrobić, będziesz musiał **otworzyć** port **25** i sprawdzić odpowiedź w pliku _/var/mail/root_, jeśli wysyłasz e-mail jako root).\
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
Możesz również wysłać **wiadomość do Gmaila pod swoją kontrolą** i sprawdzić **nagłówki e-maila** w swojej skrzynce odbiorczej Gmaila, `dkim=pass` powinno być obecne w polu nagłówka `Authentication-Results`.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Usuwanie z listy Spamhouse Blacklist

Strona [www.mail-tester.com](www.mail-tester.com) może wskazać, czy twoja domena jest blokowana przez spamhouse. Możesz poprosić o usunięcie swojej domeny/IP pod adresem: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Usuwanie z listy czarnej Microsoftu

Możesz poprosić o usunięcie swojej domeny/IP pod adresem [https://sender.office.com/](https://sender.office.com).

## Tworzenie i Uruchamianie Kampanii GoPhish

### Profil Wysyłającego

* Ustaw **nazwę identyfikującą** profil nadawcy
* Zdecyduj, z którego konta będziesz wysyłać e-maile phishingowe. Sugestie: _noreply, support, servicedesk, salesforce..._
* Możesz pozostawić puste pole nazwy użytkownika i hasła, ale upewnij się, że zaznaczysz Ignoruj Błędy Certyfikatu

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
Zaleca się skorzystanie z funkcji "**Wyślij E-mail Testowy**" w celu sprawdzenia, czy wszystko działa poprawnie.\
Zalecam **wysłanie testowych e-maili na adresy 10minutowe** w celu uniknięcia wpadnięcia na czarną listę podczas testów.
{% endhint %}

### Szablon E-maila

* Ustaw **nazwę identyfikującą** szablonu
* Następnie napisz **temat** (nic dziwnego, po prostu coś, czego można by się spodziewać w zwykłym e-mailu)
* Upewnij się, że zaznaczyłeś "**Dodaj Obraz Śledzenia**"
* Napisz **szablon e-maila** (możesz używać zmiennych, jak w poniższym przykładzie):
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
Zauważ, że **dla zwiększenia wiarygodności e-maila** zaleca się użycie jakiegoś podpisu z e-maila klienta. Sugestie:

* Wyślij e-mail na **nieistniejący adres** i sprawdź, czy odpowiedź zawiera jakiś podpis.
* Szukaj **publicznych adresów e-mail** takich jak info@ex.com lub press@ex.com lub public@ex.com i wyślij im e-mail, oczekując na odpowiedź.
* Spróbuj skontaktować się z **jakimś odkrytym ważnym** adresem e-mail i poczekaj na odpowiedź.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
Szablon e-maila pozwala również na **dołączenie plików do wysłania**. Jeśli chcesz również ukraść wyzwania NTLM za pomocą specjalnie przygotowanych plików/dokumentów, [przeczytaj tę stronę](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Strona docelowa

* Wprowadź **nazwę**
* **Napisz kod HTML** strony internetowej. Zauważ, że możesz **importować** strony internetowe.
* Zaznacz **Przechwytywanie przesłanych danych** i **Przechwytywanie haseł**
* Ustaw **przekierowanie**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Zazwyczaj będziesz musiał zmodyfikować kod HTML strony i przeprowadzić testy lokalnie (może używając serwera Apache) **aż uzyskasz pożądane rezultaty**. Następnie wpisz ten kod HTML w pole.\
Zauważ, że jeśli potrzebujesz **użyć jakichś zasobów statycznych** dla HTML (może to być CSS i JS), możesz je zapisać w _**/opt/gophish/static/endpoint**_ i później uzyskać do nich dostęp z _**/static/\<nazwapliku>**_
{% endhint %}

{% hint style="info" %}
W przypadku przekierowania możesz **przekierować użytkowników na prawdziwą główną stronę internetową** ofiary, lub przekierować ich na _/static/migration.html_ na przykład, dodać **kręcące się koło** ([**https://loading.io/**](https://loading.io)) przez 5 sekund, a następnie wskazać, że proces zakończył się sukcesem.
{% endhint %}

### Użytkownicy i Grupy

* Ustaw nazwę
* **Zaimportuj dane** (zauważ, że aby użyć szablonu w przykładzie, potrzebujesz imienia, nazwiska i adresu e-mail każdego użytkownika)

![](<../../.gitbook/assets/image (395).png>)

### Kampania

W końcu, stwórz kampanię wybierając nazwę, szablon e-maila, stronę docelową, URL, profil wysyłania i grupę. Zauważ, że URL będzie linkiem wysłanym do ofiar

Zauważ, że **Profil Wysyłania pozwala na wysłanie testowego e-maila, aby zobaczyć, jak będzie wyglądał ostateczny e-mail phishingowy**:

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Zalecam **wysyłanie testowych e-maili na adresy 10minutemail**, aby uniknąć wpadnięcia na czarną listę podczas testów.
{% endhint %}

Gdy wszystko jest gotowe, wystarczy uruchomić kampanię!

## Klonowanie Strony Internetowej

Jeśli z jakiegoś powodu chcesz sklonować stronę internetową, sprawdź następującą stronę:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Dokumenty i Pliki z Tylnymi Drzwiami

W niektórych ocenach phishingowych (głównie dla Red Teams) będziesz chciał również **wysłać pliki zawierające jakieś rodzaje tylnych drzwi** (może to być C2 lub po prostu coś, co wywoła uwierzytelnienie).\
Sprawdź następującą stronę dla przykładów:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Przez Proxy MitM

Poprzedni atak jest dość sprytny, ponieważ podszywasz się pod prawdziwą stronę internetową i zbierasz informacje wprowadzone przez użytkownika. Niestety, jeśli użytkownik nie wprowadził poprawnego hasła lub jeśli aplikacja, którą podszywasz się, jest skonfigurowana z 2FA, **te informacje nie pozwolą ci podać się za oszukanego użytkownika**.

W takich przypadkach narzędzia takie jak [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) i [**muraena**](https://github.com/muraenateam/muraena) są przydatne. Narzędzie to pozwoli ci wygenerować atak typu MitM. W skrócie, ataki działają w następujący sposób:

1. **Podszywasz się pod formularz logowania** prawdziwej strony internetowej.
2. Użytkownik **wysyła** swoje **dane uwierzytelniające** na twoją fałszywą stronę, a narzędzie przesyła je do prawdziwej strony internetowej, **sprawdzając, czy dane uwierzytelniające są poprawne**.
3. Jeśli konto jest skonfigurowane z **2FA**, strona MitM poprosi o to, a gdy **użytkownik je wprowadzi**, narzędzie prześle je do prawdziwej strony internetowej.
4. Gdy użytkownik zostanie uwierzytelniony, ty (jako atakujący) **przechwycisz dane uwierzytelniające, 2FA, ciasteczka i wszelkie informacje** z każdej interakcji, podczas gdy narzędzie wykonuje atak MitM.

### Przez VNC

Co jeśli zamiast **przekierować ofiarę na złośliwą stronę** o takim samym wyglądzie jak oryginalna, przekierujesz ją na **sesję VNC z przeglądarką podłączoną do prawdziwej strony internetowej**? Będziesz mógł zobaczyć, co robi, ukraść hasło, użyte MFA, ciasteczka...\
Możesz to zrobić za pomocą [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Wykrywanie wykrycia

Oczywiście jednym z najlepszych sposobów, aby dowiedzieć się, czy zostałeś wykryty, jest **sprawdzenie swojej domeny na czarnych listach**. Jeśli się tam znajduje, to w jakiś sposób twoja domena została uznana za podejrzaną.\
Łatwym sposobem sprawdzenia, czy twoja domena znajduje się na jakiejkolwiek czarnej liście, jest skorzystanie z [https://malwareworld.com/](https://malwareworld.com)

Jednak istnieją inne sposoby, aby dowiedzieć się, czy ofiara **aktywnie szuka podejrzanej aktywności phishingowej w sieci**, jak wyjaśniono w:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Możesz **kupić domenę o bardzo podobnej nazwie** do domeny ofiary **i/lub wygenerować certyfikat** dla **poddomeny** domeny kontrolowanej przez ciebie **zawierającej** słowo kluczowe z domeny ofiary. Jeśli **ofiara** wykonuje jakiekolwiek **interakcje DNS lub HTTP** z nimi, będziesz wiedział, że **aktywnie szuka** podejrzanych domen i będziesz musiał działać bardzo dyskretnie.

### Ocenianie phishingu

Użyj [**Phishious** ](https://github.com/Rices/Phishious), aby ocenić, czy twój e-mail trafi do folderu spamu, czy zostanie zablokowany, czy też będzie udany.

## Referencje

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
* [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
