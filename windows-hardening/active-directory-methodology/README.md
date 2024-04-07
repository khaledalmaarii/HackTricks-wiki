# Metodologia Active Directory

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowy przegląd

**Active Directory** pełni rolę technologii podstawowej, umożliwiając **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** oraz **obiektami** w sieci. Został zaprojektowany do skalowania, ułatwiając organizację dużej liczby użytkowników w zarządzalne **grupy** i **podgrupy**, kontrolując jednocześnie **prawa dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech podstawowych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** lub **urządzenia**, współdzielących wspólną bazę danych. **Drzewa** to grupy tych domen połączone wspólną strukturą, a **las** reprezentuje zbiór wielu drzew, połączonych poprzez **relacje zaufania**, tworząc najwyższą warstwę struktury organizacyjnej. Określone **prawa dostępu** i **komunikacji** mogą być przypisane na każdym z tych poziomów.

Kluczowe koncepcje w **Active Directory** obejmują:

1. **Katalog** – Zawiera wszystkie informacje dotyczące obiektów Active Directory.
2. **Obiekt** – Oznacza jednostki w katalogu, w tym **użytkowników**, **grupy** lub **udostępnione foldery**.
3. **Domena** – Pełni rolę kontenera dla obiektów katalogu, z możliwością współistnienia wielu domen w **lesie**, z każdą utrzymującą własną kolekcję obiektów.
4. **Drzewo** – Grupowanie domen, które dzielą wspólny domenę nadrzędną.
5. **Las** – Szczytowa struktura organizacyjna w Active Directory, składająca się z kilku drzew z **relacjami zaufania** między nimi.

**Usługi domenowe Active Directory (AD DS)** obejmują szereg usług kluczowych dla scentralizowanego zarządzania i komunikacji w sieci. Usługi te obejmują:

1. **Usługi domenowe** – Centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** i **domenami**, w tym funkcje **uwierzytelniania** i **wyszukiwania**.
2. **Usługi certyfikatów** – Nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Usługi katalogowe Lightweight** – Obsługuje aplikacje z włączonym katalogiem za pomocą protokołu **LDAP**.
4. **Usługi federacji katalogowej** – Zapewnia możliwość **jednokrotnego logowania** do uwierzytelniania użytkowników w wielu aplikacjach internetowych w jednej sesji.
5. **Zarządzanie prawami** – Pomaga w ochronie materiałów podlegających prawom autorskim poprzez regulowanie ich nieautoryzowanego rozpowszechniania i użytkowania.
6. **Usługa DNS** – Istotna dla rozwiązywania **nazw domen**.

Dla bardziej szczegółowego wyjaśnienia sprawdź: [**TechTerms - Definicja Active Directory**](https://techterms.com/definition/active\_directory)

### **Uwierzytelnianie Kerberos**

Aby nauczyć się **atakować AD**, musisz bardzo dobrze zrozumieć proces **uwierzytelniania Kerberos**.\
[**Przeczytaj tę stronę, jeśli wciąż nie wiesz, jak to działa.**](kerberos-authentication.md)

## Arkusz oszustw

Możesz przejść do [https://wadcoms.github.io/](https://wadcoms.github.io), aby szybko zobaczyć, jakie polecenia można uruchomić do wyliczenia/eksploatacji AD.

## Rozpoznanie Active Directory (Bez poświadczeń/sesji)

Jeśli masz dostęp do środowiska AD, ale nie masz żadnych poświadczeń/sesji, możesz:

* **Testuj sieć:**
* Skanuj sieć, znajduj maszyny i otwarte porty, a następnie spróbuj **wykorzystać podatności** lub **wydobyć poświadczenia** z nich (na przykład [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md).
* Wyliczenie DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak strony internetowe, drukarki, udziały, VPN, media, itp.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Zapoznaj się z ogólną [**Metodologią Testowania Przenikania**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby uzyskać więcej informacji na ten temat.
* **Sprawdź dostęp null i Gościa w usługach smb** (to nie zadziała w nowoczesnych wersjach systemu Windows):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Bardziej szczegółowy przewodnik dotyczący wyliczania serwera SMB można znaleźć tutaj:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Wylicz Ldap**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Bardziej szczegółowy przewodnik dotyczący wyliczania LDAP można znaleźć tutaj (zwróć **szczególną uwagę na dostęp anonimowy**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Zatrute sieć**
* Zbieraj poświadczenia [**podając się za usługi z użyciem Respondera**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Uzyskaj dostęp do hosta, [**wykorzystując atak przekierowania**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Zbieraj poświadczenia **odsłaniając** [**fałszywe usługi UPnP za pomocą evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Wydobywaj nazwy użytkowników/imiona z wewnętrznych dokumentów, mediów społecznościowych, usług (głównie internetowych) w środowiskach domenowych oraz z publicznie dostępnych.
* Jeśli znajdziesz pełne nazwiska pracowników firmy, możesz spróbować różnych konwencji **nazewnictwa użytkowników AD (**[**przeczytaj to**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęstsze konwencje to: _ImięNazwisko_, _Imię.Nazwisko_, _ImięNaz_, _Imię.Nazw_, _NazwiskoImię_, _Nazwisko.Imię_, _NazwiskoN_, _Nazwisko.N_, 3 _losowe litery i 3 losowe cyfry_ (abc123).
* Narzędzia:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)
### Wyliczanie użytkowników

* **Anonimowe wyliczanie SMB/LDAP:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Wyliczanie Kerbrute**: Gdy zostanie zapytane o **nieprawidłową nazwę użytkownika**, serwer odpowie kodem błędu **Kerberos** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, co pozwala nam stwierdzić, że nazwa użytkownika była nieprawidłowa. **Prawidłowe nazwy użytkowników** spowodują odpowiedź albo z **TGT w odpowiedzi AS-REP**, albo błąd _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, co wskazuje, że użytkownik musi wykonać wstępną autoryzację.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Serwer OWA (Outlook Web Access)**

Jeśli znalazłeś jeden z tych serwerów w sieci, możesz również przeprowadzić **wyliczanie użytkowników przeciwko niemu**. Na przykład, możesz użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
{% hint style="warning" %}
Możesz znaleźć listy nazw użytkowników w [**tym repozytorium na githubie**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) oraz w tym ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

Jednakże, powinieneś mieć **imię i nazwisko osób pracujących w firmie** z kroku rozpoznania, który powinieneś wykonać wcześniej. Dzięki imieniu i nazwisku możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951) do generowania potencjalnie poprawnych nazw użytkowników.
{% endhint %}

### Znając jedno lub kilka nazw użytkowników

Ok, więc wiesz, że masz już poprawną nazwę użytkownika, ale nie znasz haseł... W takim przypadku spróbuj:

* [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT\_REQ\_PREAUTH_, możesz **żądać wiadomość AS\_REP** dla tego użytkownika, która będzie zawierać pewne dane zaszyfrowane przez pochodną hasła użytkownika.
* [**Password Spraying**](password-spraying.md): Spróbuj najbardziej **popularnych haseł** z każdym z odkrytych użytkowników, być może jakiś użytkownik używa słabego hasła (pamiętaj o polityce haseł!).
* Zauważ, że możesz również **spróbować atakować serwery OWA** w celu uzyskania dostępu do skrzynek pocztowych użytkowników.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Zatrucie LLMNR/NBT-NS

Możesz **uzyskać** pewne **hashe wyzwań** do złamania **zatruwając** niektóre protokoły **sieciowe**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

Jeśli udało ci się wyliczyć katalog aktywny, będziesz mieć **więcej adresów e-mail i lepsze zrozumienie sieci**. Możesz próbować wymusić ataki NTML [**relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* w celu uzyskania dostępu do środowiska AD.

### Kradzież poświadczeń NTLM

Jeśli możesz **uzyskać dostęp do innych komputerów lub zasobów** za pomocą **użytkownika null lub gościa**, możesz **umieścić pliki** (np. plik SCF), które jeśli w jakiś sposób zostaną otwarte, spowodują **uwierzytelnienie NTML przeciwko tobie**, dzięki czemu będziesz mógł **ukraść** **wyzwanie NTLM** do złamania:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Wyliczanie katalogu aktywnego Z poświadczeniami/sesją

W tej fazie musisz **skompromitować poświadczenia lub sesję ważnego konta domeny**. Jeśli masz ważne poświadczenia lub powłokę jako użytkownik domeny, **pamiętaj, że opcje podane wcześniej nadal są opcjami do skompromitowania innych użytkowników**.

Przed rozpoczęciem uwierzytelnionego wyliczania powinieneś wiedzieć, co to jest **problem podwójnego skoku Kerberosa**.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Wyliczanie

Posiadanie skompromitowanego konta to **duży krok w kierunku skompromitowania całej domeny**, ponieważ będziesz mógł rozpocząć **Wyliczanie katalogu aktywnego:**

W odniesieniu do [**ASREPRoast**](asreproast.md) możesz teraz znaleźć każdego potencjalnie podatnego użytkownika, a w odniesieniu do [**Password Spraying**](password-spraying.md) możesz uzyskać **listę wszystkich nazw użytkowników** i spróbować hasła skompromitowanego konta, puste hasła i nowe obiecujące hasła.

* Możesz użyć [**CMD do wykonania podstawowego rozpoznania**](../basic-cmd-for-pentesters.md#domain-info)
* Możesz również użyć [**powershell do rozpoznania**](../basic-powershell-for-pentesters/), co będzie bardziej dyskretne
* Możesz również [**użyć powerview**](../basic-powershell-for-pentesters/powerview.md), aby uzyskać bardziej szczegółowe informacje
* Innym niesamowitym narzędziem do rozpoznania w katalogu aktywnym jest [**BloodHound**](bloodhound.md). Nie jest zbyt dyskretny (w zależności od używanych metod zbierania danych), ale **jeśli nie przeszkadza ci to**, koniecznie spróbuj. Znajdź, gdzie użytkownicy mogą łączyć się zdalnie, znajdź ścieżkę do innych grup, itp.
* **Inne zautomatyzowane narzędzia do wyliczania AD to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Rekordy DNS AD**](ad-dns-records.md), ponieważ mogą zawierać interesujące informacje.
* Narzędzie z interfejsem graficznym, które możesz użyć do wyliczania katalogu to **AdExplorer.exe** z pakietu **SysInternal** Suite.
* Możesz również przeszukać bazę danych LDAP za pomocą **ldapsearch** w poszukiwaniu poświadczeń w polach _userPassword_ & _unixUserPassword_, a nawet w _Description_. Por. [Hasło w komentarzu użytkownika AD na PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) dla innych metod.
* Jeśli korzystasz z systemu **Linux**, możesz również wyliczyć domenę za pomocą [**pywerview**](https://github.com/the-useless-one/pywerview).
* Możesz również spróbować zautomatyzowanych narzędzi takich jak:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Wyodrębnianie wszystkich użytkowników domeny**

Bardzo łatwo jest uzyskać wszystkie nazwy użytkowników domeny z systemu Windows (`net user /domain`, `Get-DomainUser` lub `wmic useraccount get name,sid`). W systemie Linux możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli ta sekcja Wyliczania wygląda na małą, jest to najważniejsza część. Wejdź na linki (głównie ten do cmd, powershell, powerview i BloodHound), naucz się, jak wyliczać domenę i praktykuj, aż poczujesz się pewnie. Podczas oceny, to będzie kluczowy moment, aby znaleźć drogę do DA lub zdecydować, że nic nie można zrobić.

### Kerberoast

Kerberoasting polega na uzyskaniu **biletów TGS** używanych przez usługi powiązane z kontami użytkowników i złamaniu ich szyfrowania—które opiera się na hasłach użytkowników—**offline**.

Więcej na ten temat:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}
### Połączenie zdalne (RDP, SSH, FTP, Win-RM, itp)

Po uzyskaniu pewnych poświadczeń, możesz sprawdzić, czy masz dostęp do jakiejkolwiek **maszyny**. W tym celu możesz użyć **CrackMapExec** do próby połączenia się z kilkoma serwerami za pomocą różnych protokołów, zgodnie z przeprowadzonymi skanami portów.

### Eskalacja uprawnień lokalnych

Jeśli masz skompromitowane poświadczenia lub sesję jako zwykły użytkownik domeny i masz **dostęp** z tym użytkownikiem do **jakiejkolwiek maszyny w domenie**, powinieneś spróbować znaleźć sposób na **eskalację uprawnień lokalnych i zdobycie poświadczeń**. Jest to konieczne, ponieważ tylko posiadając uprawnienia lokalnego administratora będziesz mógł **wydobyć hashe innych użytkowników** z pamięci (LSASS) i lokalnie (SAM).

W tej książce znajduje się pełna strona dotycząca [**eskalacji uprawnień lokalnych w systemie Windows**](../windows-local-privilege-escalation/) oraz [**checklista**](../checklist-windows-privilege-escalation.md). Nie zapomnij również skorzystać z [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Bieżące bilety sesji

Bardzo **mało prawdopodobne** jest, że znajdziesz **bilety** w bieżącym użytkowniku, które **umożliwią Ci dostęp do** nieoczekiwanych zasobów, ale możesz sprawdzić:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Jeśli udało ci się wyliczyć aktywny katalog, będziesz miał **więcej adresów e-mail i lepsze zrozumienie sieci**. Być może będziesz w stanie wymusić ataki **przekazywania NTML**.

### **Szukaj poświadczeń w udziałach komputerowych**

Teraz, gdy masz pewne podstawowe poświadczenia, powinieneś sprawdzić, czy **znajdziesz** jakieś **interesujące pliki udostępnione wewnątrz AD**. Możesz to zrobić ręcznie, ale jest to bardzo nudne i powtarzalne zadanie (szczególnie jeśli znajdziesz setki dokumentów do sprawdzenia).

[**Kliknij ten link, aby dowiedzieć się o narzędziach, których możesz użyć.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### Ukradnij poświadczenia NTLM

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów**, możesz **umieścić pliki** (np. plik SCF), które jeśli w jakiś sposób zostaną otwarte, spowodują **uwierzytelnienie NTML przeciwko tobie**, dzięki czemu będziesz mógł **ukraść** **wyzwanie NTLM**, aby je złamać:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta podatność pozwalała każdemu uwierzytelnionemu użytkownikowi **skompromitować kontroler domeny**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Eskalacja uprawnień w Active Directory Z uprzywilejowanymi poświadczeniami/sesją

**Dla poniższych technik zwykły użytkownik domeny nie wystarczy, potrzebujesz specjalnych uprawnień/poświadczeń, aby przeprowadzić te ataki.**

### Wydobycie hasha

Mam nadzieję, że udało ci się **skompromitować pewne konto lokalnego administratora** za pomocą [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) włącznie z przekazywaniem, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [eskaluowaniem uprawnień lokalnie](../windows-local-privilege-escalation/).\
Następnie nadszedł czas, aby wydobyć wszystkie hashe z pamięci i lokalnie.\
[**Przeczytaj tę stronę o różnych sposobach pozyskania hashy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Przekazanie hasha

**Gdy masz hash użytkownika**, możesz go **podrobić**.\
Musisz użyć **narzędzia**, które **wykona** **uwierzytelnienie NTLM używając** tego **hasła**, **lub** możesz utworzyć nową **sesję logowania** i **wstrzyknąć** to **hasło** do **LSASS**, więc gdy zostanie wykonane **uwierzytelnienie NTLM**, to **hasło zostanie użyte**. Ostatnia opcja to to, co robi mimikatz.\
[**Przeczytaj tę stronę, aby uzyskać więcej informacji.**](../ntlm/#pass-the-hash)

### Przekazanie hasła/klucza

Ten atak ma na celu **wykorzystanie hasha NTLM użytkownika do żądania biletów Kerberos**, jako alternatywy dla powszechnego przekazywania hasha w protokole NTLM. Dlatego może to być szczególnie **przydatne w sieciach, gdzie protokół NTLM jest wyłączony**, a do autoryzacji dopuszczony jest tylko **Kerberos**.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Przekazanie biletu

W metodzie ataku **Pass The Ticket (PTT)** atakujący **kradnie bilet autoryzacyjny użytkownika** zamiast hasła lub wartości hasha. Skradziony bilet jest następnie używany do **podrobienia użytkownika**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Ponowne wykorzystanie poświadczeń

Jeśli masz **hash** lub **hasło** lokalnego **administratora**, powinieneś spróbować **zalogować się lokalnie** do innych **komputerów** z jego użyciem.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Zauważ, że jest to dość **hałaśliwe** i **LAPS** może to **złagodzić**.
{% endhint %}

### Nadużycie MSSQL i zaufane linki

Jeśli użytkownik ma uprawnienia do **dostępu do instancji MSSQL**, może użyć ich do **wykonywania poleceń** na hoście MSSQL (jeśli działa jako SA), **ukraść** skrót NetNTLM lub nawet przeprowadzić **atak przekazywania**.\
Ponadto, jeśli instancja MSSQL jest zaufana (link bazy danych) przez inną instancję MSSQL. Jeśli użytkownik ma uprawnienia do zaufanej bazy danych, będzie mógł **wykorzystać relację zaufania do wykonywania zapytań także w innej instancji**. Te zaufania mogą być łańcuchowe, a w pewnym momencie użytkownik może znaleźć źle skonfigurowaną bazę danych, w której może wykonywać polecenia.\
**Linki między bazami danych działają nawet w przypadku zaufania między lasami.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Nieograniczone przekazywanie

Jeśli znajdziesz jakikolwiek obiekt komputera z atrybutem [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) i masz uprawnienia domeny na komputerze, będziesz mógł wydobyć TGT z pamięci każdego użytkownika, który loguje się na komputerze.\
Dlatego jeśli **Administrator domeny zaloguje się na komputer**, będziesz mógł wydobyć jego TGT i podszyć się pod niego, korzystając z [Przekazania Biletu](pass-the-ticket.md).\
Dzięki ograniczonemu przekazywaniu możesz nawet **automatycznie skompromitować Serwer Drukarek** (oby był to DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Ograniczone przekazywanie

Jeśli użytkownik lub komputer jest uprawniony do "Ograniczonego przekazywania", będzie mógł **podawać się za dowolnego użytkownika, aby uzyskać dostęp do niektórych usług na komputerze**.\
Następnie, jeśli **skompromitujesz skrót** tego użytkownika/komputera, będziesz mógł **podawać się za dowolnego użytkownika** (nawet administratorów domeny), aby uzyskać dostęp do niektórych usług.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Ograniczenie przekazywania oparte na zasobach

Posiadanie uprawnień **ZAPISYWANIE** do obiektu Active Directory zdalnego komputera umożliwia uzyskanie wykonania kodu z **uprzywilejowanymi uprawnieniami**:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Nadużycie ACL

Skompromitowany użytkownik może mieć pewne **interesujące uprawnienia do niektórych obiektów domeny**, które mogą pozwolić ci na **przesuwanie się** bocznie/**eskalację** uprawnień.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Nadużycie usługi Spooler drukarki

Odkrycie **usługi Spool** nasłuchującej w domenie może być **nadużyte** do **uzyskania nowych poświadczeń** i **eskalacji uprawnień**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Nadużycie sesji osób trzecich

Jeśli **inne osoby** **dostęp** do **skompromitowanego** komputera, możliwe jest **pobranie poświadczeń z pamięci** i nawet **wstrzyknięcie beaconów do ich procesów** w celu podszywania się pod nich.\
Zazwyczaj użytkownicy będą uzyskiwać dostęp do systemu za pomocą RDP, więc tutaj masz, jak przeprowadzić kilka ataków na sesje RDP osób trzecich:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** zapewnia system do zarządzania **hasłem lokalnego Administratora** na komputerach dołączonych do domeny, zapewniając, że jest **losowe**, unikalne i często **zmieniane**. Te hasła są przechowywane w Active Directory, a dostęp jest kontrolowany za pomocą ACL tylko dla uprawnionych użytkowników. Posiadając wystarczające uprawnienia do dostępu do tych haseł, staje się możliwe przechodzenie do innych komputerów.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Kradzież certyfikatów

**Zbieranie certyfikatów** z zainfekowanego komputera może być sposobem na eskalację uprawnień w środowisku:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Nadużycie szablonów certyfikatów

Jeśli są skonfigurowane **podatne szablony**, możliwe jest ich nadużycie w celu eskalacji uprawnień:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Poeksploatacja z kontem o wysokich uprawnieniach

### Wydobywanie poświadczeń domeny

Gdy uzyskasz uprawnienia **Administratora domeny** lub nawet lepiej **Administratora przedsiębiorstwa**, możesz **wydobyć** bazę danych domeny: _ntds.dit_.

[**Więcej informacji na temat ataku DCSync można znaleźć tutaj**](dcsync.md).

[**Więcej informacji na temat kradzieży NTDS.dit można znaleźć tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Przywileje jako trwałość

Niektóre z omawianych wcześniej technik mogą być wykorzystane do trwałości.\
Na przykład możesz:

*   Uczynić użytkowników podatnymi na [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <nazwa użytkownika> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   Uczynić użytkowników podatnymi na [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <nazwa użytkownika> -XOR @{UserAccountControl=4194304}
```
*   Przyznać uprawnienia [**DCSync**](./#dcsync) użytkownikowi

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Bilet srebrny

Atak **Bilet srebrny** tworzy **legitymacyjny bilet usługi Granting Service (TGS)** dla określonej usługi, korzystając z **skrótu NTLM** (na przykład **skrótu konta PC**). Ta metoda jest stosowana do **uzyskania dostępu do uprawnień usługi**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Bilet złoty

Atak **Bilet złoty** polega na uzyskaniu dostępu do **skrótu NTLM konta krbtgt** w środowisku Active Directory (AD). To konto jest specjalne, ponieważ służy do podpisywania wszystkich **Biletów Granting Tickets (TGTs)**, które są niezbędne do uwierzytelniania w sieci AD.

Gdy atakujący uzyska ten skrót, może tworzyć **TGTs** dla dowolnego konta, które wybierze (atak biletu srebrnego).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Bilet diamentowy

Są to jak złote bilety sfałszowane w taki sposób, że **omijają powszechne mechanizmy wykrywania złotych biletów**.

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}
### **Trwałość kont certyfikatów**

**Posiadanie certyfikatów konta lub możliwość ich żądania** jest bardzo dobrym sposobem na trwałość w koncie użytkownika (nawet jeśli zmieni hasło):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Trwałość domeny certyfikatów**

**Z użyciem certyfikatów można również trwale uzyskać wysokie uprawnienia w obrębie domeny:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Grupa AdminSDHolder

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (takich jak Administratorzy domeny i Administratorzy przedsiębiorstwa), stosując standardowy **Listę Kontroli Dostępu (ACL)** w tych grupach w celu zapobieżenia nieautoryzowanym zmianom. Jednak ta funkcja może być wykorzystana; jeśli atakujący zmodyfikuje ACL AdminSDHoldera, aby nadać pełny dostęp zwykłemu użytkownikowi, ten użytkownik uzyskuje rozległą kontrolę nad wszystkimi uprzywilejowanymi grupami. Ta środek bezpieczeństwa, mający na celu ochronę, może więc odwrócić się przeciwko, umożliwiając nieuprawniony dostęp, chyba że jest śledzony wnikliwie.

[**Więcej informacji o grupie AdminDSHolder tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Dane uwierzytelniające DSRM

Wewnątrz każdego **Kontrolera domeny (DC)** istnieje konto **lokalnego administratora**. Uzyskując prawa administratora na takim urządzeniu, można wydobyć skrót lokalnego Administratora, korzystając z **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **umożliwić użycie tego hasła**, umożliwiając zdalny dostęp do konta lokalnego Administratora.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Trwałość ACL

Możesz **przypisać** pewne **specjalne uprawnienia** do **użytkownika** wobec określonych obiektów domenowych, co pozwoli użytkownikowi **eskalować uprawnienia w przyszłości**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Deskryptory zabezpieczeń

**Deskryptory zabezpieczeń** są używane do **przechowywania** uprawnień, jakie **obiekt** ma **nad** innym **obiektem**. Jeśli możesz **wprowadzić** niewielką **zmianę** w **deskryptorze zabezpieczeń** obiektu, możesz uzyskać bardzo interesujące uprawnienia wobec tego obiektu, nie będąc członkiem uprzywilejowanej grupy.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Klucz szkieletowy

Zmodyfikuj **LSASS** w pamięci, aby ustawić **uniwersalne hasło**, umożliwiające dostęp do wszystkich kont domenowych.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### Niestandardowy SSP

[Dowiedz się, czym jest SSP (Dostawca Obsługi Zabezpieczeń) tutaj.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Możesz stworzyć **własny SSP**, aby **przechwycić** w **czystym tekście** dane **uwierzytelniające** używane do dostępu do maszyny.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Rejestruje **nowy Kontroler domeny** w AD i używa go do **przesyłania atrybutów** (SIDHistory, SPN...) na określone obiekty **bez** pozostawiania **logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień DA i musisz być w **domenie głównej**.\
Zauważ, że w przypadku użycia błędnych danych pojawią się dość brzydkie logi.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Trwałość LAPS

Wcześniej omówiliśmy, jak eskalować uprawnienia, jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Jednak te hasła można również wykorzystać do **utrzymywania trwałości**.\
Sprawdź:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Eskalacja uprawnień w lesie - Zaufanie domenowe

Microsoft traktuje **Las** jako granicę bezpieczeństwa. Oznacza to, że **skompromitowanie jednej domeny może potencjalnie doprowadzić do skompromitowania całego Lasu**.

### Podstawowe informacje

[**Zaufanie domenowe**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) to mechanizm bezpieczeństwa, który umożliwia użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. W zasadzie tworzy ono połączenie między systemami uwierzytelniania obu domen, umożliwiając płynne przepływanie weryfikacji uwierzytelniania. Gdy domeny ustanawiają zaufanie, wymieniają i zachowują określone **klucze** w swoich **Kontrolerach domeny (DC)**, które są kluczowe dla integralności zaufania.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **zaufanej domenie**, musi najpierw poprosić o specjalny bilet znanym jako **TGT międzydomenowy** od DC swojej własnej domeny. Ten TGT jest szyfrowany za pomocą wspólnego **klucza**, na który obie domeny się zgodziły. Użytkownik następnie przedstawia ten TGT **DC zaufanej domeny**, aby uzyskać bilet usługi (**TGS**). Po pomyślnej walidacji TGT międzydomenowego przez DC zaufanej domeny, wydaje ona TGS, udzielając użytkownikowi dostępu do usługi.

**Kroki**:

1. **Komputer klienta** w **Domenie 1** rozpoczyna proces, używając swojego **skrótu NTLM** do żądania **Biletu Grantowego (TGT)** od swojego **Kontrolera domeny (DC1)**.
2. DC1 wydaje nowy TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Klient następnie żąda **TGT międzydomenowego** od DC1, który jest potrzebny do dostępu do zasobów w **Domenie 2**.
4. TGT międzydomenowy jest szyfrowany za pomocą **klucza zaufania** współdzielonego między DC1 a DC2 jako część dwukierunkowego zaufania domenowego.
5. Klient zabiera TGT międzydomenowy do **Kontrolera domeny Domeny 2 (DC2)**.
6. DC2 weryfikuje TGT międzydomenowy za pomocą współdzielonego klucza zaufania i w przypadku poprawności wydaje **Bilet Usługi Grantującej (TGS)** dla serwera w Domenie 2, do którego klient chce uzyskać dostęp.
7. Wreszcie klient przedstawia ten TGS serwerowi, który jest szyfrowany za pomocą skrótu konta serwera, aby uzyskać dostęp do usługi w Domenie 2.

### Różne zaufania

Ważne jest zauważenie, że **zaufanie może być jednokierunkowe lub dwukierunkowe**. W opcjach dwukierunkowych obie domeny będą sobie ufać, ale w relacji **jednokierunkowej** jedna z domen będzie **zaufaną**, a druga **ufającą** domeną. W ostatnim przypadku **będziesz mógł uzyskać dostęp tylko do zasobów w domenie ufającej z zaufanej**.

Jeśli Domena A ufa Domenie B, A jest domeną ufającą, a B jest zaufaną. Ponadto w **Domenie A** byłoby to **zaufanie wychodzące**; a w **Domenie B** byłoby to **zaufanie przychodzące**.

**Różne relacje ufania**

* **Zaufania rodzica-dziecka**: Jest to powszechne ustawienie w obrębie tego samego lasu, gdzie domena dziecka automatycznie ma dwukierunkowe zaufanie przechodnie z domeną nadrzędną. W zasadzie oznacza to, że żądania uwierzytelniania mogą płynnie przepływać między nadrzędnym a dzieckiem.
* **Zaufania krzyżowe**: Nazywane "zaufaniami skróconymi", są one ustanawiane między domenami potomnymi w celu przyspieszenia procesów przekierowań. W złożonych lasach przekierowania uwierzytelniania zwykle muszą podróżować do góry do korzenia lasu, a następnie w dół do docelowej domeny. Tworząc krzyżowe połączenia, podróż jest skracana, co jest szczególnie korzystne w rozproszonych geograficznie środowiskach.
* **Zaufania zewnętrzne**: Są one ustanawiane między różnymi, niepowiązanymi domenami i są niewspółrzędne z natury. Zgodnie z [dokumentacją Microsoftu](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), zaufania zewnętrzne są przydatne do uzyskiwania dostępu do zasobów w domenie spoza bieżącego lasu, który nie jest połączony zaufaniem lasu. Bezpieczeństwo jest wzmacniane poprzez filtrowanie SID z zaufaniami zewnętrznymi.
* **Zaufania korzenia drzewa**: Te zaufania są automatycznie ustanawiane między korzeniem lasu a nowo dodanym korzeniem drzewa. Chociaż nie są one powszechne, zaufania korzenia drzewa są ważne dla dodawania nowych drzew domenowych do lasu, umożliwiając im zachowanie unikalnej nazwy domeny i zapewniając dwukierunkową przechodniość. Więcej informacji można znaleźć w [przewodniku Microsoftu](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx).
* **Zaufania lasu**: Ten rodzaj zaufania to dwukierunkowe zaufanie przechodnie między dwoma korzeniami lasu, również stosujące filtrowanie SID w celu wzmocnienia środków bezpieczeństwa.
* **Zaufania MIT**: Te zaufania są ustanawiane z domenami Kerberos, zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120). Zaufania MIT są nieco bardziej specjalistyczne i przeznaczone dla środowisk wymagających integracji z systemami opartymi na Kerberos poza ekosystemem Windows.
#### Inne różnice w **zaufanych relacjach**

* Relacja zaufania może być również **przekazywana** (A zaufał B, B zaufał C, wtedy A zaufał C) lub **nieprzekazywana**.
* Relacja zaufania może być ustanowiona jako **zaufanie dwukierunkowe** (obie strony sobie ufają) lub jako **zaufanie jednokierunkowe** (tylko jedna strona ufa drugiej).

### Ścieżka ataku

1. **Wylicz** zaufane relacje
2. Sprawdź, czy jakikolwiek **podmiot bezpieczeństwa** (użytkownik/grupa/komputer) ma **dostęp** do zasobów **innego domeny**, być może poprzez wpisy ACE lub poprzez przynależność do grupy z innej domeny. Szukaj **relacji między domenami** (prawdopodobnie zaufanie zostało utworzone w tym celu).
3. W tym przypadku kerberoast może być kolejną opcją.
4. **Skompromituj** **konta**, które mogą **przełączać się** między domenami.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie poprzez trzy podstawowe mechanizmy:

* **Przynależność do lokalnej grupy**: Podmioty mogą być dodane do lokalnych grup na maszynach, takich jak grupa „Administratorzy” na serwerze, co daje im znaczącą kontrolę nad tą maszyną.
* **Przynależność do grupy z obcej domeny**: Podmioty mogą również być członkami grup w obcej domenie. Jednak skuteczność tego sposobu zależy od charakteru zaufania i zakresu grupy.
* **Listy kontroli dostępu (ACL)**: Podmioty mogą być określone w **ACL**, szczególnie jako jednostki w **ACE** w **DACL**, co daje im dostęp do określonych zasobów. Dla tych, którzy chcą zagłębić się w mechanikę ACL, DACL i ACE, whitepaper zatytułowany „[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)” jest nieocenionym źródłem wiedzy.

### Eskalacja przywilejów w lesie od dziecka do rodzica
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
{% hint style="warning" %}
Istnieją **2 zaufane klucze**, jeden dla _Dziecko --> Rodzic_ i drugi dla _Rodzic_ --> _Dziecko_.\
Możesz sprawdzić ten używany przez bieżącą domenę za pomocą:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### Wstrzyknięcie historii SID

Eskalacja jako administrator przedsiębiorstwa do domeny podrzędnej/nadrzędnej, nadużywając zaufania za pomocą wstrzyknięcia historii SID:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Wykorzystanie zapisywalnego NC konfiguracji

Zrozumienie, jak można wykorzystać Kontekst Nazw Konfiguracji (NC), jest kluczowe. NC konfiguracji służy jako centralne repozytorium danych konfiguracyjnych w całym lesie w środowiskach Active Directory (AD). Te dane są replikowane do każdego kontrolera domeny (DC) w lesie, a zapisywalne DC utrzymują zapisywalną kopię NC konfiguracji. Aby to wykorzystać, trzeba mieć **uprawnienia SYSTEM na DC**, najlepiej na DC podrzędnym.

**Połącz GPO z miejscem korzenia DC**

Kontener Miejsc NC konfiguracji zawiera informacje o wszystkich miejscach komputerów dołączonych do domeny w lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą połączyć GPO z miejscami korzenia DC. Ta akcja potencjalnie narusza domenę nadrzędną poprzez manipulowanie politykami stosowanymi do tych miejsc.

Dla bardziej szczegółowych informacji, można zgłębić badania na temat [Ominie SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Skompromituj dowolne gMSA w lesie**

Wektor ataku polega na celowaniu w uprzywilejowane gMSA w obrębie domeny. Klucz KDS Root, niezbędny do obliczania haseł gMSA, jest przechowywany w NC konfiguracji. Dzięki uprawnieniom SYSTEM na dowolnym DC, możliwe jest uzyskanie dostępu do klucza KDS Root i obliczenie haseł dla dowolnego gMSA w całym lesie.

Szczegółowa analiza znajduje się w dyskusji na temat [Ataków na Zaufanie Golden gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Atak na zmianę schematu**

Ta metoda wymaga cierpliwości, oczekując na utworzenie nowych uprzywilejowanych obiektów AD. Dzięki uprawnieniom SYSTEM, atakujący może zmodyfikować schemat AD, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu i kontroli nad nowo utworzonymi obiektami AD.

Dalsze informacje są dostępne na temat [Ataków na Zaufanie Zmiany Schematu](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Od DA do EA z ADCS ESC5**

Ukierunkowana na podatność ADCS ESC5 ma na celu przejęcie kontroli nad obiektami Infrastruktury Klucza Publicznego (PKI), aby utworzyć szablon certyfikatu umożliwiający uwierzytelnianie jako dowolny użytkownik w całym lesie. Ponieważ obiekty PKI znajdują się w NC konfiguracji, skompromitowanie zapisywalnego DC podrzędnego umożliwia wykonanie ataków ESC5.

Więcej szczegółów na ten temat można przeczytać w [Od DA do EA z ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). W scenariuszach, w których brakuje ADCS, atakujący ma możliwość skonfigurowania niezbędnych komponentów, jak omówiono w [Eskalacji z Administratorów Domeny Dzieci do Administratorów Przedsiębiorstwa](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Zewnętrzna Domena Lasu - Jednokierunkowa (Przychodząca) lub dwukierunkowa
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
W tym scenariuszu **twoja domena jest zaufana** przez zewnętrzną, co daje ci **nieokreślone uprawnienia** nad nią. Musisz dowiedzieć się, **które podmioty twojej domeny mają jakie dostępy do zewnętrznej domeny**, a następnie spróbować ją wykorzystać:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Zewnętrzna Domena Lasu - Jednokierunkowa (Wychodząca)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
W tym scenariuszu **twoja domena** udziela pewnych **uprawnień** podmiotowi z **innych domen**.

Jednak gdy **domena jest zaufana** przez domenę zaufaną, domena zaufana **tworzy użytkownika** o **przewidywalnej nazwie**, który używa jako **hasła zaufanego hasła**. Oznacza to, że istnieje możliwość **dostępu do użytkownika z domeny zaufanej, aby dostać się do zaufanej** i próbować eskalować więcej uprawnień:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Innym sposobem na skompromitowanie domeny zaufanej jest znalezienie [**zaufanego łącza SQL**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** zaufania domeny (co nie jest zbyt częste).

Innym sposobem na skompromitowanie domeny zaufanej jest czekanie na maszynie, do której **użytkownik z zaufanej domeny ma dostęp**, aby zalogować się za pomocą **RDP**. Następnie atakujący mógłby wstrzyknąć kod w proces sesji RDP i **uzyskać dostęp do domeny ofiary** stamtąd.\
Co więcej, jeśli **ofiara zamontowała swój dysk twardy**, z procesu sesji RDP atakujący mógłby przechowywać **tylnie drzwi** w **folderze uruchamiania dysku twardego**. Ta technika nazywa się **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Zastosowanie zabezpieczeń przed nadużyciami zaufania domenowego

### **Filtrowanie SID:**

* Ryzyko ataków wykorzystujących atrybut historii SID w obszarze zaufania między lasami jest łagodzone przez Filtrowanie SID, które jest domyślnie aktywowane we wszystkich obszarach zaufania między lasami. Leży to u podstaw założenia, że obszary zaufania wewnątrz lasu są bezpieczne, biorąc pod uwagę las, a nie domenę, jako granicę bezpieczeństwa zgodnie z stanowiskiem Microsoftu.
* Jednak jest haczyk: filtrowanie SID może zakłócać działanie aplikacji i dostęp użytkowników, co czasami prowadzi do jego czasowego wyłączenia.

### **Autoryzacja selektywna:**

* W obszarach zaufania między lasami stosowanie Autoryzacji selektywnej zapewnia, że użytkownicy z dwóch lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jasne uprawnienia, aby użytkownicy mieli dostęp do domen i serwerów w obrębie domeny lub lasu zaufającego.
* Ważne jest zauważenie, że te środki nie chronią przed wykorzystaniem zapisywalnego Kontekstu Nazw Konfiguracji (NC) ani atakami na konto zaufania.

[**Więcej informacji na temat zaufania domenowego na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Kilka ogólnych obron

[**Dowiedz się więcej o ochronie poświadczeń tutaj.**](../stealing-credentials/credentials-protections.md)\\

### **Środki obronne w zakresie ochrony poświadczeń**

* **Ograniczenia administratorów domeny**: Zaleca się, aby administratorzy domeny mieli możliwość logowania się tylko do kontrolerów domeny, unikając ich użycia na innych hostach.
* **Uprawnienia konta usługi**: Usługi nie powinny być uruchamiane z uprawnieniami administratora domeny (DA) w celu zachowania bezpieczeństwa.
* **Ograniczenie czasowe uprawnień**: Dla zadań wymagających uprawnień DA, ich czas trwania powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Wdrażanie technik dezinformacji**

* Wdrażanie dezinformacji polega na ustawianiu pułapek, takich jak użytkownicy lub komputery-pułapki, z funkcjami takimi jak hasła, które nie wygasają lub są oznaczone jako Zaufane do Delegacji. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi uprawnieniami lub dodawanie ich do grup o wysokich uprawnieniach.
* Praktycznym przykładem jest użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* Więcej informacji na temat wdrażania technik dezinformacji można znaleźć na stronie [Deploy-Deception na GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identyfikacja dezinformacji**

* **Dla obiektów użytkowników**: Podejrzane wskaźniki obejmują nietypowy ObjectSID, rzadkie logowania, daty utworzenia i niskie liczby złych haseł.
* **Ogólne wskaźniki**: Porównanie atrybutów potencjalnych obiektów-pułapek z atrybutami autentycznych obiektów może ujawnić niezgodności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikowaniu takich dezinformacji.

### **Ominiecie systemów wykrywania**

* **Ominięcie wykrywania Microsoft ATA**:
* **Wyliczenie użytkowników**: Unikanie wyliczania sesji na kontrolerach domeny w celu zapobieżenia wykryciu ATA.
* **Podszywanie się pod bilet**: Wykorzystanie kluczy **aes** do tworzenia biletów pomaga uniknąć wykrycia, nie degradując do NTLM.
* **Ataki DCSync**: Wykonywanie z komputera nie będącego kontrolerem domeny, aby uniknąć wykrycia ATA, jest zalecane, ponieważ bezpośrednie wykonanie z kontrolera domeny spowoduje wygenerowanie alertów.

## Odnośniki

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
