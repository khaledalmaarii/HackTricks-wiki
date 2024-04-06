# Active Directory Methodology

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowy przegląd

**Active Directory** służy jako technologia podstawowa, umożliwiając **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** i **obiektami** w sieci. Jest zaprojektowany w celu skalowania, ułatwiając organizację dużej liczby użytkowników w zarządzalne **grupy** i **podgrupy**, jednocześnie kontrolując **prawa dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech podstawowych warstw: **domen**, **drzew** i **lasów**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** lub **urządzenia**, które dzielą wspólną bazę danych. **Drzewa** to grupy tych domen połączone wspólną strukturą, a **las** reprezentuje zbiór wielu drzew, połączonych przez **relacje zaufania**, tworząc najwyższą warstwę struktury organizacyjnej. Na każdym z tych poziomów można określić konkretne **prawa dostępu** i **komunikacji**.

Kluczowe koncepcje w **Active Directory** obejmują:

1. **Katalog** - Zawiera wszystkie informacje dotyczące obiektów Active Directory.
2. **Obiekt** - Oznacza jednostki w katalogu, w tym **użytkowników**, **grupy** lub **udostępnione foldery**.
3. **Domena** - Służy jako kontener dla obiektów katalogowych, z możliwością współistnienia wielu domen w **lesie**, z każdą utrzymującą własny zbiór obiektów.
4. **Drzewo** - Grupowanie domen, które dzielą wspólną domenę nadrzędną.
5. **Las** - Szczyt struktury organizacyjnej w Active Directory, składający się z kilku drzew z **relacjami zaufania** między nimi.

**Usługi domenowe Active Directory (AD DS)** obejmują szereg usług niezbędnych do scentralizowanego zarządzania i komunikacji w sieci. Usługi te obejmują:

1. **Usługi domenowe** - Centralizuje przechowywanie danych i zarządza interakcjami między **użytkownikami** a **domenami**, w tym funkcjami **uwierzytelniania** i **wyszukiwania**.
2. **Usługi certyfikatów** - Nadzoruje tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Usługi lekkiego katalogu** - Obsługuje aplikacje obsługujące katalog za pomocą protokołu **LDAP**.
4. **Usługi federacji katalogowej** - Zapewnia możliwość **jednokrotnego logowania** w celu uwierzytelniania użytkowników w wielu aplikacjach internetowych w jednej sesji.
5. **Zarządzanie prawami** - Pomaga w ochronie materiałów objętych prawami autorskimi, regulując ich nieautoryzowane rozpowszechnianie i wykorzystywanie.
6. **Usługa DNS** - Istotna dla rozwiązywania **nazw domenowych**.

Aby uzyskać bardziej szczegółowe wyjaśnienie, sprawdź: [**TechTerms - Definicja Active Directory**](https://techterms.com/definition/active\_directory)

### **Uwierzytelnianie Kerberos**

Aby nauczyć się **atakować AD**, musisz bardzo dobrze zrozumieć **proces uwierzytelniania Kerberos**.\
[**Przeczytaj tę stronę, jeśli wciąż nie wiesz, jak to działa.**](kerberos-authentication.md)

## Cheat Sheet

Możesz przejść do [https://wadcoms.github.io/](https://wadcoms.github.io), aby szybko zobaczyć, jakie polecenia można uruchomić, aby wyliczyć/wykorzystać AD.

## Rozpoznawanie Active Directory (bez poświadczeń/sesji)

Jeśli masz dostęp do środowiska AD, ale nie masz żadnych poświadczeń/sesji, możesz:

* **Testuj sieć:**
* Przeskanuj sieć, znajdź maszyny i otwarte porty, a następnie spróbuj **wykorzystać podatności** lub **wydobyć poświadczenia** z nich (na przykład [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md)).
* Wyliczenie DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak serwery WWW, drukarki, udziały, VPN, media itp.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Zapoznaj się z ogólną [**Metodologią Pentestingu**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby uzyskać więcej informacji na ten temat.
* **Sprawdź dostęp do usług smb dla wartości null i Guest** (to nie zadziała w nowoczesnych wersjach systemu Windows):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Bardziej szczegółowy przewodnik dotyczący wyliczania serwera SMB można znaleźć tutaj:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Wyliczanie LDAP**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Bardziej szczegółowy przewodnik dotyczący wyliczania LDAP można znaleźć tutaj (zwróć **szczególną uwagę na dostęp anonimowy**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Zatrute sieć**
* Zbieraj poświadczenia \[\*\*udając usługi za pomocą Res

### Wyliczanie użytkowników

* **Wyliczanie anonimowe SMB/LDAP:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Wyliczanie Kerbrute**: Gdy zostanie żądane **nieprawidłowe nazwa użytkownika**, serwer odpowie kodem błędu Kerberos _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, co pozwala nam stwierdzić, że nazwa użytkownika jest nieprawidłowa. **Prawidłowe nazwy użytkowników** spowodują odpowiedź zawierającą **TGT w odpowiedzi AS-REP** lub błąd _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, wskazujący, że użytkownik musi wykonać wstępną autoryzację.

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
Możesz znaleźć listy nazw użytkowników w [**tym repozytorium GitHub**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* oraz w tym ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

Jednak powinieneś mieć **imiona i nazwiska osób pracujących w firmie** z etapu rozpoznania, który powinieneś wykonać wcześniej. Z imieniem i nazwiskiem możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951), aby wygenerować potencjalnie prawidłowe nazwy użytkowników.
{% endhint %}

### Znając jedno lub kilka nazw użytkowników

Ok, więc wiesz, że masz już prawidłową nazwę użytkownika, ale nie masz hasła... W takim przypadku spróbuj:

* [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT\_REQ\_PREAUTH_, możesz **żądać wiadomości AS\_REP** dla tego użytkownika, która będzie zawierać pewne dane zaszyfrowane za pomocą pochodnej hasła użytkownika.
* [**Password Spraying**](password-spraying.md): Spróbuj najbardziej **popularnych haseł** dla każdego z odkrytych użytkowników, być może jakiś użytkownik używa słabego hasła (pamiętaj o polityce haseł!).
* Zauważ, że możesz również **spróbować ataku na serwery OWA**, aby uzyskać dostęp do skrzynek pocztowych użytkowników.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Zatrucie LLMNR/NBT-NS

Możesz być w stanie **uzyskać** pewne **skróty wyzwań** do złamania, **zatruwając** niektóre protokoły **sieciowe**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

Jeśli udało ci się wyliczyć katalog aktywnego, będziesz mieć **więcej adresów e-mail i lepsze zrozumienie sieci**. Możesz próbować **ataków przekierowania NTML** \*\*\*\* w celu uzyskania dostępu do środowiska AD.

### Kradzież poświadczeń NTLM

Jeśli masz **dostęp do innych komputerów lub udziałów** za pomocą **użytkownika null lub gościa**, możesz **umieścić pliki** (np. plik SCF), które jeśli zostaną somehow accessed, spowodują **uwierzytelnienie NTML przeciwko tobie**, dzięki czemu możesz **ukraść** wyzwanie **NTLM**, aby je złamać:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Wyliczanie katalogu aktywnego Z UŻYCIEM poświadczeń/sesji

W tej fazie musisz **zdobyć poświadczenia lub sesję ważnego konta domeny**. Jeśli masz ważne poświadczenia lub powłokę jako użytkownik domeny, **pamiętaj, że opcje podane wcześniej nadal są opcjami do kompromitacji innych użytkowników**.

Przed rozpoczęciem uwierzytelnionego wyliczania powinieneś wiedzieć, co to jest **problem podwójnego skoku Kerberos**.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Wyliczanie

Posiadanie skompromitowanego konta to **duży krok w kierunku kompromitacji całej domeny**, ponieważ będziesz mógł rozpocząć **Wyliczanie katalogu aktywnego**:

W odniesieniu do [**ASREPRoast**](asreproast.md) możesz teraz znaleźć wszystkich potencjalnie podatnych użytkowników, a w odniesieniu do [**Password Spraying**](password-spraying.md) możesz uzyskać **listę wszystkich nazw użytkowników** i sprawdzić hasło skompromitowanego konta, puste hasła i nowe obiecujące hasła.

* Możesz użyć [**CMD do wykonania podstawowego rozpoznania**](../basic-cmd-for-pentesters.md#domain-info)
* Możesz również użyć [**powershell do rozpoznania**](../basic-powershell-for-pentesters/), co będzie bardziej stealthowe
* Możesz również [**użyć powerview**](../basic-powershell-for-pentesters/powerview.md), aby uzyskać bardziej szczegółowe informacje
* Innym niesamowitym narzędziem do rozpoznania w katalogu aktywnym jest [**BloodHound**](bloodhound.md). Jest **niezbyt stealthowy** (w zależności od używanych metod zbierania danych), ale **jeśli nie przeszkadza ci to**, zdecydowanie warto spróbować. Znajdź, gdzie użytkownicy mogą się zdalnie połączyć, znajdź ścieżkę do innych grup itp.
* **Inne zautomatyzowane narzędzia do wyliczania katalogu aktywnego to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Rekordy DNS AD**](ad-dns-records.md), ponieważ mogą zawierać interesujące informacje.
* Narzędzie z interfejsem graficznym, które można użyć do wyliczania katalogu, to **AdExplorer.exe** z pakietu **SysInternal** Suite.
* Możesz również przeszukiwać bazę danych LDAP za pomocą **ldapsearch**, aby szukać poświadczeń w polach _userPassword_ & _unixUserPassword_, a nawet w _Description_. Por. [Hasło w komentarzu użytkownika AD na PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) dla innych metod.
* Jeśli używasz **Linuxa**, możesz również wyliczyć domenę za pomocą [**pywerview**](https://github.com/the-useless-one/pywerview).
* Możesz również spróbować zautomatyzowanych narzędzi takich jak:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
* **Wyodrębnianie wszystkich użytkowników domeny**

Bardzo łatwo uzyskać wszystkie nazwy użytkowników domeny w systemie Windows (`net user /domain`, `Get-DomainUser` lub `wmic useraccount get name,sid`). W systemie Linux można użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Chociaż ta sekcja Wyliczanie wydaje się niewielka, jest to najważniejsza część. Przejdź do linków (głównie do cmd, powershell, powerview i BloodHound), naucz się, jak wyliczać domenę i ćwicz, aż poczujesz się komfortowo. Podczas oceny, to będzie kluczowy moment, aby znaleźć drogę do DA lub zdecydować, że nic nie można zrobić.

### Kerberoasting

Kerberoasting polega na uzyskaniu **biletów TGS** używanych przez usługi powiązane z kontami użytkowników i złamaniu ich szyfrowania - które opiera się na hasłach użytkowników - **offline**.

Więcej na ten temat w:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Połączenie zdalne (RDP, SSH, FTP, Win-RM, itp.)

Po uzyskaniu pewnych poświadczeń, możesz sprawdzić, czy masz dostęp do jakiejkolwiek **maszyny**. W tym celu możesz użyć **CrackMapExec**, aby spróbować połączyć się z kilkoma serwerami za pomocą różnych protokołów, zgodnie z przeskanowanymi portami.

### Eskalacja uprawnień lokalnych

Jeśli masz skompromitowane poświadczenia lub sesję jako zwykły użytkownik domeny i masz **dostęp** do **jakiejkolwiek maszyny w domenie** za pomocą tego użytkownika, powinieneś spróbować znaleźć sposób na **eskalację uprawnień lokalnych i zdobycie poświadczeń**. Jest to konieczne, ponieważ tylko posiadając uprawnienia lokalnego administratora, będziesz w stanie **wydobyć hashe innych użytkowników** z pamięci (LSASS) i lokalnie (SAM).

W tej książce znajduje się kompletna strona na temat [**eskalacji uprawnień lokalnych w systemie Windows**](../windows-local-privilege-escalation/) oraz [**checklista**](../checklist-windows-privilege-escalation.md). Nie zapomnij również użyć narzędzia [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Bieżące bilety sesji

Jest mało **prawdopodobne**, że znajdziesz **bilety** w bieżącym użytkowniku, które dają ci uprawnienia do dostępu do nieoczekiwanych zasobów, ale możesz to sprawdzić:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTML Relay

Jeśli udało ci się wyliczyć aktywny katalog, będziesz mieć **więcej adresów e-mail i lepsze zrozumienie sieci**. Możesz próbować **przeprowadzić ataki przekazywania NTML**.

### Szukanie poświadczeń w udostępnionych folderach komputera

Teraz, gdy masz pewne podstawowe poświadczenia, powinieneś sprawdzić, czy możesz **znaleźć** jakieś **interesujące pliki udostępniane wewnątrz AD**. Możesz to zrobić ręcznie, ale to bardzo nudne i powtarzalne zadanie (zwłaszcza jeśli znajdziesz setki dokumentów, które musisz sprawdzić).

[**Kliknij tutaj, aby dowiedzieć się o narzędziach, których możesz użyć.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### Kradzież poświadczeń NTLM

Jeśli masz **dostęp do innych komputerów lub folderów**, możesz **umieścić pliki** (np. plik SCF), które, jeśli zostaną w jakiś sposób otwarte, spowodują **uwierzytelnienie NTML przeciwko tobie**, dzięki czemu będziesz mógł **ukraść** wyzwanie **NTLM**, aby je złamać:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta podatność umożliwiała każdemu uwierzytelnionemu użytkownikowi **skompromitowanie kontrolera domeny**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Eskalacja uprawnień w Active Directory Z uprzywilejowanymi poświadczeniami/sesją

**Do wykonania poniższych technik nie wystarczy zwykły użytkownik domeny, potrzebujesz specjalnych uprawnień/poświadczeń, aby przeprowadzić te ataki.**

### Wydobycie haszy

Mam nadzieję, że udało ci się **skompromitować konto lokalnego administratora** za pomocą [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) wraz z przekazywaniem, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [eskalacji uprawnień lokalnych](../windows-local-privilege-escalation/).\
Nadszedł czas, aby wydobyć wszystkie hasze z pamięci i lokalnie.\
[**Przeczytaj tę stronę, aby dowiedzieć się o różnych sposobach uzyskania haseł.**](https://github.com/carlospolop/hacktricks/blob/pl/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Przekazanie hasza

**Po uzyskaniu hasza użytkownika** możesz go użyć do **udawania** tego użytkownika.\
Musisz użyć **narzędzia**, które **przeprowadzi** uwierzytelnianie **NTLM, używając** tego **hasza**, **lub** możesz utworzyć nową **sesję logowania** i **wstrzyknąć** ten **hasz** do **LSASS**, więc gdy zostanie wykonane jakiekolwiek **uwierzytelnianie NTLM**, ten **hasz zostanie użyty**. Ostatnia opcja to to, co robi mimikatz.\
[**Przeczytaj tę stronę, aby uzyskać więcej informacji.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **użycie hasza NTLM użytkownika do żądania biletów Kerberos**, jako alternatywy dla powszechnego przekazywania hasza za pośrednictwem protokołu NTLM. Dlatego może to być szczególnie **użyteczne w sieciach, w których protokół NTLM jest wyłączony**, a jedynie **Kerberos jest dozwolony** jako protokół uwierzytelniania.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Przekazanie biletu

W metodzie ataku **Pass The Ticket (PTT)**, atakujący **kradnie bilet uwierzytelniania użytkownika** zamiast hasła lub wartości skrótu. Skradziony bilet jest następnie używany do **udawania użytkownika**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Ponowne wykorzystanie poświadczeń

Jeśli masz **hasz** lub **hasło** lokalnego **administratora**, spróbuj zalogować się lokalnie na inne **komputery** za jego pomocą.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

{% hint style="warning" %}
Zauważ, że jest to dość **hałaśliwe**, a **LAPS** może to **zmniejszyć**.
{% endhint %}

### Nadużycie MSSQL i zaufane linki

Jeśli użytkownik ma uprawnienia do **dostępu do instancji MSSQL**, może go wykorzystać do **wykonywania poleceń** na hoście MSSQL (jeśli działa jako SA), **kradzieży** hasha NetNTLM lub nawet przeprowadzenia **ataków przekazywania**.\
Ponadto, jeśli instancja MSSQL jest zaufana (link bazy danych) przez inną instancję MSSQL. Jeśli użytkownik ma uprawnienia do zaufanej bazy danych, będzie mógł **używać relacji zaufania do wykonywania zapytań również w innej instancji**. Te zaufania mogą być łańcuchowe i w pewnym momencie użytkownik może znaleźć źle skonfigurowaną bazę danych, w której może wykonywać polecenia.\
**Linki między bazami danych działają nawet w przypadku zaufania między lasami.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Nieograniczone przekazywanie

Jeśli znajdziesz jakikolwiek obiekt komputera z atrybutem [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) i masz uprawnienia domeny na tym komputerze, będziesz mógł wydobyć TGT z pamięci każdego użytkownika, który loguje się na ten komputer.\
Więc jeśli **administrator domeny zaloguje się na ten komputer**, będziesz mógł wydobyć jego TGT i podszywać się pod niego, używając [Pass the Ticket](pass-the-ticket.md).\
Dzięki ograniczonemu przekazywaniu możesz nawet **automatycznie przejąć serwer drukowania** (oby był to DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Ograniczone przekazywanie

Jeśli użytkownik lub komputer ma uprawnienia do "Ograniczonego przekazywania", będzie mógł **udawać dowolnego użytkownika, aby uzyskać dostęp do niektórych usług na komputerze**.\
Następnie, jeśli **uzyskasz dostęp do hasha** tego użytkownika/komputera, będziesz mógł **udawać dowolnego użytkownika** (nawet administratorów domeny), aby uzyskać dostęp do niektórych usług.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Ograniczone przekazywanie oparte na zasobach

Posiadanie uprawnień **WRITE** do obiektu Active Directory zdalnego komputera umożliwia wykonanie kodu z **podwyższonymi uprawnieniami**:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Nadużycie ACL

Skompromitowany użytkownik może mieć pewne **interesujące uprawnienia wobec niektórych obiektów domeny**, które mogą umożliwić **przesuwanie się** po boku/**podwyższanie** uprawnień.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Nadużycie usługi drukowania

Odkrycie **nasłuchującej usługi drukowania** w domenie może być **nadużywane** do **uzyskania nowych poświadczeń** i **podwyższenia uprawnień**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Nadużycie sesji osób trzecich

Jeśli **inni użytkownicy** **uzyskają dostęp** do **skompromitowanego** komputera, można **pobrać poświadczenia z pamięci** i nawet **wstrzyknąć beacons w ich procesy**, aby udawać ich.\
Zwykle użytkownicy będą uzyskiwać dostęp do systemu za pomocą RDP, więc tutaj masz, jak przeprowadzić kilka ataków na sesje RDP osób trzecich:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** zapewnia system zarządzania **hasłem lokalnego administratora** na komputerach dołączonych do domeny, zapewniając, że jest **losowe**, unikalne i często **zmieniane**. Te hasła są przechowywane w Active Directory, a dostęp jest kontrolowany za pomocą list kontroli dostępu (ACL) tylko dla uprawnionych użytkowników. Posiadając wystarczające uprawnienia do dostępu do tych haseł, możliwe staje się przechodzenie do innych komputerów.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Kradzież certyfikatów

**Pobieranie certyfikatów** z zainfekowanego komputera może być sposobem na podwyższenie uprawnień w środowisku:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Nadużycie szablonów certyfikatów

Jeśli są skonfigurowane **podatne szablony**, można je nadużywać do podwyższania uprawnień:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-eksploatacja z kontem o wysokich uprawnieniach

### Wydobywanie poświadczeń domeny

Po uzyskaniu uprawnień **administratora domeny** lub nawet lepiej **administratora przedsiębiorstwa**, można **wydobyć** bazę danych domeny: _ntds.dit_.

[**Więcej informacji na temat ataku DCSync można znaleźć tutaj**](dcsync.md).

[**Więcej informacji na temat kradzieży NTDS.dit można znaleźć tutaj**](https://github.com/carlospolop/hacktricks/blob/pl/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Przywileje jako trwałość

Niektóre z omówionych wcześniej technik można wykorzystać do trwałości.\
Na przykład można:

* Uczynić użytkowników podatnymi na [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <nazwa_użytkownika> -Set @{serviceprincipalname="fake/NOTHING"}r
```

* Uczynić użytkowników podatnymi na [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <nazwa_użytkownika> -XOR @{UserAccountControl=4194304}
```

* Przyznać uprawnienia [**DCSync**](./#dcsync) użytkownikowi

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Bilet srebrny

Atak **Silver Ticket** tworzy **legitymacyjny bilet usługi Ticket Granting Service (TGS)** dla określonej usługi, używając **hasza NTLM** (na przykład hasza konta PC). Ta metoda jest stosowana do **uzyskania dostępu do uprawnień usługi**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Bilet złoty

Atak **Golden Ticket** polega na uzyskaniu dostępu do **hasza NTLM konta krbtgt** w środowisku Active Directory (AD). To konto jest specjalne, ponieważ służy do podpisywania wszystkich **Ticket Granting Tickets (TGT)**, które są niezbędne do uwierzytelniania w sieci AD.

Po uzyskaniu tego hasza, atakujący może tworzyć **TGT** dla dowolnego wybranego konta (atak Silver ticket).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Bilet diamentowy

Są to jak złote bilety sfałszowane w taki sposób, że \*\*omijają powszechne mechanizmy wykrywania złotych b

### **Trwałość domeny za pomocą certyfikatów**

**Za pomocą certyfikatów można również trwale zasiedlić domenę z wysokimi uprawnieniami:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Grupa AdminSDHolder

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **grup uprzywilejowanych** (takich jak Administratorzy domeny i Administratorzy przedsiębiorstwa), stosując standardową **listę kontroli dostępu (ACL)** dla tych grup w celu zapobiegania nieautoryzowanym zmianom. Jednak ta funkcja może być wykorzystana; jeśli atakujący zmodyfikuje ACL AdminSDHolder, aby dać pełny dostęp zwykłemu użytkownikowi, ten użytkownik uzyskuje rozległą kontrolę nad wszystkimi grupami uprzywilejowanymi. Ta środek bezpieczeństwa, mający na celu ochronę, może więc przynieść odwrotny skutek, umożliwiając nieuprawniony dostęp, chyba że jest śledzony.

[**Więcej informacji na temat grupy AdminSDHolder tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

W każdym **kontrolerze domeny (DC)** istnieje **lokalne konto administratora**. Uzyskując uprawnienia administratora na takim urządzeniu, można wyodrębnić skrót lokalnego administratora za pomocą **mimikatz**. Następnie konieczna jest modyfikacja rejestru w celu **włączenia użycia tego hasła**, umożliwiając zdalny dostęp do konta lokalnego administratora.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Trwałość ACL

Możesz **przyznać** pewne **specjalne uprawnienia** użytkownikowi w odniesieniu do określonych obiektów domenowych, które pozwolą użytkownikowi **zwiększyć uprawnienia w przyszłości**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Deskryptory zabezpieczeń

Deskryptory zabezpieczeń są używane do **przechowywania** uprawnień, jakie **obiekt** ma **nad** innym **obiektem**. Jeśli możesz **wykonać** małą **zmianę** w deskryptorze zabezpieczeń obiektu, możesz uzyskać bardzo interesujące uprawnienia do tego obiektu, nie będąc członkiem grupy uprzywilejowanej.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Skeleton Key

Zmodyfikuj **LSASS** w pamięci, aby ustawić **uniwersalne hasło**, umożliwiające dostęp do wszystkich kont domenowych.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### Niestandardowy SSP

[Dowiedz się, czym jest SSP (Security Support Provider) tutaj.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Możesz stworzyć **własny SSP**, aby **przechwycić** w **czystym tekście** dane uwierzytelniające używane do dostępu do maszyny.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Rejestruje **nowy kontroler domeny** w AD i używa go do **wprowadzania atrybutów** (SIDHistory, SPN...) na określone obiekty **bez** pozostawiania **logów** dotyczących **modyfikacji**. Potrzebujesz uprawnień DA i musisz znajdować się w **domenie głównej**.\
Należy pamiętać, że jeśli użyjesz nieprawidłowych danych, pojawią się nieładne logi.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Trwałość LAPS

Wcześniej omówiliśmy, jak zwiększyć uprawnienia, jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Jednak te hasła można również wykorzystać do **utrzymania trwałości**.\
Sprawdź:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Eskalacja uprawnień w lesie - Zaufanie domenowe

Microsoft traktuje **Las** jako granicę bezpieczeństwa. Oznacza to, że **skompromitowanie pojedynczej domeny może potencjalnie prowadzić do skompromitowania całego Lasu**.

### Podstawowe informacje

[**Zaufanie domenowe**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) to mechanizm bezpieczeństwa, który umożliwia użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. Tworzy ono połączenie między systemami uwierzytelniania dwóch domen, umożliwiając płynne przepływanie weryfikacji uwierzytelniania. Gdy domeny ustanawiają zaufanie, wymieniają i przechowują określone **klucze** w swoich **kontrolerach domeny (DC)**, które są kluczowe dla integralności zaufania.

W typowym scenariuszu, jeśli użytkownik chce uzyskać dostęp do usługi w **zaufanej domenie**, musi najpierw poprosić o specjalny bilet znanym jako **inter-realm TGT** od swojego własnego DC domeny. Ten TGT jest szyfrowany za pomocą wspólnego **klucza**, na który obie domeny się zgodziły. Następnie użytkownik przedstawia ten TGT **DC zaufanej domeny**, aby uzyskać bilet usługi (**TGS**). Po pomyślnym zweryfikowaniu inter-realm TGT przez DC zaufanej domeny, wydaje on TGS, udzielając użytkownikowi dostępu do usługi.

**Kroki**:

1. **Komputer klienta** w **Domenie 1** rozpoczyna proces, używając swojego **skrótu NTLM** do żądania **Ticket Granting Ticket (TGT)** od swojego **kontrolera domeny (DC1)**.
2. DC1 wydaje nowe TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Klient następnie żąda **inter-realm TGT** od DC1, który jest potrzebny do dostępu do zasobów w **Domenie 2**.
4. Inter-realm TGT jest szyfrowany za pomocą **klucza zaufania** współdzielonego między DC1 a DC2 jako część dwukierunkowego zaufania między domenami.
5. Klient zabiera inter-realm TGT do **kontrolera domeny (DC2) Domeny 2**.
6. DC2 weryfikuje inter-realm TGT za pomocą współdzielonego klucza zaufania i jeśli jest ważny, wydaje **Ticket Granting Service (TGS)** dla serwera w Domenie 2, do którego klient chce uzyskać dostęp.
7. Wreszcie klient przedstawia ten TGS serwerowi, który jest szyfrowany za pomocą skrótu konta serwera, aby uzyskać dostęp do usługi w Domenie 2.

### Różne zaufania

Warto zauważyć, że **zaufanie może być jednostronne lub dwustronne**. W przypadku dwustronnych opcji obie domeny będą sobie ufać, ale w relacji zaufania \*\*jednostr

#### Inne różnice w **relacjach zaufania**

* Relacja zaufania może być również **przekazywalna** (A ufa B, B ufa C, wtedy A ufa C) lub **nieprzekazywalna**.
* Relacja zaufania może być ustanowiona jako **dwukierunkowa** (oba ufają sobie nawzajem) lub jako **jednokierunkowa** (tylko jedno z nich ufa drugiemu).

### Ścieżka ataku

1. **Wylicz** relacje zaufania.
2. Sprawdź, czy jakikolwiek **podmiot bezpieczeństwa** (użytkownik/grupa/komputer) ma **dostęp** do zasobów **innego domeny**, być może poprzez wpisy ACE lub poprzez przynależność do grupy z innej domeny. Szukaj **relacji między domenami** (prawdopodobnie relacja zaufania została utworzona w tym celu).
3. W tym przypadku kerberoast może być inną opcją.
4. **Skompromituj** konta, które mogą **przejść** przez domeny.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie za pomocą trzech podstawowych mechanizmów:

* **Przynależność do lokalnej grupy**: Podmioty mogą zostać dodane do lokalnych grup na maszynach, takich jak grupa "Administratorzy" na serwerze, co daje im znaczącą kontrolę nad tą maszyną.
* **Przynależność do grupy z obcej domeny**: Podmioty mogą również być członkami grup w obcej domenie. Jednak skuteczność tego sposobu zależy od charakteru relacji zaufania i zakresu grupy.
* **Listy kontroli dostępu (ACL)**: Podmioty mogą być określone w **ACL**, zwłaszcza jako jednostki w **ACE** w **DACL**, co daje im dostęp do określonych zasobów. Dla tych, którzy chcą zagłębić się w mechanikę ACL, DACL i ACE, wartościowym źródłem informacji jest whitepaper o tytule "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)".

### Eskalacja uprawnień w lesie od dziecka do rodzica

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

#### Wstrzykiwanie SID-History

Eskalacja jako administrator przedsiębiorstwa do domeny podrzędnej/rodzicielskiej, wykorzystując zaufanie poprzez wstrzykiwanie SID-History:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Wykorzystanie zapisywalnego NC konfiguracji

Zrozumienie, jak można wykorzystać NC konfiguracji (Configuration Naming Context), jest kluczowe. NC konfiguracji służy jako centralne repozytorium danych konfiguracyjnych w środowiskach Active Directory (AD). Te dane są replikowane do każdego kontrolera domeny (DC) w obrębie lasu, a kontrolery DC zapisywalne utrzymują zapisywalną kopię NC konfiguracji. Aby wykorzystać to, trzeba mieć **uprawnienia SYSTEM na DC**, najlepiej na DC podrzędnym.

**Połącz GPO z główną lokalizacją DC**

Kontener Sites NC konfiguracji zawiera informacje o lokalizacjach wszystkich komputerów dołączonych do domeny w obrębie lasu AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący może połączyć GPO z głównymi lokalizacjami DC. Ta akcja potencjalnie kompromituje domenę główną poprzez manipulację politykami stosowanymi do tych lokalizacji.

Aby uzyskać szczegółowe informacje, można zapoznać się z badaniami na temat [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Skompromituj dowolne gMSA w lesie**

Wektor ataku polega na celowaniu w uprzywilejowane gMSA w obrębie domeny. Klucz KDS Root, niezbędny do obliczania haseł gMSA, jest przechowywany w NC konfiguracji. Dzięki uprawnieniom SYSTEM na dowolnym DC możliwe jest uzyskanie dostępu do klucza KDS Root i obliczenie haseł dla dowolnej gMSA w całym lesie.

Szczegółowa analiza znajduje się w dyskusji na temat [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Atak na zmianę schematu**

Ta metoda wymaga cierpliwości, oczekiwania na utworzenie nowych uprzywilejowanych obiektów AD. Dzięki uprawnieniom SYSTEM atakujący może zmodyfikować schemat AD, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu i kontroli nad nowo utworzonymi obiektami AD.

Więcej informacji można znaleźć w artykule [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Od DA do EA z ADCS ESC5**

Podatność ADCS ESC5 dotyczy kontroli nad obiektami infrastruktury klucza publicznego (PKI), aby utworzyć szablon certyfikatu umożliwiający uwierzytelnianie jako dowolny użytkownik w obrębie lasu. Ponieważ obiekty PKI znajdują się w NC konfiguracji, skompromitowanie zapisywalnego DC podrzędnego umożliwia przeprowadzenie ataków ESC5.

Więcej szczegółów na ten temat można przeczytać w artykule [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). W przypadku braku ADCS, atakujący ma możliwość skonfigurowania niezbędnych komponentów, o czym mówi [Eskalacja od administratorów domeny podrzędnej do administratorów przedsiębiorstwa](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Zewnętrzna domena lasu - jednokierunkowa (przychodząca) lub dwukierunkowa

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

W tym scenariuszu **twoja domena jest zaufana** przez zewnętrzną domenę, co daje ci **nieokreślone uprawnienia** nad nią. Będziesz musiał znaleźć **jakie podmioty twojej domeny mają jakie dostępy do zewnętrznej domeny** i spróbować je wykorzystać:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Zewnętrzna domena leśna - jednokierunkowa (wychodząca)

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

W tym scenariuszu **twoja domena** udziela pewnych **uprawnień** podmiotowi z **innej domeny**.

Jednak gdy **domena jest zaufana** przez domenę zaufaną, domena zaufana **tworzy użytkownika** o **przewidywalnej nazwie**, który używa jako **hasła zaufanego hasła**. Oznacza to, że możliwe jest **uzyskanie dostępu do użytkownika z domeny zaufanej, aby dostać się do domeny zaufanej** i przeprowadzić jej enumerację oraz próbować eskalacji uprawnień:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Innym sposobem na skompromitowanie domeny zaufanej jest znalezienie [**zaufanego połączenia SQL**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** do zaufania domeny (co nie jest zbyt powszechne).

Innym sposobem na skompromitowanie domeny zaufanej jest czekanie na maszynie, do której **użytkownik z domeny zaufanej ma dostęp**, aby zalogować się za pomocą **RDP**. Następnie atakujący mógłby wstrzyknąć kod w proces sesji RDP i **uzyskać dostęp do domeny pochodzenia ofiary**.\
Ponadto, jeśli **ofiara zamontowała swój dysk twardy**, atakujący mógłby przechowywać **tylnymi drzwiami** w **folderze uruchamiania dysku twardego** z procesu sesji RDP. Ta technika nazywa się **RDPInception**.

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Zapobieganie nadużyciom zaufania domeny

### **Filtrowanie SID:**

* Ryzyko ataków wykorzystujących atrybut historii SID w zaufanych lasach jest ograniczone przez filtrowanie SID, które jest domyślnie aktywowane we wszystkich zaufanych lasach. Założeniem jest, że zaufane lasy są bezpieczne, biorąc pod uwagę las, a nie domenę, jako granicę bezpieczeństwa zgodnie z podejściem Microsoftu.
* Jednak jest pewne ograniczenie: filtrowanie SID może zakłócać działanie aplikacji i dostęp użytkowników, co czasami prowadzi do jego dezaktywacji.

### **Autoryzacja selektywna:**

* W przypadku zaufanych lasów, zastosowanie autoryzacji selektywnej zapewnia, że użytkownicy z dwóch lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są jasne uprawnienia, aby użytkownicy mogli uzyskać dostęp do domen i serwerów w obrębie domeny lub lasu zaufanego.
* Ważne jest zauważenie, że te środki nie chronią przed wykorzystaniem zapisywalnego kontekstu nazwy konfiguracji (NC) ani przed atakami na konto zaufania.

[**Więcej informacji na temat zaufania domenowego na stronie ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Kilka ogólnych zabezpieczeń

[**Dowiedz się więcej o ochronie poświadczeń tutaj.**](../stealing-credentials/credentials-protections.md)\\

### **Środki obronne dla ochrony poświadczeń**

* **Ograniczenia administratorów domeny**: Zaleca się, aby administratorzy domeny mieli możliwość logowania się tylko do kontrolerów domeny, unikając ich użycia na innych hostach.
* **Uprawnienia konta usługi**: Usługi nie powinny być uruchamiane z uprawnieniami administratora domeny (DA) w celu utrzymania bezpieczeństwa.
* **Ograniczenie czasowe uprawnień**: Czas trwania zadań wymagających uprawnień DA powinien być ograniczony. Można to osiągnąć za pomocą polecenia: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Wdrażanie technik dezinformacyjnych**

* Wdrażanie dezinformacji polega na ustawianiu pułapek, takich jak użytkownicy lub komputery-pułapki, z cechami takimi jak hasła, które nie wygasają lub są oznaczone jako zaufane do delegacji. Szczegółowe podejście obejmuje tworzenie użytkowników o określonych uprawnieniach lub dodawanie ich do grup o wysokich uprawnieniach.
* Praktycznym przykładem jest użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* Więcej informacji na temat wdrażania technik dezinformacyjnych można znaleźć na stronie [Deploy-Deception na GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identyfikowanie dezinformacji**

* **Dla obiektów użytkowników**: Podejrzane wskaźniki obejmują nietypowy ObjectSID, rzadkie logowania, daty utworzenia i niskie liczniki złych haseł.
* **Ogólne wskaźniki**: Porównanie atrybutów potencjalnych obiektów-pułapek z atrybutami prawdziwych obiektów może ujawnić niezgodności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikacji takich dezinformacji.

### **Ominiecie systemów wykrywania**

* **Ominięcie wykrywania Microsoft ATA**:
* **Wyliczanie użytkowników**: Unikanie wyliczania sesji na kontrolerach domeny w celu uniknięcia wykrycia przez ATA.
* **Podszywanie się pod bilet**: Wykorzystanie kluczy **aes** do tworzenia biletów pomaga uniknąć wykrycia poprzez brak degradacji do NTLM.
* **Ataki DCSync**: Zaleca się wykonanie ich z maszyny niebędącej kontrolerem domeny, aby uniknąć wykrycia przez ATA, ponieważ bezpośrednie wykonanie z kontrolera domeny spowoduje wygenerowanie alertów.

## Odnośniki

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github

</details>
