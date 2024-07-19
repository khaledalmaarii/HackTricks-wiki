# Metodologia Active Directory

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## Podstawowy przegląd

**Active Directory** służy jako podstawowa technologia, umożliwiająca **administratorom sieci** efektywne tworzenie i zarządzanie **domenami**, **użytkownikami** i **obiektami** w sieci. Jest zaprojektowane do skalowania, ułatwiając organizację dużej liczby użytkowników w zarządzalne **grupy** i **podgrupy**, jednocześnie kontrolując **prawa dostępu** na różnych poziomach.

Struktura **Active Directory** składa się z trzech głównych warstw: **domen**, **drzew** i **lasy**. **Domena** obejmuje zbiór obiektów, takich jak **użytkownicy** lub **urządzenia**, które dzielą wspólną bazę danych. **Drzewa** to grupy tych domen połączone wspólną strukturą, a **las** reprezentuje zbiór wielu drzew, połączonych przez **relacje zaufania**, tworząc najwyższą warstwę struktury organizacyjnej. Specyficzne **prawa dostępu** i **prawa komunikacji** mogą być przypisane na każdym z tych poziomów.

Kluczowe pojęcia w **Active Directory** obejmują:

1. **Katalog** – Zawiera wszystkie informacje dotyczące obiektów Active Directory.
2. **Obiekt** – Oznacza byty w katalogu, w tym **użytkowników**, **grupy** lub **udostępnione foldery**.
3. **Domena** – Służy jako kontener dla obiektów katalogu, z możliwością współistnienia wielu domen w **lesie**, z każdą utrzymującą własny zbiór obiektów.
4. **Drzewo** – Grupa domen, które dzielą wspólną domenę główną.
5. **Las** – Szczyt struktury organizacyjnej w Active Directory, składający się z kilku drzew z **relacjami zaufania** między nimi.

**Usługi domen Active Directory (AD DS)** obejmują szereg usług krytycznych dla centralnego zarządzania i komunikacji w sieci. Usługi te obejmują:

1. **Usługi domen** – Centralizują przechowywanie danych i zarządzają interakcjami między **użytkownikami** a **domenami**, w tym funkcjonalności **uwierzytelniania** i **wyszukiwania**.
2. **Usługi certyfikatów** – Nadzorują tworzenie, dystrybucję i zarządzanie bezpiecznymi **certyfikatami cyfrowymi**.
3. **Usługi lekkiego katalogu** – Wspierają aplikacje z katalogiem za pomocą **protokół LDAP**.
4. **Usługi federacji katalogów** – Zapewniają możliwości **jednolitego logowania** do uwierzytelniania użytkowników w wielu aplikacjach internetowych w jednej sesji.
5. **Zarządzanie prawami** – Pomaga w ochronie materiałów objętych prawem autorskim poprzez regulowanie ich nieautoryzowanej dystrybucji i użycia.
6. **Usługa DNS** – Kluczowa dla rozwiązywania **nazw domen**.

Aby uzyskać bardziej szczegółowe wyjaśnienie, sprawdź: [**TechTerms - Definicja Active Directory**](https://techterms.com/definition/active\_directory)

### **Uwierzytelnianie Kerberos**

Aby nauczyć się, jak **atakować AD**, musisz **dobrze zrozumieć** **proces uwierzytelniania Kerberos**.\
[**Przeczytaj tę stronę, jeśli nadal nie wiesz, jak to działa.**](kerberos-authentication.md)

## Arkusz oszustw

Możesz skorzystać z [https://wadcoms.github.io/](https://wadcoms.github.io), aby szybko zobaczyć, jakie polecenia możesz uruchomić, aby enumerować/eksploatować AD.

## Rekonesans Active Directory (Bez poświadczeń/sesji)

Jeśli masz dostęp do środowiska AD, ale nie masz żadnych poświadczeń/sesji, możesz:

* **Pentestować sieć:**
* Skanować sieć, znaleźć maszyny i otwarte porty oraz spróbować **eksploatować luki** lub **wyciągać poświadczenia** z nich (na przykład, [drukarki mogą być bardzo interesującymi celami](ad-information-in-printers.md).
* Enumeracja DNS może dostarczyć informacji o kluczowych serwerach w domenie, takich jak web, drukarki, udostępnienia, vpn, media itp.
* `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
* Zobacz ogólną [**Metodologię Pentestingu**](../../generic-methodologies-and-resources/pentesting-methodology.md), aby znaleźć więcej informacji na temat tego, jak to zrobić.
* **Sprawdź dostęp null i Gościa w usługach smb** (to nie zadziała w nowoczesnych wersjach Windows):
* `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
* `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
* `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
* Bardziej szczegółowy przewodnik dotyczący enumeracji serwera SMB można znaleźć tutaj:

{% content-ref url="../../network-services-pentesting/pentesting-smb/" %}
[pentesting-smb](../../network-services-pentesting/pentesting-smb/)
{% endcontent-ref %}

* **Enumeracja LDAP**
* `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
* Bardziej szczegółowy przewodnik dotyczący enumeracji LDAP można znaleźć tutaj (zwróć **szczególną uwagę na dostęp anonimowy**):

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

* **Zatrucie sieci**
* Zbieraj poświadczenia [**podszywając się pod usługi za pomocą Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
* Uzyskaj dostęp do hosta, [**nadużywając ataku relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
* Zbieraj poświadczenia **ujawniając** [**fałszywe usługi UPnP za pomocą evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
* [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
* Wyciągnij nazwy użytkowników/imiona z dokumentów wewnętrznych, mediów społecznościowych, usług (głównie web) w środowiskach domenowych oraz z publicznie dostępnych.
* Jeśli znajdziesz pełne imiona pracowników firmy, możesz spróbować różnych konwencji **namingowych użytkowników AD** (**[**przeczytaj to**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Najczęstsze konwencje to: _ImięNazwisko_, _Imię.Nazwisko_, _ImN_ (3 litery z każdej), _Im.N_, _NazwaNazwisko_, _N.Nazwisko_, _NazwiskoImię_, _Nazwisko.Imię_, _NazwiskoN_, _Nazwisko.N_, 3 _losowe litery i 3 losowe liczby_ (abc123).
* Narzędzia:
* [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
* [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeracja użytkowników

* **Anonimowa enumeracja SMB/LDAP:** Sprawdź strony [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/) i [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
* **Enumeracja Kerbrute**: Gdy **żądany jest nieprawidłowy nazwa użytkownika**, serwer odpowie używając kodu błędu **Kerberos** _KRB5KDC\_ERR\_C\_PRINCIPAL\_UNKNOWN_, co pozwala nam ustalić, że nazwa użytkownika była nieprawidłowa. **Prawidłowe nazwy użytkowników** wywołają albo **TGT w odpowiedzi AS-REP**, albo błąd _KRB5KDC\_ERR\_PREAUTH\_REQUIRED_, co wskazuje, że użytkownik musi przeprowadzić wstępne uwierzytelnienie.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Serwer OWA (Outlook Web Access)**

Jeśli znajdziesz jeden z tych serwerów w sieci, możesz również przeprowadzić **enumerację użytkowników** przeciwko niemu. Na przykład, możesz użyć narzędzia [**MailSniper**](https://github.com/dafthack/MailSniper):
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
Możesz znaleźć listy nazw użytkowników w [**tym repozytorium github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* oraz w tym ([**statystycznie-prawdopodobne-nazwy-użytkowników**](https://github.com/insidetrust/statistically-likely-usernames)).

Jednak powinieneś mieć **imię i nazwisko osób pracujących w firmie** z kroku rekonesansu, który powinieneś wykonać wcześniej. Z imieniem i nazwiskiem możesz użyć skryptu [**namemash.py**](https://gist.github.com/superkojiman/11076951), aby wygenerować potencjalne poprawne nazwy użytkowników.
{% endhint %}

### Znając jedną lub kilka nazw użytkowników

Ok, więc wiesz, że masz już poprawną nazwę użytkownika, ale nie masz haseł... Spróbuj:

* [**ASREPRoast**](asreproast.md): Jeśli użytkownik **nie ma** atrybutu _DONT\_REQ\_PREAUTH_, możesz **zażądać wiadomości AS\_REP** dla tego użytkownika, która będzie zawierać dane zaszyfrowane pochodną hasła użytkownika.
* [**Password Spraying**](password-spraying.md): Spróbujmy najczęściej **używanych haseł** z każdym z odkrytych użytkowników, może któryś z użytkowników używa złego hasła (pamiętaj o polityce haseł!).
* Zauważ, że możesz również **sprayować serwery OWA**, aby spróbować uzyskać dostęp do serwerów pocztowych użytkowników.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### LLMNR/NBT-NS Poisoning

Możesz być w stanie **uzyskać** kilka wyzwań **hashy**, aby złamać **truciznę** niektórych protokołów **sieci**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

Jeśli udało ci się zenumerować aktywny katalog, będziesz miał **więcej e-maili i lepsze zrozumienie sieci**. Możesz być w stanie wymusić ataki NTML [**relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* aby uzyskać dostęp do środowiska AD.

### Kradzież poświadczeń NTLM

Jeśli możesz **uzyskać dostęp do innych komputerów lub udziałów** z **użytkownikiem null lub gościem**, możesz **umieścić pliki** (jak plik SCF), które, jeśli zostaną w jakiś sposób otwarte, **wywołają uwierzytelnienie NTML przeciwko tobie**, abyś mógł **ukraść** **wyzwanie NTLM** do złamania:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Enumeracja Active Directory Z poświadczeniami/sesją

Na tym etapie musisz mieć **skomprymowane poświadczenia lub sesję ważnego konta domenowego.** Jeśli masz jakieś ważne poświadczenia lub powłokę jako użytkownik domenowy, **powinieneś pamiętać, że opcje podane wcześniej są nadal opcjami do skompromitowania innych użytkowników**.

Zanim rozpoczniesz uwierzytelnioną enumerację, powinieneś wiedzieć, czym jest **problem podwójnego skoku Kerberos.**

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Enumeracja

Posiadając skompromitowane konto, to **duży krok w kierunku kompromitacji całej domeny**, ponieważ będziesz mógł rozpocząć **Enumerację Active Directory:**

W odniesieniu do [**ASREPRoast**](asreproast.md) możesz teraz znaleźć każdego możliwego podatnego użytkownika, a w odniesieniu do [**Password Spraying**](password-spraying.md) możesz uzyskać **listę wszystkich nazw użytkowników** i spróbować hasła skompromitowanego konta, pustych haseł i nowych obiecujących haseł.

* Możesz użyć [**CMD do przeprowadzenia podstawowego rekonesansu**](../basic-cmd-for-pentesters.md#domain-info)
* Możesz również użyć [**powershell do rekonesansu**](../basic-powershell-for-pentesters/), co będzie bardziej dyskretne
* Możesz także [**użyć powerview**](../basic-powershell-for-pentesters/powerview.md), aby uzyskać bardziej szczegółowe informacje
* Innym niesamowitym narzędziem do rekonesansu w aktywnym katalogu jest [**BloodHound**](bloodhound.md). Nie jest **zbyt dyskretne** (w zależności od metod zbierania, które używasz), ale **jeśli ci to nie przeszkadza**, powinieneś spróbować. Znajdź, gdzie użytkownicy mogą RDP, znajdź ścieżki do innych grup itp.
* **Inne zautomatyzowane narzędzia do enumeracji AD to:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* [**Rekordy DNS AD**](ad-dns-records.md), ponieważ mogą zawierać interesujące informacje.
* Narzędziem z GUI, które możesz użyć do enumeracji katalogu, jest **AdExplorer.exe** z **SysInternal** Suite.
* Możesz również przeszukać bazę danych LDAP za pomocą **ldapsearch**, aby szukać poświadczeń w polach _userPassword_ i _unixUserPassword_, lub nawet dla _Description_. cf. [Hasło w komentarzu użytkownika AD na PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) dla innych metod.
* Jeśli używasz **Linux**, możesz również enumerować domenę za pomocą [**pywerview**](https://github.com/the-useless-one/pywerview).
* Możesz również spróbować zautomatyzowanych narzędzi, takich jak:
* [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
* [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Ekstrakcja wszystkich użytkowników domeny**

Bardzo łatwo jest uzyskać wszystkie nazwy użytkowników domeny z Windows (`net user /domain`, `Get-DomainUser` lub `wmic useraccount get name,sid`). W Linuxie możesz użyć: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` lub `enum4linux -a -u "user" -p "password" <DC IP>`

> Nawet jeśli ta sekcja enumeracji wygląda na małą, to najważniejsza część wszystkiego. Uzyskaj dostęp do linków (głównie do cmd, powershell, powerview i BloodHound), naucz się, jak enumerować domenę i ćwicz, aż poczujesz się komfortowo. Podczas oceny to będzie kluczowy moment, aby znaleźć drogę do DA lub zdecydować, że nic nie można zrobić.

### Kerberoast

Kerberoasting polega na uzyskaniu **biletów TGS** używanych przez usługi powiązane z kontami użytkowników i łamaniu ich szyfrowania—które opiera się na hasłach użytkowników—**offline**.

Więcej na ten temat w:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Zdalne połączenie (RDP, SSH, FTP, Win-RM, itp.)

Gdy już uzyskasz jakieś poświadczenia, możesz sprawdzić, czy masz dostęp do jakiejkolwiek **maszyny**. W tym celu możesz użyć **CrackMapExec**, aby spróbować połączyć się z kilkoma serwerami za pomocą różnych protokołów, zgodnie z twoimi skanami portów.

### Lokalne podwyższenie uprawnień

Jeśli skompromitowałeś poświadczenia lub masz sesję jako zwykły użytkownik domenowy i masz **dostęp** z tym użytkownikiem do **jakiejkolwiek maszyny w domenie**, powinieneś spróbować znaleźć sposób na **podwyższenie uprawnień lokalnie i poszukiwanie poświadczeń**. Dzieje się tak, ponieważ tylko z lokalnymi uprawnieniami administratora będziesz w stanie **zrzucić hashe innych użytkowników** w pamięci (LSASS) i lokalnie (SAM).

W tej książce znajduje się pełna strona na temat [**lokalnego podwyższania uprawnień w Windows**](../windows-local-privilege-escalation/) oraz [**lista kontrolna**](../checklist-windows-privilege-escalation.md). Nie zapomnij również użyć [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Bilety bieżącej sesji

Jest bardzo **mało prawdopodobne**, że znajdziesz **bilety** w bieżącym użytkowniku **dającym ci pozwolenie na dostęp** do nieoczekiwanych zasobów, ale możesz sprawdzić:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Jeśli udało ci się zenumerować aktywną dyrekcję, będziesz miał **więcej e-maili i lepsze zrozumienie sieci**. Możesz być w stanie wymusić ataki NTML [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Szukaj poświadczeń w udostępnionych plikach komputerowych**

Teraz, gdy masz podstawowe poświadczenia, powinieneś sprawdzić, czy możesz **znaleźć** jakieś **interesujące pliki udostępnione w AD**. Możesz to zrobić ręcznie, ale to bardzo nudne i powtarzalne zadanie (a jeszcze bardziej, jeśli znajdziesz setki dokumentów, które musisz sprawdzić).

[**Śledź ten link, aby dowiedzieć się o narzędziach, które możesz wykorzystać.**](../../network-services-pentesting/pentesting-smb/#domain-shared-folders-search)

### Kradzież poświadczeń NTLM

Jeśli możesz **uzyskać dostęp do innych komputerów lub udostępnionych plików**, możesz **umieścić pliki** (jak plik SCF), które, jeśli zostaną w jakiś sposób otwarte, **wywołają uwierzytelnienie NTML przeciwko tobie**, abyś mógł **ukraść** **wyzwanie NTLM** do złamania:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Ta luka pozwalała każdemu uwierzytelnionemu użytkownikowi na **kompromitację kontrolera domeny**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Eskalacja uprawnień w Active Directory Z uprzywilejowanymi poświadczeniami/sesją

**Dla poniższych technik zwykły użytkownik domeny nie wystarczy, potrzebujesz specjalnych uprawnień/poświadczeń, aby przeprowadzić te ataki.**

### Ekstrakcja haszy

Mam nadzieję, że udało ci się **skompromentować jakieś konto lokalnego administratora** za pomocą [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) w tym relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/).\
Następnie czas na zrzut wszystkich haszy w pamięci i lokalnie.\
[**Przeczytaj tę stronę o różnych sposobach uzyskania haszy.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Gdy masz hasz użytkownika**, możesz go użyć do **podszywania się** pod niego.\
Musisz użyć jakiegoś **narzędzia**, które **wykona** **uwierzytelnienie NTLM przy użyciu** tego **hasza**, **lub** możesz utworzyć nowy **sessionlogon** i **wstrzyknąć** ten **hasz** do **LSASS**, aby przy każdym **wykonywaniu uwierzytelnienia NTLM** ten **hasz był używany.** Ostatnia opcja to to, co robi mimikatz.\
[**Przeczytaj tę stronę, aby uzyskać więcej informacji.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Ten atak ma na celu **użycie hasza NTLM użytkownika do żądania biletów Kerberos**, jako alternatywy dla powszechnego Pass The Hash w protokole NTLM. Dlatego może być to szczególnie **przydatne w sieciach, w których protokół NTLM jest wyłączony** i tylko **Kerberos jest dozwolony** jako protokół uwierzytelniania.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

W metodzie ataku **Pass The Ticket (PTT)**, atakujący **kradną bilet uwierzytelniający użytkownika** zamiast jego hasła lub wartości haszy. Ten skradziony bilet jest następnie używany do **podszywania się pod użytkownika**, uzyskując nieautoryzowany dostęp do zasobów i usług w sieci.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Ponowne użycie poświadczeń

Jeśli masz **hasz** lub **hasło** lokalnego **administratora**, powinieneś spróbować **zalogować się lokalnie** do innych **komputerów** z jego pomocą.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Zauważ, że to jest dość **hałaśliwe** i **LAPS** by **złagodziło** to.
{% endhint %}

### Nadużycie MSSQL i Zaufane Linki

Jeśli użytkownik ma uprawnienia do **dostępu do instancji MSSQL**, może być w stanie użyć go do **wykonywania poleceń** na hoście MSSQL (jeśli działa jako SA), **ukraść** **hash** NetNTLM lub nawet przeprowadzić **atak** **przekaźnikowy**.\
Ponadto, jeśli instancja MSSQL jest zaufana (link bazy danych) przez inną instancję MSSQL. Jeśli użytkownik ma uprawnienia do zaufanej bazy danych, będzie mógł **wykorzystać relację zaufania do wykonywania zapytań również w innej instancji**. Te zaufania mogą być łańcuchowane i w pewnym momencie użytkownik może być w stanie znaleźć źle skonfigurowaną bazę danych, w której może wykonywać polecenia.\
**Linki między bazami danych działają nawet w przypadku zaufania między lasami.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Nieograniczona Delegacja

Jeśli znajdziesz jakikolwiek obiekt Komputera z atrybutem [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) i masz uprawnienia domeny na komputerze, będziesz mógł zrzucić TGT z pamięci każdego użytkownika, który loguje się na komputerze.\
Więc, jeśli **administrator domeny loguje się na komputerze**, będziesz mógł zrzucić jego TGT i podszyć się pod niego używając [Pass the Ticket](pass-the-ticket.md).\
Dzięki ograniczonej delegacji mógłbyś nawet **automatycznie skompromitować serwer druku** (mam nadzieję, że będzie to DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Ograniczona Delegacja

Jeśli użytkownik lub komputer ma zezwolenie na "Ograniczoną Delegację", będzie mógł **podszyć się pod dowolnego użytkownika, aby uzyskać dostęp do niektórych usług na komputerze**.\
Następnie, jeśli **skompromitujesz hash** tego użytkownika/komputera, będziesz mógł **podszyć się pod dowolnego użytkownika** (nawet administratorów domeny), aby uzyskać dostęp do niektórych usług.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Ograniczona Delegacja na podstawie zasobów

Posiadanie uprawnienia **WRITE** do obiektu Active Directory zdalnego komputera umożliwia uzyskanie wykonania kodu z **podwyższonymi uprawnieniami**:

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Nadużycie ACL

Skompromitowany użytkownik może mieć pewne **interesujące uprawnienia do niektórych obiektów domeny**, które mogą pozwolić ci na **lateralne poruszanie się**/**eskalację** uprawnień.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Nadużycie usługi Spooler drukarki

Odkrycie **usługi Spool** nasłuchującej w obrębie domeny może być **nadużyte** do **zdobycia nowych poświadczeń** i **eskalacji uprawnień**.

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Nadużycie sesji osób trzecich

Jeśli **inni użytkownicy** **uzyskują dostęp** do **skompromitowanej** maszyny, możliwe jest **zbieranie poświadczeń z pamięci** i nawet **wstrzykiwanie beaconów w ich procesy** w celu podszywania się pod nich.\
Zazwyczaj użytkownicy uzyskują dostęp do systemu przez RDP, więc oto jak przeprowadzić kilka ataków na sesje RDP osób trzecich:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### LAPS

**LAPS** zapewnia system zarządzania **hasłem lokalnego administratora** na komputerach dołączonych do domeny, zapewniając, że jest ono **losowe**, unikalne i często **zmieniane**. Te hasła są przechowywane w Active Directory, a dostęp jest kontrolowany przez ACL tylko dla uprawnionych użytkowników. Posiadając wystarczające uprawnienia do uzyskania dostępu do tych haseł, możliwe staje się przejście do innych komputerów.

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

### Kradzież certyfikatów

**Zbieranie certyfikatów** z skompromitowanej maszyny może być sposobem na eskalację uprawnień w środowisku:

{% content-ref url="ad-certificates/certificate-theft.md" %}
[certificate-theft.md](ad-certificates/certificate-theft.md)
{% endcontent-ref %}

### Nadużycie szablonów certyfikatów

Jeśli **wrażliwe szablony** są skonfigurowane, możliwe jest ich nadużycie do eskalacji uprawnień:

{% content-ref url="ad-certificates/domain-escalation.md" %}
[domain-escalation.md](ad-certificates/domain-escalation.md)
{% endcontent-ref %}

## Post-eksploatacja z kontem o wysokich uprawnieniach

### Zrzut poświadczeń domeny

Gdy uzyskasz uprawnienia **Administratora Domeny** lub jeszcze lepiej **Administratora Enterprise**, możesz **zrzucić** **bazę danych domeny**: _ntds.dit_.

[**Więcej informacji na temat ataku DCSync można znaleźć tutaj**](dcsync.md).

[**Więcej informacji na temat kradzieży NTDS.dit można znaleźć tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc jako Utrzymanie

Niektóre z wcześniej omówionych technik mogą być używane do utrzymania.\
Na przykład możesz:

*   Uczynić użytkowników podatnymi na [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```
*   Uczynić użytkowników podatnymi na [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
*   Przyznać uprawnienia [**DCSync**](./#dcsync) użytkownikowi

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Srebrny Bilet

Atak **Srebrnego Biletu** tworzy **legitymację usługi Ticket Granting Service (TGS)** dla konkretnej usługi, używając **hasła NTLM** (na przykład, **hasła konta PC**). Metoda ta jest stosowana do **uzyskania dostępu do uprawnień usługi**.

{% content-ref url="silver-ticket.md" %}
[silver-ticket.md](silver-ticket.md)
{% endcontent-ref %}

### Złoty Bilet

Atak **Złotego Biletu** polega na tym, że atakujący uzyskuje dostęp do **hasła NTLM konta krbtgt** w środowisku Active Directory (AD). To konto jest specjalne, ponieważ jest używane do podpisywania wszystkich **Biletów Grantujących Bilety (TGT)**, które są niezbędne do uwierzytelniania w sieci AD.

Gdy atakujący uzyska to hasło, może stworzyć **TGT** dla dowolnego konta, które wybierze (atak Srebrnego Biletu).

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### Diamentowy Bilet

Są one podobne do złotych biletów, fałszowane w sposób, który **omija powszechne mechanizmy wykrywania złotych biletów.**

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### **Utrzymanie Konta Certyfikatów**

**Posiadanie certyfikatów konta lub możliwość ich żądania** to bardzo dobry sposób na utrzymanie się w koncie użytkownika (nawet jeśli zmieni hasło):

{% content-ref url="ad-certificates/account-persistence.md" %}
[account-persistence.md](ad-certificates/account-persistence.md)
{% endcontent-ref %}

### **Utrzymanie Certyfikatów w Domenie**

**Używanie certyfikatów również umożliwia utrzymanie się z wysokimi uprawnieniami w obrębie domeny:**

{% content-ref url="ad-certificates/domain-persistence.md" %}
[domain-persistence.md](ad-certificates/domain-persistence.md)
{% endcontent-ref %}

### Grupa AdminSDHolder

Obiekt **AdminSDHolder** w Active Directory zapewnia bezpieczeństwo **uprzywilejowanych grup** (takich jak Administratorzy Domeny i Administratorzy Enterprise) poprzez stosowanie standardowej **Listy Kontroli Dostępu (ACL)** w tych grupach, aby zapobiec nieautoryzowanym zmianom. Jednak ta funkcja może być nadużywana; jeśli atakujący zmodyfikuje ACL AdminSDHolder, aby nadać pełny dostęp zwykłemu użytkownikowi, ten użytkownik zyskuje znaczne uprawnienia nad wszystkimi uprzywilejowanymi grupami. To zabezpieczenie, mające na celu ochronę, może więc obrócić się przeciwko, umożliwiając nieuzasadniony dostęp, chyba że będzie ściśle monitorowane.

[**Więcej informacji na temat grupy AdminDSHolder tutaj.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Poświadczenia DSRM

W każdym **Kontrolerze Domeny (DC)** istnieje konto **lokalnego administratora**. Uzyskując prawa administratora na takiej maszynie, hash lokalnego administratora może być wyodrębniony za pomocą **mimikatz**. Następnie konieczna jest modyfikacja rejestru, aby **umożliwić użycie tego hasła**, co pozwala na zdalny dostęp do konta lokalnego administratora.

{% content-ref url="dsrm-credentials.md" %}
[dsrm-credentials.md](dsrm-credentials.md)
{% endcontent-ref %}

### Utrzymanie ACL

Możesz **przyznać** pewne **specjalne uprawnienia** **użytkownikowi** do niektórych konkretnych obiektów domeny, które pozwolą użytkownikowi **eskalować uprawnienia w przyszłości**.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Deskryptory zabezpieczeń

**Deskryptory zabezpieczeń** są używane do **przechowywania** **uprawnień**, jakie **obiekt** ma **nad** innym **obiektem**. Jeśli możesz **dokonać** **niewielkiej zmiany** w **deskryptorze zabezpieczeń** obiektu, możesz uzyskać bardzo interesujące uprawnienia nad tym obiektem bez potrzeby bycia członkiem uprzywilejowanej grupy.

{% content-ref url="security-descriptors.md" %}
[security-descriptors.md](security-descriptors.md)
{% endcontent-ref %}

### Klucz Szkieletowy

Zmień **LSASS** w pamięci, aby ustanowić **uniwersalne hasło**, dając dostęp do wszystkich kont domenowych.

{% content-ref url="skeleton-key.md" %}
[skeleton-key.md](skeleton-key.md)
{% endcontent-ref %}

### Niestandardowy SSP

[Dowiedz się, czym jest SSP (Dostawca Wsparcia Zabezpieczeń) tutaj.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Możesz stworzyć **własny SSP**, aby **przechwytywać** w **czystym tekście** **poświadczenia** używane do uzyskania dostępu do maszyny.\\

{% content-ref url="custom-ssp.md" %}
[custom-ssp.md](custom-ssp.md)
{% endcontent-ref %}

### DCShadow

Rejestruje **nowy Kontroler Domeny** w AD i używa go do **wypychania atrybutów** (SIDHistory, SPNs...) na określonych obiektach **bez** pozostawiania jakichkolwiek **logów** dotyczących **zmian**. Musisz mieć uprawnienia DA i być w **domenie głównej**.\
Zauważ, że jeśli użyjesz błędnych danych, pojawią się dość brzydkie logi.

{% content-ref url="dcshadow.md" %}
[dcshadow.md](dcshadow.md)
{% endcontent-ref %}

### Utrzymanie LAPS

Wcześniej omawialiśmy, jak eskalować uprawnienia, jeśli masz **wystarczające uprawnienia do odczytu haseł LAPS**. Jednak te hasła mogą być również używane do **utrzymania się**.\
Sprawdź:

{% content-ref url="laps.md" %}
[laps.md](laps.md)
{% endcontent-ref %}

## Eskalacja uprawnień w lesie - Zaufania domen

Microsoft postrzega **Las** jako granicę bezpieczeństwa. Oznacza to, że **skomplikowanie jednej domeny może potencjalnie prowadzić do skompromitowania całego lasu**.

### Podstawowe informacje

[**Zaufanie domeny**](http://technet.microsoft.com/en-us/library/cc759554\(v=ws.10\).aspx) to mechanizm zabezpieczeń, który umożliwia użytkownikowi z jednej **domeny** dostęp do zasobów w innej **domenie**. W zasadzie tworzy to powiązanie między systemami uwierzytelniania obu domen, umożliwiając płynny przepływ weryfikacji uwierzytelnienia. Gdy domeny ustanawiają zaufanie, wymieniają i zachowują określone **klucze** w swoich **Kontrolerach Domeny (DC)**, które są kluczowe dla integralności zaufania.

W typowym scenariuszu, jeśli użytkownik zamierza uzyskać dostęp do usługi w **zaufanej domenie**, musi najpierw zażądać specjalnego biletu znanego jako **inter-realm TGT** od swojego DC domeny. Ten TGT jest szyfrowany za pomocą wspólnego **klucza**, na który obie domeny się zgodziły. Użytkownik następnie przedstawia ten TGT **DC zaufanej domeny**, aby uzyskać bilet usługi (**TGS**). Po pomyślnej walidacji inter-realm TGT przez DC zaufanej domeny, wydaje TGS, przyznając użytkownikowi dostęp do usługi.

**Kroki**:

1. **Klient komputer** w **Domenie 1** rozpoczyna proces, używając swojego **hasła NTLM**, aby zażądać **Biletu Grantującego Bilet (TGT)** od swojego **Kontrolera Domeny (DC1)**.
2. DC1 wydaje nowy TGT, jeśli klient zostanie pomyślnie uwierzytelniony.
3. Klient następnie żąda **inter-realm TGT** od DC1, który jest potrzebny do uzyskania dostępu do zasobów w **Domenie 2**.
4. Inter-realm TGT jest szyfrowany za pomocą **klucza zaufania** współdzielonego między DC1 a DC2 w ramach dwukierunkowego zaufania domen.
5. Klient zabiera inter-realm TGT do **Kontrolera Domeny 2 (DC2)**.
6. DC2 weryfikuje inter-realm TGT za pomocą swojego współdzielonego klucza zaufania i, jeśli jest ważny, wydaje **Bilet Grantujący Usługę (TGS)** dla serwera w Domenie 2, do którego klient chce uzyskać dostęp.
7. Na koniec klient przedstawia ten TGS serwerowi, który jest szyfrowany hasłem konta serwera, aby uzyskać dostęp do usługi w Domenie 2.

### Różne zaufania

Ważne jest, aby zauważyć, że **zaufanie może być jednostronne lub dwustronne**. W przypadku opcji dwustronnej obie domeny będą sobie ufać, ale w przypadku **jednostronnego** zaufania jedna z domen będzie **zaufana**, a druga **ufająca**. W ostatnim przypadku **możesz uzyskać dostęp do zasobów wewnątrz ufającej domeny tylko z zaufanej**.

Jeśli Domen A ufa Domenie B, A jest ufającą domeną, a B jest zaufaną. Ponadto, w **Domenie A** byłoby to **zaufanie wychodzące**; a w **Domenie B** byłoby to **zaufanie przychodzące**.

**Różne relacje zaufania**

* **Zaufania rodzic-dziecko**: To jest powszechne ustawienie w obrębie tego samego lasu, gdzie domena dziecka automatycznie ma dwukierunkowe zaufanie z domeną rodzica. W zasadzie oznacza to, że żądania uwierzytelnienia mogą płynnie przepływać między rodzicem a dzieckiem.
* **Zaufania krzyżowe**: Nazywane "zaufaniami skrótowymi", są ustanawiane między domenami dziecka, aby przyspieszyć procesy referencyjne. W złożonych lasach, referencje uwierzytelniające zazwyczaj muszą podróżować do korzenia lasu, a następnie w dół do docelowej domeny. Tworząc zaufania krzyżowe, podróż jest skracana, co jest szczególnie korzystne w geograficznie rozproszonych środowiskach.
* **Zaufania zewnętrzne**: Te są ustanawiane między różnymi, niepowiązanymi domenami i są z natury nieprzechodnie. Zgodnie z [dokumentacją Microsoftu](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), zaufania zewnętrzne są przydatne do uzyskiwania dostępu do zasobów w domenie poza aktualnym lasem, która nie jest połączona przez zaufanie lasu. Bezpieczeństwo jest wzmacniane przez filtrowanie SID w przypadku zaufania zewnętrznego.
* **Zaufania korzeni drzew**: Te zaufania są automatycznie ustanawiane między domeną korzenia lasu a nowo dodanym korzeniem drzewa. Chociaż nie są powszechnie spotykane, zaufania korzeni drzew są ważne dla dodawania nowych drzew domen do lasu, umożliwiając im utrzymanie unikalnej nazwy domeny i zapewniając dwukierunkową przejrzystość. Więcej informacji można znaleźć w [przewodniku Microsoftu](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx).
* **Zaufania lasów**: Ten typ zaufania to dwukierunkowe zaufanie przechodnie między dwoma domenami korzenia lasu, również egzekwujące filtrowanie SID w celu wzmocnienia środków bezpieczeństwa.
* **Zaufania MIT**: Te zaufania są ustanawiane z domenami Kerberos zgodnymi z [RFC4120](https://tools.ietf.org/html/rfc4120) i nie będącymi systemami Windows. Zaufania MIT są nieco bardziej wyspecjalizowane i odpowiadają środowiskom wymagającym integracji z systemami opartymi na Kerberos poza ekosystemem Windows.

#### Inne różnice w **relacjach zaufania**

* Relacja zaufania może być również **przechodnia** (A ufa B, B ufa C, więc A ufa C) lub **nieprzechodnia**.
* Relacja zaufania może być ustawiona jako **zaufanie dwukierunkowe** (obie sobie ufają) lub jako **zaufanie jednostronne** (tylko jedna z nich ufa drugiej).

### Ścieżka ataku

1. **Wymień** relacje zaufania
2. Sprawdź, czy jakikolwiek **podmiot zabezpieczeń** (użytkownik/grupa/komputer) ma **dostęp** do zasobów **innej domeny**, być może przez wpisy ACE lub będąc w grupach innej domeny. Szukaj **relacji między domenami** (zaufanie zostało prawdopodobnie utworzone dla tego).
1. Kerberoast w tym przypadku może być inną opcją.
3. **Skompromituj** **konta**, które mogą **przejść** przez domeny.

Atakujący mogą uzyskać dostęp do zasobów w innej domenie za pomocą trzech podstawowych mechanizmów:

* **Członkostwo w grupie lokalnej**: Podmioty mogą być dodawane do lokalnych grup na maszynach, takich jak grupa "Administratorzy" na serwerze, co daje im znaczne uprawnienia nad tą maszyną.
* **Członkostwo w grupie domeny obcej**: Podmioty mogą być również członkami grup w domenie obcej. Jednak skuteczność tej metody zależy od charakteru zaufania i zakresu grupy.
* **Listy Kontroli Dostępu (ACL)**: Podmioty mogą być określone w **ACL**, szczególnie jako podmioty w **ACE** w ramach **DACL**, co zapewnia im dostęp do określonych zasobów. Dla tych, którzy chcą zgłębić mechanikę ACL, DACL i ACE, dokument zatytułowany “[As ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)” jest nieocenionym źródłem.

### Eskalacja uprawnień z dziecka do rodzica w lesie
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
Istnieją **2 zaufane klucze**, jeden dla _Dziecka --> Rodzica_ i drugi dla _Rodzica_ --> _Dziecka_.\
Możesz użyć tego, który jest używany przez bieżącą domenę, za pomocą:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### Wstrzykiwanie SID-History

Podnieś uprawnienia jako administrator przedsiębiorstwa do domeny podrzędnej/rodzicielskiej, wykorzystując zaufanie z wstrzykiwaniem SID-History:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Wykorzystanie zapisywalnej konfiguracji NC

Zrozumienie, jak można wykorzystać Konfigurację Nazewniczą (NC), jest kluczowe. Konfiguracja NC służy jako centralne repozytorium danych konfiguracyjnych w środowiskach Active Directory (AD). Dane te są replikowane do każdego Kontrolera Domeny (DC) w lesie, a zapisywalne DC utrzymują zapisywalną kopię Konfiguracji NC. Aby to wykorzystać, należy mieć **uprawnienia SYSTEM na DC**, najlepiej na DC podrzędnym.

**Połącz GPO z witryną główną DC**

Kontener Witryn w Konfiguracji NC zawiera informacje o wszystkich komputerach dołączonych do domeny w lesie AD. Działając z uprawnieniami SYSTEM na dowolnym DC, atakujący mogą połączyć GPO z witrynami głównymi DC. Działanie to potencjalnie kompromituje domenę główną poprzez manipulację politykami stosowanymi do tych witryn.

Aby uzyskać szczegółowe informacje, można zbadać badania na temat [Obchodzenia filtrowania SID](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Kompromitacja dowolnego gMSA w lesie**

Wektor ataku polega na celowaniu w uprzywilejowane gMSA w domenie. Klucz KDS Root, niezbędny do obliczania haseł gMSA, jest przechowywany w Konfiguracji NC. Posiadając uprawnienia SYSTEM na dowolnym DC, można uzyskać dostęp do klucza KDS Root i obliczyć hasła dla dowolnego gMSA w lesie.

Szczegółowa analiza znajduje się w dyskusji na temat [Ataków zaufania Golden gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Atak zmiany schematu**

Ta metoda wymaga cierpliwości, czekając na utworzenie nowych uprzywilejowanych obiektów AD. Posiadając uprawnienia SYSTEM, atakujący może zmodyfikować schemat AD, aby przyznać dowolnemu użytkownikowi pełną kontrolę nad wszystkimi klasami. Może to prowadzić do nieautoryzowanego dostępu i kontroli nad nowo utworzonymi obiektami AD.

Dalsze czytanie dostępne jest na temat [Ataków zaufania zmiany schematu](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Od DA do EA z ADCS ESC5**

Luka ADCS ESC5 celuje w kontrolę nad obiektami Infrastruktury Klucza Publicznego (PKI), aby stworzyć szablon certyfikatu, który umożliwia uwierzytelnienie jako dowolny użytkownik w lesie. Ponieważ obiekty PKI znajdują się w Konfiguracji NC, kompromitacja zapisywalnego DC podrzędnego umożliwia przeprowadzenie ataków ESC5.

Więcej szczegółów można przeczytać w [Od DA do EA z ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). W scenariuszach bez ADCS, atakujący ma możliwość skonfigurowania niezbędnych komponentów, jak omówiono w [Podnoszeniu uprawnień z administratorów domeny podrzędnej do administratorów przedsiębiorstwa](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
W tym scenariuszu **twój domena jest zaufana** przez zewnętrzną, co daje ci **nieokreślone uprawnienia** nad nią. Będziesz musiał znaleźć **które podmioty twojej domeny mają jakie uprawnienia nad zewnętrzną domeną** i spróbować to wykorzystać:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Zewnętrzna domena leśna - jednokierunkowa (wyjściowa)
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
W tym scenariuszu **twoja domena** **ufają** pewnym **uprawnieniom** dla podmiotu z **innych domen**.

Jednak gdy **domena jest zaufana** przez ufającą domenę, zaufana domena **tworzy użytkownika** o **przewidywalnej nazwie**, który używa jako **hasła zaufanego hasła**. Oznacza to, że możliwe jest **uzyskanie dostępu do użytkownika z ufającej domeny, aby dostać się do zaufanej**, aby ją zenumerować i spróbować eskalować więcej uprawnień:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Innym sposobem na skompromitowanie zaufanej domeny jest znalezienie [**zaufanego połączenia SQL**](abusing-ad-mssql.md#mssql-trusted-links) utworzonego w **przeciwnym kierunku** zaufania domeny (co nie jest zbyt powszechne).

Innym sposobem na skompromitowanie zaufanej domeny jest czekanie na maszynie, na której **użytkownik z zaufanej domeny może uzyskać dostęp** do logowania przez **RDP**. Następnie atakujący mógłby wstrzyknąć kod w proces sesji RDP i **uzyskać dostęp do domeny źródłowej ofiary** stamtąd.\
Co więcej, jeśli **ofiara zamontowała swój dysk twardy**, z procesu **sesji RDP** atakujący mógłby przechowywać **tylnie drzwi** w **folderze uruchamiania dysku twardego**. Ta technika nazywa się **RDPInception.**

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Łagodzenie nadużyć zaufania domeny

### **Filtracja SID:**

* Ryzyko ataków wykorzystujących atrybut historii SID w zaufaniach między lasami jest łagodzone przez filtrację SID, która jest aktywowana domyślnie we wszystkich zaufaniach między lasami. Opiera się to na założeniu, że zaufania wewnątrz lasu są bezpieczne, traktując las, a nie domenę, jako granicę bezpieczeństwa zgodnie z stanowiskiem Microsoftu.
* Jednak jest pewien haczyk: filtracja SID może zakłócać aplikacje i dostęp użytkowników, co prowadzi do jej okazjonalnej dezaktywacji.

### **Selektywna autoryzacja:**

* W przypadku zaufania między lasami, stosowanie selektywnej autoryzacji zapewnia, że użytkownicy z dwóch lasów nie są automatycznie uwierzytelniani. Zamiast tego wymagane są wyraźne uprawnienia dla użytkowników, aby uzyskać dostęp do domen i serwerów w ufającej domenie lub lesie.
* Ważne jest, aby zauważyć, że te środki nie chronią przed wykorzystaniem zapisywalnego kontekstu nazewniczego konfiguracji (NC) ani atakami na konto zaufania.

[**Więcej informacji o zaufaniach domen w ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Niektóre ogólne obrony

[**Dowiedz się więcej o tym, jak chronić dane uwierzytelniające tutaj.**](../stealing-credentials/credentials-protections.md)\\

### **Środki obronne dla ochrony danych uwierzytelniających**

* **Ograniczenia dla administratorów domeny**: Zaleca się, aby administratorzy domeny mogli logować się tylko do kontrolerów domeny, unikając ich użycia na innych hostach.
* **Uprawnienia konta usługi**: Usługi nie powinny być uruchamiane z uprawnieniami administratora domeny (DA), aby zachować bezpieczeństwo.
* **Ograniczenie czasowe uprawnień**: W przypadku zadań wymagających uprawnień DA, ich czas trwania powinien być ograniczony. Można to osiągnąć za pomocą: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Wdrażanie technik oszustwa**

* Wdrażanie oszustwa polega na ustawianiu pułapek, takich jak użytkownicy lub komputery zastępcze, z funkcjami takimi jak hasła, które nie wygasają lub są oznaczone jako zaufane do delegacji. Szczegółowe podejście obejmuje tworzenie użytkowników z określonymi prawami lub dodawanie ich do grup o wysokich uprawnieniach.
* Praktyczny przykład obejmuje użycie narzędzi takich jak: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
* Więcej informacji na temat wdrażania technik oszustwa można znaleźć w [Deploy-Deception na GitHubie](https://github.com/samratashok/Deploy-Deception).

### **Identyfikacja oszustwa**

* **Dla obiektów użytkowników**: Podejrzane wskaźniki obejmują nietypowy ObjectSID, rzadkie logowania, daty utworzenia i niskie liczby błędnych haseł.
* **Ogólne wskaźniki**: Porównanie atrybutów potencjalnych obiektów zastępczych z atrybutami obiektów rzeczywistych może ujawnić niespójności. Narzędzia takie jak [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) mogą pomóc w identyfikacji takich oszustw.

### **Omijanie systemów wykrywania**

* **Omijanie wykrywania Microsoft ATA**:
* **Enumeracja użytkowników**: Unikanie enumeracji sesji na kontrolerach domeny, aby zapobiec wykryciu przez ATA.
* **Impersonacja biletu**: Wykorzystanie kluczy **aes** do tworzenia biletów pomaga unikać wykrycia, nie obniżając się do NTLM.
* **Ataki DCSync**: Zaleca się wykonywanie z niekontrolera domeny, aby uniknąć wykrycia przez ATA, ponieważ bezpośrednie wykonanie z kontrolera domeny wywoła alerty.

## Referencje

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{% hint style="success" %}
Ucz się i ćwicz hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>
{% endhint %}
