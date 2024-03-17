# macOS Red Teaming

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Nadużywanie MDMów

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Jeśli uda ci się **skompromitować dane uwierzytelniające administratora** w celu uzyskania dostępu do platformy zarządzania, możesz **potencjalnie skompromitować wszystkie komputery**, rozpowszechniając złośliwe oprogramowanie na maszynach.

Podczas testowania czerwonych zespołów w środowiskach MacOS zaleca się posiadanie pewnego zrozumienia działania MDMów:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Wykorzystanie MDM jako C2

MDM będzie miał uprawnienia do instalowania, zapytywania lub usuwania profili, instalowania aplikacji, tworzenia kont administratora lokalnego, ustawiania hasła firmware, zmiany klucza FileVault...

Aby uruchomić własne MDM, musisz **podpisać swoje CSR przez dostawcę**, którego możesz spróbować uzyskać za pomocą [**https://mdmcert.download/**](https://mdmcert.download/). Aby uruchomić własne MDM dla urządzeń Apple, możesz użyć [**MicroMDM**](https://github.com/micromdm/micromdm).

Jednakże, aby zainstalować aplikację na zarejestrowanym urządzeniu, nadal musi ona być podpisana przez konto dewelopera... jednakże, po zarejestrowaniu w MDM, **urządzenie dodaje certyfikat SSL MDM jako zaufany CA**, więc teraz możesz podpisywać cokolwiek.

Aby zarejestrować urządzenie w MDM, musisz zainstalować plik **`mobileconfig`** jako root, który może być dostarczony za pomocą pliku **pkg** (możesz go skompresować w zip i po pobraniu z safari zostanie zdekompresowany).

**Agent Mythic Orthrus** wykorzystuje tę technikę.

### Nadużywanie JAMF PRO

JAMF może uruchamiać **skrypty niestandardowe** (skrypty opracowane przez administratora systemu), **natywne ładunki** (tworzenie kont lokalnych, ustawianie hasła EFI, monitorowanie plików/procesów...) i **MDM** (konfiguracje urządzenia, certyfikaty urządzenia...).

#### Samozapis JAMF

Przejdź do strony takiej jak `https://<nazwa-firmy>.jamfcloud.com/enroll/`, aby sprawdzić, czy mają włączone **samozapisanie**. Jeśli tak, może **poprosić o dane uwierzytelniające do dostępu**.

Możesz użyć skryptu [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py), aby przeprowadzić atak polegający na rozpylaniu haseł.

Ponadto, po znalezieniu odpowiednich danych uwierzytelniających, możesz być w stanie przeprowadzić atak brutalnej siły na inne nazwy użytkowników za pomocą następującego formularza:

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### Uwierzytelnianie urządzenia JAMF

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Binarny plik **`jamf`** zawierał sekret do otwarcia keychain, który w momencie odkrycia był **udostępniony** wszystkim i był to: **`jk23ucnq91jfu9aj`**.\
Ponadto, jamf **utrzymuje się** jako **LaunchDaemon** w **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Przejęcie urządzenia JAMF

URL **JSS** (Jamf Software Server), który użyje **`jamf`**, znajduje się w **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ten plik zawiera podstawowo URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Więc atakujący mógłby umieścić złośliwy pakiet (`pkg`), który **nadpisuje ten plik** podczas instalacji, ustawiając **URL na słuchacza Mythic C2 z agentem Typhon**, aby teraz móc wykorzystać JAMF jako C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Podszywanie się pod JAMF

Aby **podrobić komunikację** między urządzeniem a JMF, potrzebujesz:

* **UUID** urządzenia: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* **Klucz JAMF** z: `/Library/Application\ Support/Jamf/JAMF.keychain`, który zawiera certyfikat urządzenia

Mając te informacje, **utwórz wirtualną maszynę** z **ukradzionym** sprzętowym **UUID** oraz z wyłączonym **SIP**, upuść **klucz JAMF**, **zahacz** agenta Jamf i ukradnij jego informacje.

#### Kradzież sekretów

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

Możesz również monitorować lokalizację `/Library/Application Support/Jamf/tmp/` w poszukiwaniu **skryptów niestandardowych**, które administratorzy chcieliby wykonać za pośrednictwem Jamf, ponieważ są one **umieszczane tutaj, uruchamiane i usuwane**. Te skrypty **mogą zawierać poświadczenia**.

Jednakże **poświadczenia** mogą być przekazywane do tych skryptów jako **parametry**, dlatego musisz monitorować `ps aux | grep -i jamf` (nawet bez uprawnień roota).

Skrypt [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) może nasłuchiwać na dodawanie nowych plików i nowych argumentów procesu.

### Zdalny dostęp do macOS

Oraz o "specjalnych" **protokołach sieciowych** w **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

W niektórych przypadkach zauważysz, że **komputer z MacOS jest podłączony do AD**. W takim scenariuszu powinieneś spróbować **wyliczyć** katalog aktywny, tak jak jesteś tego przyzwyczajony. Znajdź **pomoc** na następujących stronach:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Pewne **narzędzie lokalne MacOS**, które może ci pomóc, to `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Istnieją również narzędzia przygotowane dla systemu MacOS do automatycznego wyliczania AD i zabawy z kerberosem:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound to rozszerzenie narzędzia audytowego Bloodhound, umożliwiające zbieranie i przetwarzanie relacji w Active Directory na hostach MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost to projekt Objective-C zaprojektowany do interakcji z interfejsem API Heimdal krb5 na macOS. Celem projektu jest umożliwienie lepszego testowania bezpieczeństwa wokół Kerberosa na urządzeniach macOS przy użyciu natywnych interfejsów API, bez konieczności korzystania z innych frameworków ani pakietów na celu.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Narzędzie JavaScript for Automation (JXA) do wyliczania Active Directory. 

### Informacje o domenie
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Użytkownicy

Trzy rodzaje użytkowników MacOS to:

- **Użytkownicy lokalni** — Zarządzani przez lokalną usługę OpenDirectory, nie są w żaden sposób połączeni z Active Directory.
- **Użytkownicy sieciowi** — Nietrwałe użytkownicy Active Directory, którzy wymagają połączenia z serwerem DC w celu uwierzytelnienia.
- **Użytkownicy mobilni** — Użytkownicy Active Directory z lokalną kopią zapasową swoich poświadczeń i plików.

Lokalne informacje o użytkownikach i grupach są przechowywane w folderze _/var/db/dslocal/nodes/Default._\
Na przykład, informacje o użytkowniku o nazwie _mark_ są przechowywane w _/var/db/dslocal/nodes/Default/users/mark.plist_, a informacje o grupie _admin_ znajdują się w _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Oprócz korzystania z krawędzi HasSession i AdminTo, **MacHound dodaje trzy nowe krawędzie** do bazy danych Bloodhound:

- **CanSSH** - podmiot uprawniony do łączenia się przez SSH z hostem
- **CanVNC** - podmiot uprawniony do łączenia się przez VNC z hostem
- **CanAE** - podmiot uprawniony do wykonywania skryptów AppleEvent na hoście
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Więcej informacji można znaleźć pod adresem [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## Dostęp do Keychain

Keychain prawdopodobnie zawiera wrażliwe informacje, które w przypadku uzyskania dostępu bez generowania monitu mogą pomóc w przeprowadzeniu ćwiczenia czerwonej drużyny:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Usługi zewnętrzne

Czerwona drużyna MacOS różni się od zwykłej czerwonej drużyny Windows, ponieważ zazwyczaj **MacOS jest zintegrowany z kilkoma zewnętrznymi platformami bezpośrednio**. Powszechną konfiguracją MacOS jest dostęp do komputera za pomocą **synchronizowanych pośrednich danych OneLogin oraz dostęp do kilku zewnętrznych usług** (takich jak github, aws...) za pośrednictwem OneLogin.

## Różne techniki czerwonej drużyny

### Safari

Gdy plik jest pobierany w Safari, jeśli jest to "bezpieczny" plik, zostanie **automatycznie otwarty**. Na przykład, jeśli **pobierasz plik zip**, zostanie automatycznie rozpakowany:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## Odnośniki

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
