# Red Teaming w macOS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Wykorzystywanie MDM

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Jeśli uda ci się **skompromitować poświadczenia administratora** w celu uzyskania dostępu do platformy zarządzania, możesz **potencjalnie skompromitować wszystkie komputery**, rozpowszechniając złośliwe oprogramowanie na maszynach.

Podczas testowania czerwonej drużyny w środowiskach MacOS zaleca się posiadanie pewnego zrozumienia, jak działają MDM:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Wykorzystanie MDM jako C2

MDM będzie miał uprawnienia do instalowania, zapytywania lub usuwania profili, instalowania aplikacji, tworzenia kont administratora lokalnie, ustawiania hasła firmware, zmiany klucza FileVault...

Aby uruchomić własne MDM, musisz **podpisać swoje CSR przez dostawcę**, którego możesz spróbować uzyskać za pomocą [**https://mdmcert.download/**](https://mdmcert.download/). Aby uruchomić własne MDM dla urządzeń Apple, możesz użyć [**MicroMDM**](https://github.com/micromdm/micromdm).

Jednak aby zainstalować aplikację na zarejestrowanym urządzeniu, nadal musisz ją podpisać kontem dewelopera... jednak po zarejestrowaniu MDM **urządzenie dodaje certyfikat SSL MDM jako zaufany CA**, więc teraz możesz podpisywać cokolwiek.

Aby zarejestrować urządzenie w MDM, musisz zainstalować plik **`mobileconfig`** jako root, który można dostarczyć za pomocą pliku **pkg** (można go skompresować w zip i po pobraniu z Safari zostanie rozpakowany).

**Agent Mythic Orthrus** korzysta z tej techniki.

### Wykorzystanie JAMF PRO

JAMF może uruchamiać **skrypty niestandardowe** (skrypty opracowane przez administratora systemu), **payloady natywne** (tworzenie kont lokalnych, ustawianie hasła EFI, monitorowanie plików/procesów...) i **MDM** (konfiguracje urządzeń, certyfikaty urządzeń...).

#### Samorejestracja JAMF

Przejdź do strony takiej jak `https://<nazwa-firmy>.jamfcloud.com/enroll/`, aby sprawdzić, czy mają **włączoną samorejestrację**. Jeśli tak, może **poprosić o poświadczenia dostępu**.

Możesz użyć skryptu [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py), aby przeprowadzić atak rozpylania haseł.

Ponadto, po znalezieniu odpowiednich poświadczeń, możesz próbować łamać hasła innych użytkowników za pomocą następującego formularza:

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### Uwierzytelnianie urządzenia JAMF

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Binarny plik **`jamf`** zawierał sekret do otwarcia keychain, który w momencie odkrycia był **udostępniany** wszystkim i był to: **`jk23ucnq91jfu9aj`**.\
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
{% endcode %}

Więc atakujący mógłby umieścić złośliwy pakiet (`pkg`), który **nadpisuje ten plik** podczas instalacji, ustawiając **adres URL na nasłuchiwacz Mythic C2 z agentem Typhon**, aby móc wykorzystać JAMF jako C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### Podrabianie JAMF

Aby **podrabiać komunikację** między urządzeniem a JMF, potrzebujesz:

* **UUID** urządzenia: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* **JAMF keychain** z: `/Library/Application\ Support/Jamf/JAMF.keychain`, który zawiera certyfikat urządzenia

Z tymi informacjami **utwórz wirtualną maszynę** z **ukradzionym** sprzętowym **UUID** i wyłączonym **SIP**, upuść **JAMF keychain**, **podłącz** agenta Jamf i wykradnij jego informacje.

#### Kradzież sekretów

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

Możesz również monitorować lokalizację `/Library/Application Support/Jamf/tmp/` w poszukiwaniu **skryptów niestandardowych**, które administratorzy mogą chcieć wykonać za pomocą Jamf, ponieważ są **umieszczane tutaj, wykonywane i usuwane**. Te skrypty **mogą zawierać poświadczenia**.

Jednakże, **poświadczenia** mogą być przekazywane do tych skryptów jako **parametry**, więc musisz monitorować `ps aux | grep -i jamf` (nawet bez uprawnień roota).

Skrypt [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) może nasłuchiwać na dodawanie nowych plików i nowych argumentów procesu.

### Zdalny dostęp do macOS

A także o "specjalnych" **protokołach** **sieciowych** w **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

W niektórych przypadkach możesz zauważyć, że **komputer z MacOS jest podłączony do AD**. W takim scenariuszu powinieneś spróbować **przebadać** katalog aktywny, tak jak jesteś przyzwyczajony. Znajdziesz **pomoc** na następujących stronach:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Niektóre **lokalne narzędzia MacOS**, które mogą ci pomóc, to `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Poniżej znajdują się narzędzia przygotowane dla systemu MacOS, które automatycznie wyliczają AD i umożliwiają manipulację kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound to rozszerzenie narzędzia audytowego Bloodhound, które umożliwia zbieranie i przetwarzanie relacji w Active Directory na hostach MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost to projekt Objective-C, który ma na celu interakcję z interfejsem API Heimdal krb5 na macOS. Celem projektu jest umożliwienie lepszego testowania bezpieczeństwa wokół Kerberos na urządzeniach z systemem macOS, korzystając z natywnych interfejsów API, bez konieczności instalowania innych frameworków lub pakietów na celu.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Narzędzie JavaScript for Automation (JXA) do wyliczania Active Directory.

### Informacje o domenie
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Użytkownicy

Trzy rodzaje użytkowników systemu MacOS to:

* **Lokalni użytkownicy** - Zarządzani przez lokalną usługę OpenDirectory, nie są w żaden sposób połączeni z Active Directory.
* **Użytkownicy sieciowi** - Nietrwałe użytkownicy Active Directory, którzy wymagają połączenia z serwerem DC w celu uwierzytelnienia.
* **Użytkownicy mobilni** - Użytkownicy Active Directory z lokalną kopią zapasową swoich poświadczeń i plików.

Lokalne informacje o użytkownikach i grupach są przechowywane w folderze _/var/db/dslocal/nodes/Default._\
Na przykład, informacje o użytkowniku o nazwie _mark_ są przechowywane w pliku _/var/db/dslocal/nodes/Default/users/mark.plist_, a informacje o grupie _admin_ znajdują się w pliku _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Oprócz korzystania z krawędzi HasSession i AdminTo, **MacHound dodaje trzy nowe krawędzie** do bazy danych Bloodhound:

* **CanSSH** - podmiot uprawniony do SSH do hosta
* **CanVNC** - podmiot uprawniony do VNC do hosta
* **CanAE** - podmiot uprawniony do wykonywania skryptów AppleEvent na hoście
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
Więcej informacji na stronie [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## Dostęp do Keychain

Keychain prawdopodobnie zawiera wrażliwe informacje, które, jeśli uzyskane bez generowania monitu, mogą pomóc w przeprowadzeniu ćwiczeń zespołu czerwonego:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Usługi zewnętrzne

Red Teaming na MacOS różni się od zwykłego Red Teamingu na Windows, ponieważ zazwyczaj **MacOS jest zintegrowany z kilkoma platformami zewnętrznymi bezpośrednio**. Wspólną konfiguracją MacOS jest dostęp do komputera za pomocą **synchronizowanych poświadczeń OneLogin oraz dostęp do różnych usług zewnętrznych** (takich jak github, aws...) za pośrednictwem OneLogin.

## Różne techniki Red Team

### Safari

Gdy plik jest pobierany w Safari, jeśli jest to "bezpieczny" plik, zostanie **automatycznie otwarty**. Na przykład, jeśli **pobierasz plik zip**, zostanie on automatycznie rozpakowany:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## Odwołania

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
