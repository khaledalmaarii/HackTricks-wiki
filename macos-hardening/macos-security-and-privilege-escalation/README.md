# Bezpieczeństwo i eskalacja uprawnień w macOS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hakerami i łowcami nagród za błędy!

**Wgląd w hakerstwo**\
Zajmuj się treściami, które zagłębiają się w emocje i wyzwania hakerstwa

**Aktualności na żywo z hakerstwa**\
Bądź na bieżąco z szybkim tempem świata hakerstwa dzięki aktualnym wiadomościom i wglądom

**Najnowsze ogłoszenia**\
Bądź na bieżąco z najnowszymi programami nagród za błędy i ważnymi aktualizacjami platformy

**Dołącz do nas na** [**Discordzie**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hakerami już dziś!

## Podstawy macOS

Jeśli nie znasz się na macOS, powinieneś zacząć od nauki podstaw macOS:

* Specjalne **pliki i uprawnienia macOS:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Wspólne **użytkownicy macOS**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **Architektura** jądra

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Wspólne usługi i protokoły **sieciowe macOS**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Open Source** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Aby pobrać `tar.gz`, zmień adres URL, na przykład [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) na [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### macOS MDM

W firmach **systemy macOS** są prawdopodobnie zarządzane za pomocą MDM. Dlatego z perspektywy atakującego ważne jest, aby wiedzieć, **jak to działa**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### macOS - Inspekcja, debugowanie i fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Zabezpieczenia macOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Powierzchnia ataku

### Uprawnienia plików

Jeśli **proces działający jako root zapisuje** plik, który może być kontrolowany przez użytkownika, użytkownik może go wykorzystać do **eskalacji uprawnień**.\
Może to wystąpić w następujących sytuacjach:

* Plik używany był już utworzony przez użytkownika (należy do użytkownika)
* Plik używany jest zapisywalny przez użytkownika z powodu grupy
* Plik używany znajduje się w katalogu należącym do użytkownika (użytkownik może utworzyć plik)
* Plik używany znajduje się w katalogu należącym do roota, ale użytkownik ma do niego dostęp zapisu z powodu grupy (użytkownik może utworzyć plik)

Możliwość **utworzenia pliku**, który będzie **używany przez roota**, pozwala użytkownikowi na **wykorzystanie jego zawartości** lub nawet tworzenie **symlinków/hardlinków**, aby wskazywać go w inne miejsce.

Przy tego rodzaju podatności nie zapomnij **sprawdzić podatnych instalatorów `.pkg`**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}



### Rozszerzenie pliku i obsługa aplikacji przez schemat URL

Dziwne aplikacje zarejestrowane przez rozszerzenia plików mogą być wykorzystane, a różne aplikacje mogą być zarejestrowane do otwierania określonych protokołów

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / Eskalacja uprawnień SIP

W macOS **aplikacje i pliki binarne mogą mieć uprawnienia** do dostępu do folderów lub ustawień, które czynią je bardziej uprzywilejowanymi niż inne.

Dlatego atakujący, który chce skutecznie skompromitować maszynę macOS, będzie musiał **eskalować swoje uprawnienia TCC** (lub nawet **omijać SIP**, w zależności od swoich potrzeb).

Te uprawnienia zwykle są udzielane w formie **uprawnień**, z którymi aplikacja jest podpisana, lub aplikacja może poprosić o dostęp i po **zatwierdzeniu przez użytkownika** można je znaleźć w **bazach danych TCC**. Inny sposób, w jaki proces może uzyskać te uprawnienia, to być **dzieckiem procesu** z tymi **uprawnieniami**, ponieważ zwykle są one **dziedziczone**.

Przejdź do tych linków, aby znaleźć różne sposoby [**eskalacji uprawnień w TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), [**omijania TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) i jak w przeszłości [**omijano SIP**](macos-security-protections/macos-sip.md#sip-bypasses).

## Tradycyjna eskalacja uprawnień w macOS

Oczywiście z perspektywy zespołów czerwonych warto również zainteresować się eskalacją do roota. Sprawdź poniższy post, aby uzyskać kilka wskazówek:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Odwołania

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hakerami i łowcami błędów!

**Wnioski z Hackingu**\
Zajmuj się treściami, które zagłębiają się w emocje i wyzwania związane z hakowaniem

**Aktualności na żywo z Hackingu**\
Bądź na bieżąco z szybkim tempem świata hakowania dzięki aktualnym wiadomościom i spostrzeżeniom

**Najnowsze ogłoszenia**\
Bądź na bieżąco z najnowszymi programami bug bounty i ważnymi aktualizacjami platformy

**Dołącz do nas na** [**Discordzie**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hakerami już dziś!

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
