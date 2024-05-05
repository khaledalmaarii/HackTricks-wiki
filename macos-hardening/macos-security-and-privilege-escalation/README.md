# Bezpieczeństwo macOS i Eskalacja Uprawnień

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) albo **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hakerami i łowcami błędów!

**Spojrzenie na Hacking**\
Zajmij się treściami, które zagłębiają się w emocje i wyzwania hakowania

**Aktualności na Żywo z Hackingu**\
Bądź na bieżąco z szybkim światem hakowania dzięki aktualnościom i spojrzeniom na żywo

**Najnowsze Ogłoszenia**\
Bądź na bieżąco z najnowszymi programami bug bounty i istotnymi aktualizacjami platform

**Dołącz do nas na** [**Discordzie**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hakerami już dziś!

## Podstawy macOS

Jeśli nie znasz macOS, powinieneś zacząć od nauki podstaw macOS:

* Specjalne **pliki i uprawnienia macOS:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Typowi **użytkownicy macOS**

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

* Typowe usługi i protokoły **sieciowe macOS**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Open Source** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Aby pobrać `tar.gz`, zmień adres URL, na przykład z [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) na [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM w macOS

W firmach systemy **macOS** są bardzo prawdopodobnie zarządzane za pomocą MDM. Dlatego z perspektywy atakującego ważne jest poznanie **jak to działa**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### macOS - Inspekcja, Debugowanie i Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Zabezpieczenia macOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Powierzchnia Ataku

### Uprawnienia Plików

Jeśli **proces uruchomiony jako root zapisuje** plik, który może być kontrolowany przez użytkownika, użytkownik może wykorzystać to do **eskalacji uprawnień**.\
Może to wystąpić w następujących sytuacjach:

* Plik używany został już utworzony przez użytkownika (należy do użytkownika)
* Plik używany jest zapisywalny przez użytkownika z powodu grupy
* Plik używany znajduje się w katalogu należącym do użytkownika (użytkownik mógłby utworzyć plik)
* Plik używany znajduje się w katalogu należącym do roota, ale użytkownik ma nad nim uprawnienia zapisu z powodu grupy (użytkownik mógłby utworzyć plik)

Mając możliwość **utworzenia pliku**, który będzie **używany przez roota**, użytkownik może **skorzystać z jego zawartości** lub nawet utworzyć **symlinki/hardlinki**, aby wskazywać go w inne miejsce.

Dla tego rodzaju podatności nie zapomnij sprawdzić podatnych instalatorów `.pkg`:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Rozszerzenie Pliku i Obsługa Aplikacji przez schematy URL

Dziwne aplikacje zarejestrowane przez rozszerzenia plików mogą być wykorzystane, a różne aplikacje mogą być zarejestrowane do otwierania określonych protokołów

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## Eskalacja Uprawnień TCC / SIP w macOS

W macOS **aplikacje i binaria mogą mieć uprawnienia** do dostępu do folderów lub ustawień, które czynią je bardziej uprzywilejowane niż inne.

Dlatego atakujący, który chce skutecznie skompromitować maszynę z macOS, będzie musiał **eskalować swoje uprawnienia TCC** (lub nawet **obejść SIP**, w zależności od swoich potrzeb).

Te uprawnienia zazwyczaj są udzielane w formie **uprawnień**, z którymi aplikacja jest podpisana, lub aplikacja może poprosić o pewne dostępy, a po **zatwierdzeniu ich przez użytkownika** mogą być one znalezione w **bazach danych TCC**. Inny sposób, w jaki proces może uzyskać te uprawnienia, to być **dzieckiem procesu** z tymi **uprawnieniami**, ponieważ zazwyczaj są one **dziedziczone**.

Przejdź pod te linki, aby znaleźć różne sposoby na [**eskalację uprawnień w TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), na [**obejście TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) oraz jak w przeszłości [**SIP został obejścia**](macos-security-protections/macos-sip.md#sip-bypasses).

## Tradycyjna Eskalacja Uprawnień w macOS

Oczywiście z perspektywy zespołów czerwonych powinieneś być również zainteresowany eskalacją do roota. Sprawdź poniższy post, aby uzyskać kilka wskazówek:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## Odnośniki

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hakerami i łowcami błędów!

**Spojrzenie na Hacking**\
Zanurz się w treściach, które zgłębiają emocje i wyzwania związane z hakerstwem

**Aktualności z Hackingu na Żywo**\
Bądź na bieżąco z szybkim tempem świata hakerstwa dzięki aktualnościom i spojrzeniom na żywo

**Najnowsze Ogłoszenia**\
Bądź na bieżąco z najnowszymi programami nagród za błędy i istotnymi aktualizacjami platform

**Dołącz do nas na** [**Discordzie**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hakerami już dziś!

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
