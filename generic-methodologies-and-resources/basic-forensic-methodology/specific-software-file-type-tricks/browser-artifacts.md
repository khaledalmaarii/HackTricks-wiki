# Artefakty przeglądarek

<details>

<summary><strong>Nauka hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** z wykorzystaniem najbardziej **zaawansowanych narzędzi społecznościowych** na świecie.\
Zdobądź dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artefakty przeglądarek <a href="#id-3def" id="id-3def"></a>

Artefakty przeglądarek obejmują różne rodzaje danych przechowywanych przez przeglądarki internetowe, takie jak historia nawigacji, zakładki i dane pamięci podręcznej. Te artefakty są przechowywane w określonych folderach w systemie operacyjnym, różniących się pod względem lokalizacji i nazwy w zależności od przeglądarki, ale zazwyczaj przechowujących podobne rodzaje danych.

Oto podsumowanie najczęstszych artefaktów przeglądarek:

* **Historia nawigacji**: Śledzi wizyty użytkownika na stronach internetowych, przydatna do identyfikacji wizyt na złośliwych stronach.
* **Dane autouzupełniania**: Sugestie oparte na częstych wyszukiwaniach, oferujące wgląd, gdy są połączone z historią nawigacji.
* **Zakładki**: Strony zapisane przez użytkownika dla szybkiego dostępu.
* **Rozszerzenia i dodatki**: Rozszerzenia przeglądarki lub dodatki zainstalowane przez użytkownika.
* **Pamięć podręczna**: Przechowuje treści internetowe (np. obrazy, pliki JavaScript) w celu poprawy czasów ładowania strony internetowej, wartościowa do analizy sądowej.
* **Logowania**: Przechowywane dane logowania.
* **Favicons**: Ikony związane z witrynami, pojawiające się w kartach i zakładkach, przydatne do uzyskania dodatkowych informacji o wizytach użytkownika.
* **Sesje przeglądarki**: Dane związane z otwartymi sesjami przeglądarki.
* **Pobrania**: Rejestracje plików pobranych za pomocą przeglądarki.
* **Dane formularza**: Informacje wprowadzone w formularzach internetowych, zapisane do przyszłych sugestii autouzupełniania.
* **Miniatury**: Podglądy stron internetowych.
* **Custom Dictionary.txt**: Słowa dodane przez użytkownika do słownika przeglądarki.

## Firefox

Firefox organizuje dane użytkownika w profilach, przechowywanych w określonych lokalizacjach w zależności od systemu operacyjnego:

* **Linux**: `~/.mozilla/firefox/`
* **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Plik `profiles.ini` w tych katalogach wymienia profile użytkownika. Dane każdego profilu są przechowywane w folderze o nazwie zmiennej `Path` w `profiles.ini`, znajdującym się w tym samym katalogu co `profiles.ini`. Jeśli brakuje folderu profilu, może to oznaczać, że został usunięty.

W każdym folderze profilu można znaleźć kilka ważnych plików:

* **places.sqlite**: Przechowuje historię, zakładki i pobrania. Narzędzia takie jak [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) w systemie Windows mogą uzyskać dostęp do danych historycznych.
* Użyj konkretnych zapytań SQL do wydobycia informacji o historii i pobranych plikach.
* **bookmarkbackups**: Zawiera kopie zapasowe zakładek.
* **formhistory.sqlite**: Przechowuje dane formularzy internetowych.
* **handlers.json**: Zarządza obsługą protokołów.
* **persdict.dat**: Słowa słownika niestandardowego.
* **addons.json** i **extensions.sqlite**: Informacje o zainstalowanych dodatkach i rozszerzeniach.
* **cookies.sqlite**: Przechowywanie plików cookie, z [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) dostępnym do inspekcji w systemie Windows.
* **cache2/entries** lub **startupCache**: Dane pamięci podręcznej, dostępne za pomocą narzędzi takich jak [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html).
* **favicons.sqlite**: Przechowuje favikony.
* **prefs.js**: Ustawienia i preferencje użytkownika.
* **downloads.sqlite**: Starsza baza danych pobranych plików, teraz zintegrowana z places.sqlite.
* **thumbnails**: Miniatury stron internetowych.
* **logins.json**: Zaszyfrowane informacje logowania.
* **key4.db** lub **key3.db**: Przechowuje klucze szyfrowania do zabezpieczania poufnych informacji.

Dodatkowo, sprawdzenie ustawień anty-phishing przeglądarki można wykonać, wyszukując wpisy `browser.safebrowsing` w `prefs.js`, wskazujące, czy funkcje bezpiecznego przeglądania są włączone czy wyłączone.

Aby spróbować odszyfrować główne hasło, można skorzystać z [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
Z poniższym skryptem i wywołaniem można określić plik hasła do ataku brutalnej siły:

{% code title="brute.sh" %}
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
{% endcode %}

![](<../../../.gitbook/assets/image (692).png>)

## Google Chrome

Google Chrome przechowuje profile użytkownika w określonych lokalizacjach w zależności od systemu operacyjnego:

* **Linux**: `~/.config/google-chrome/`
* **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
* **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

W tych katalogach większość danych użytkownika można znaleźć w folderach **Default/** lub **ChromeDefaultData/**. Poniższe pliki przechowują istotne dane:

* **History**: Zawiera adresy URL, pobrania i słowa kluczowe wyszukiwania. Na systemie Windows można użyć [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) do odczytania historii. Kolumna "Typ przejścia" ma różne znaczenia, w tym kliknięcia użytkownika w linki, wpisane adresy URL, przesłane formularze i przeładowania strony.
* **Cookies**: Przechowuje pliki cookie. Do inspekcji dostępny jest [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html).
* **Cache**: Przechowuje dane w pamięci podręcznej. Użytkownicy systemu Windows mogą skorzystać z [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html) do inspekcji.
* **Zakładki**: Zakładki użytkownika.
* **Web Data**: Zawiera historię formularzy.
* **Favicons**: Przechowuje ikony stron internetowych.
* **Login Data**: Zawiera dane logowania, takie jak nazwy użytkowników i hasła.
* **Bieżąca sesja**/**Bieżące karty**: Dane dotyczące bieżącej sesji przeglądania i otwartych kart.
* **Ostatnia sesja**/**Ostatnie karty**: Informacje o aktywnych stronach podczas ostatniej sesji przed zamknięciem przeglądarki Chrome.
* **Rozszerzenia**: Katalogi dla rozszerzeń i dodatków przeglądarki.
* **Miniaturki**: Przechowuje miniaturki stron internetowych.
* **Preferencje**: Plik bogaty w informacje, zawierający ustawienia dla wtyczek, rozszerzeń, wyskakujących okien, powiadomień i innych.
* **Wbudowana ochrona przed phishingiem przeglądarki**: Aby sprawdzić, czy ochrona przed phishingiem i złośliwym oprogramowaniem jest włączona, uruchom polecenie `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Szukaj `{"enabled: true,"}` w wyniku.

## **Odzyskiwanie danych z bazy danych SQLite**

Jak można zauważyć w poprzednich sekcjach, zarówno Chrome, jak i Firefox używają baz danych **SQLite** do przechowywania danych. Możliwe jest **odzyskanie usuniętych wpisów za pomocą narzędzia** [**sqlparse**](https://github.com/padfoot999/sqlparse) **lub** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 zarządza swoimi danymi i metadanymi w różnych lokalizacjach, ułatwiając oddzielenie przechowywanych informacji i odpowiadających im szczegółów dla łatwego dostępu i zarządzania.

### Przechowywanie metadanych

Metadane dla Internet Explorera są przechowywane w `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (gdzie VX to V01, V16 lub V24). Towarzyszący temu plik `V01.log` może wykazywać rozbieżności czasów modyfikacji w porównaniu z `WebcacheVX.data`, co wskazuje na konieczność naprawy za pomocą `esentutl /r V01 /d`. Te metadane, przechowywane w bazie danych ESE, można odzyskać i inspirować za pomocą narzędzi takich jak photorec i [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html). W tabeli **Containers** można rozpoznać konkretne tabele lub kontenery, w których przechowywany jest każdy segment danych, w tym szczegóły pamięci podręcznej dla innych narzędzi Microsoftu, takich jak Skype.

### Inspekcja pamięci podręcznej

Narzędzie [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) umożliwia inspekcję pamięci podręcznej, wymagając lokalizacji folderu z ekstrakcją danych pamięci podręcznej. Metadane pamięci podręcznej obejmują nazwę pliku, katalog, liczbę dostępów, pochodzenie URL i znaczniki czasu wskazujące czasy tworzenia, dostępu, modyfikacji i wygaśnięcia pamięci podręcznej.

### Zarządzanie plikami cookie

Pliki cookie można badać za pomocą [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), a metadane obejmują nazwy, adresy URL, liczby dostępów i różne szczegóły związane z czasem. Trwałe pliki cookie są przechowywane w `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, a pliki sesji znajdują się w pamięci.

### Szczegóły pobierania

Metadane pobierania są dostępne za pomocą [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), a konkretne kontenery przechowują dane, takie jak URL, typ pliku i lokalizację pobierania. Fizyczne pliki można znaleźć w `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historia przeglądania

Aby przejrzeć historię przeglądania, można użyć [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html), wymagając lokalizacji wyodrębnionych plików historii i konfiguracji dla Internet Explorera. Metadane obejmują czasy modyfikacji i dostępu, wraz z liczbą dostępów. Pliki historii znajdują się w `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Wpisywane adresy URL

Wpisywane adresy URL i ich czasy użycia są przechowywane w rejestrze pod `NTUSER.DAT` w `Software\Microsoft\InternetExplorer\TypedURLs` i `Software\Microsoft\InternetExplorer\TypedURLsTime`, śledząc ostatnie 50 adresów URL wprowadzonych przez użytkownika i ich ostatnie czasy wprowadzenia.

## Microsoft Edge

Microsoft Edge przechowuje dane użytkownika w `%userprofile%\Appdata\Local\Packages`. Ścieżki do różnych typów danych to:

* **Ścieżka profilu**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
* **Historia, pliki cookie i pobrania**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
* **Ustawienia, zakładki i lista czytania**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
* **Pamięć podręczna**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
* **Ostatnie aktywne sesje**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Dane Safari są przechowywane w `/Users/$User/Library/Safari`. Kluczowe pliki to:

* **History.db**: Zawiera tabele `history_visits` i `history_items` z adresami URL i znacznikami czasu wizyt. Użyj `sqlite3` do zapytań.
* **Downloads.plist**: Informacje o pobranych plikach.
* **Bookmarks.plist**: Przechowuje adresy URL zakładek.
* **TopSites.plist**: Najczęściej odwiedzane strony.
* **Extensions.plist**: Lista rozszerzeń przeglądarki Safari. Użyj `plutil` lub `pluginkit` do odzyskania.
* **UserNotificationPermissions.plist**: Domeny uprawnione do wysyłania powiadomień. Użyj `plutil` do analizy.
* **LastSession.plist**: Karty z ostatniej sesji. Użyj `plutil` do analizy.
* **Wbudowana ochrona przed phishingiem przeglądarki**: Sprawdź za pomocą `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Odpowiedź 1 oznacza, że funkcja jest aktywna.

## Opera

Dane Opery znajdują się w `/Users/$USER/Library/Application Support/com.operasoftware.Opera` i mają format historii i pobierania podobny do Chrome'a.

* **Wbudowana ochrona przed phishingiem przeglądarki**: Sprawdź, czy `fraud_protection_enabled` w pliku Preferencje jest ustawione na `true` za pomocą `grep`.

Te ścieżki i polecenia są kluczowe dla dostępu i zrozumienia danych przeglądania przechowywanych przez różne przeglądarki internetowe.

## Referencje

* [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
* [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
* [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
* **Książka: OS X Incident Response: Scripting and Analysis By Jaron Bradley strona 123**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) do łatwego tworzenia i **automatyzacji prac** z wykorzystaniem najbardziej zaawansowanych narzędzi społeczności na świecie.\
Zdobądź dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Zacznij od zera i zostań ekspertem ds. hakowania AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>
* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
