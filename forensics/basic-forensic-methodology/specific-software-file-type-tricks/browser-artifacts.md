# Artefakty przeglądarek

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować przepływy pracy** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artefakty przeglądarek <a href="#id-3def" id="id-3def"></a>

Artefakty przeglądarek obejmują różne rodzaje danych przechowywanych przez przeglądarki internetowe, takie jak historia nawigacji, zakładki i dane pamięci podręcznej. Te artefakty są przechowywane w określonych folderach w systemie operacyjnym, różniących się lokalizacją i nazwą w zależności od przeglądarek, ale ogólnie przechowujących podobne typy danych.

Oto podsumowanie najczęstszych artefaktów przeglądarek:

- **Historia nawigacji**: Śledzi wizyty użytkownika na stronach internetowych, przydatne do identyfikacji wizyt na złośliwych stronach.
- **Dane autouzupełniania**: Sugestie oparte na częstych wyszukiwaniach, oferujące wgląd, gdy są połączone z historią nawigacji.
- **Zakładki**: Strony zapisane przez użytkownika dla szybkiego dostępu.
- **Rozszerzenia i dodatki**: Rozszerzenia przeglądarki lub dodatki zainstalowane przez użytkownika.
- **Pamięć podręczna**: Przechowuje treści internetowe (np. obrazy, pliki JavaScript) w celu poprawy czasu ładowania stron internetowych, wartościowe dla analizy śledczej.
- **Logowanie**: Przechowywane dane logowania.
- **Fawikony**: Ikony związane z witrynami, pojawiające się w kartach i zakładkach, przydatne do uzyskania dodatkowych informacji o wizytach użytkownika.
- **Sesje przeglądarki**: Dane związane z otwartymi sesjami przeglądarki.
- **Pobieranie**: Rejestr plików pobranych za pomocą przeglądarki.
- **Dane formularza**: Informacje wprowadzone w formularzach internetowych, zapisane w celu sugestii automatycznego uzupełniania w przyszłości.
- **Miniaturki**: Podgląd obrazów stron internetowych.
- **Custom Dictionary.txt**: Słowa dodane przez użytkownika do słownika przeglądarki.


## Firefox

Firefox organizuje dane użytkownika w profilach, przechowywanych w określonych lokalizacjach w zależności od systemu operacyjnego:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

W tych katalogach znajduje się plik `profiles.ini`, który zawiera listę profili użytkownika. Dane każdego profilu są przechowywane w folderze o nazwie zapisanej w zmiennej `Path` w pliku `profiles.ini`, znajdującym się w tym samym katalogu co `profiles.ini`. Jeśli folder profilu jest brakujący, może zostać usunięty.

W każdym folderze profilu można znaleźć kilka ważnych plików:

- **places.sqlite**: Przechowuje historię, zakładki i pobrane pliki. Narzędzia takie jak [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) w systemie Windows mogą uzyskać dostęp do danych historii.
- Użyj konkretnych zapytań SQL, aby wyodrębnić informacje o historii i pobieraniu.
- **bookmarkbackups**: Zawiera kopie zapasowe zakładek.
- **formhistory.sqlite**: Przechowuje dane formularzy internetowych.
- **handlers.json**: Zarządza obsługą protokołów.
- **persdict.dat**: Słowa dodane przez użytkownika do słownika.
- **addons.json** i **extensions.sqlite**: Informacje o zainstalowanych rozszerzeniach i dodatkach.
- **cookies.sqlite**: Przechowuje pliki cookie, z możliwością ich przeglądania w systemie Windows za pomocą [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** lub **startupCache**: Dane pamięci podręcznej, dostępne za pomocą narzędzi takich jak [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Przechowuje fawikony.
- **prefs.js**: Ustawienia i preferencje użytkownika.
- **downloads.sqlite**: Starsza baza danych pobieranych plików, obecnie zintegrowana z places.sqlite.
- **miniaturki**: Miniaturki stron internetowych.
- **logins.json**: Zaszyfrowane informacje logowania.
- **key4.db** lub **key3.db**: Przechowuje klucze szyfrowania do zabezpieczania poufnych informacji.

Dodatkowo, sprawdzenie ustawień przeglądarki dotyczących anty-phishingu można przeprowadzić, wyszukując wpisy `browser.safebrowsing` w pliku `prefs.js`, wskazujące, czy funkcje bezpiecznego przeglądania są włączone lub wyłączone.


Aby spróbować odszyfrować główne hasło, można użyć [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
Za pomocą poniższego skryptu i wywołania można określić plik hasła do ataku brute force:

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

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chrome przechowuje profile użytkowników w określonych lokalizacjach w zależności od systemu operacyjnego:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

W tych katalogach większość danych użytkownika można znaleźć w folderach **Default/** lub **ChromeDefaultData/**. Poniższe pliki przechowują istotne dane:

- **History**: Zawiera adresy URL, pobrane pliki i słowa kluczowe wyszukiwania. Na systemie Windows można użyć narzędzia [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) do odczytu historii. Kolumna "Transition Type" ma różne znaczenia, w tym kliknięcia użytkownika w linki, wpisywane adresy URL, wysyłanie formularzy i odświeżanie stron.
- **Cookies**: Przechowuje pliki cookie. Do ich przeglądania dostępne jest narzędzie [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Przechowuje dane w pamięci podręcznej. Użytkownicy systemu Windows mogą skorzystać z narzędzia [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) do ich przeglądania.
- **Bookmarks**: Zakładki użytkownika.
- **Web Data**: Zawiera historię formularzy.
- **Favicons**: Przechowuje ikony stron internetowych.
- **Login Data**: Zawiera dane logowania, takie jak nazwy użytkowników i hasła.
- **Current Session**/**Current Tabs**: Dane dotyczące bieżącej sesji przeglądania i otwartych kart.
- **Last Session**/**Last Tabs**: Informacje o aktywnych stronach podczas ostatniej sesji przed zamknięciem przeglądarki Chrome.
- **Extensions**: Katalogi dla rozszerzeń i dodatków przeglądarki.
- **Thumbnails**: Przechowuje miniaturki stron internetowych.
- **Preferences**: Plik zawierający wiele informacji, w tym ustawienia dla wtyczek, rozszerzeń, wyskakujących okienek, powiadomień i innych.
- **Wbudowana ochrona przed phishingiem w przeglądarce**: Aby sprawdzić, czy ochrona przed phishingiem i oprogramowaniem złośliwym jest włączona, wykonaj polecenie `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. W wyniku wyszukiwania poszukaj `{"enabled: true,"}`.

## **Odzyskiwanie danych z bazy SQLite**

Jak można zauważyć w poprzednich sekcjach, zarówno Chrome, jak i Firefox używają baz danych **SQLite** do przechowywania danych. Możliwe jest **odzyskanie usuniętych wpisów za pomocą narzędzia** [**sqlparse**](https://github.com/padfoot999/sqlparse) **lub** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 zarządza swoimi danymi i metadanymi w różnych lokalizacjach, ułatwiając oddzielenie przechowywanych informacji od ich odpowiadających szczegółów w celu łatwego dostępu i zarządzania.

### Przechowywanie metadanych
Metadane dla Internet Explorera są przechowywane w `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (gdzie VX to V01, V16 lub V24). Dodatkowo, plik `V01.log` może wykazywać różnice w czasie modyfikacji w porównaniu do `WebcacheVX.data`, co wskazuje na konieczność naprawy za pomocą `esentutl /r V01 /d`. Te metadane, przechowywane w bazie danych ESE, można odzyskać i przeglądać za pomocą narzędzi takich jak photorec i [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). W tabeli **Containers** można rozpoznać konkretne tabele lub kontenery, w których przechowywane są poszczególne segmenty danych, w tym szczegóły pamięci podręcznej dla innych narzędzi Microsoftu, takich jak Skype.

### Przeglądanie pamięci podręcznej
Narzędzie [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) umożliwia przeglądanie pamięci podręcznej, wymagając podania lokalizacji folderu z danymi pamięci podręcznej. Metadane pamięci podręcznej obejmują nazwę pliku, katalog, liczbę dostępów, pochodzenie URL i znaczniki czasowe wskazujące czas utworzenia, dostępu, modyfikacji i wygaśnięcia pamięci podręcznej.

### Zarządzanie plikami cookie
Pliki cookie można przeglądać za pomocą narzędzia [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), a metadane obejmują nazwy, adresy URL, liczbę dostępów i różne szczegóły związane z czasem. Trwałe pliki cookie są przechowywane w `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, a pliki sesji znajdują się w pamięci.

### Szczegóły pobierania
Metadane pobierania są dostępne za pomocą narzędzia [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), a konkretne kontenery przechowują dane, takie jak URL, typ pliku i lokalizację pobierania. Fizyczne pliki można znaleźć w `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historia przeglądania
Aby przejrzeć historię przeglądania, można użyć narzędzia [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), wymagającego lokalizacji plików historii i konfiguracji dla Internet Explorera. Metadane obejmują czasy modyfikacji i dostępu, oraz liczbę dostępów. Pliki historii znajdują się w `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Wpisywane adresy URL
Wpisywane adresy URL i czasy ich użycia są przechowywane w rejestrze pod `NTUSER.DAT` w `Software\Microsoft\InternetExplorer\TypedURLs` i `Software\Microsoft\InternetExplorer\TypedURLsTime`, śledząc ostatnie 50 wpisanych przez użytkownika adresów URL i ich ostatnie czasy wprowadzania.

## Microsoft Edge

Microsoft Edge przechowuje dane użytkownika w `%userprofile%\Appdata\Local\Packages`. Ścieżki do różnych typów danych są następujące:

- **Ścieżka profilu**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Historia, pliki cookie i pobrane pliki**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Ustawienia, zakładki i lista do odczytu**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do repozytoriów** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>
