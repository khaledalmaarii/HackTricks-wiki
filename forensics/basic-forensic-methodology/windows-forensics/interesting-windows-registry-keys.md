# Interesujące klucze rejestru systemu Windows

### Interesujące klucze rejestru systemu Windows

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


### **Wersja systemu Windows i informacje o właścicielu**
- W lokalizacji **`Software\Microsoft\Windows NT\CurrentVersion`** znajdują się informacje o wersji systemu Windows, Service Pack, czasie instalacji oraz zarejestrowanym właścicielu.

### **Nazwa komputera**
- Nazwa hosta znajduje się w kluczu **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Ustawienia strefy czasowej**
- Strefa czasowa systemu jest przechowywana w kluczu **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Śledzenie czasu dostępu**
- Domyślnie śledzenie czasu ostatniego dostępu jest wyłączone (**`NtfsDisableLastAccessUpdate=1`**). Aby je włączyć, użyj:
`fsutil behavior set disablelastaccess 0`

### Wersje systemu Windows i dodatki Service Pack
- **Wersja systemu Windows** wskazuje na edycję (np. Home, Pro) i jej wydanie (np. Windows 10, Windows 11), podczas gdy **dodatki Service Pack** to aktualizacje zawierające poprawki i czasami nowe funkcje.

### Włączanie śledzenia czasu ostatniego dostępu
- Włączenie śledzenia czasu ostatniego dostępu pozwala zobaczyć, kiedy pliki były ostatnio otwierane, co może być istotne dla analizy śledczej lub monitorowania systemu.

### Szczegóły dotyczące informacji o sieci
- Rejestr przechowuje obszerne dane na temat konfiguracji sieciowej, w tym **typy sieci (bezprzewodowe, kablowe, 3G)** i **kategorie sieci (Publiczna, Prywatna/Domowa, Domena/Praca)**, które są istotne dla zrozumienia ustawień zabezpieczeń sieciowych i uprawnień.

### Buforowanie po stronie klienta (CSC)
- **CSC** poprawia dostęp do plików w trybie offline poprzez buforowanie kopii udostępnionych plików. Różne ustawienia **CSCFlags** kontrolują sposób i jakie pliki są buforowane, wpływając na wydajność i doświadczenie użytkownika, zwłaszcza w środowiskach o niestabilnym połączeniu.

### Programy uruchamiane automatycznie
- Programy wymienione w różnych kluczach rejestru `Run` i `RunOnce` są automatycznie uruchamiane podczas uruchamiania systemu, wpływając na czas rozruchu systemu i potencjalnie stanowiąc punkty zainteresowania w identyfikacji złośliwego oprogramowania lub niechcianego oprogramowania.

### Shellbags
- **Shellbags** przechowują nie tylko preferencje widoków folderów, ale także dostarczają dowodów śledczych dotyczących dostępu do folderów, nawet jeśli folder już nie istnieje. Są nieocenione w dochodzeniach, ujawniając aktywność użytkownika, która nie jest oczywista w inny sposób.

### Informacje i śledztwo dotyczące urządzeń USB
- Szczegóły przechowywane w rejestrze dotyczące urządzeń USB mogą pomóc w śledzeniu, które urządzenia były podłączone do komputera, potencjalnie łącząc urządzenie z transferami poufnych plików lub incydentami nieautoryzowanego dostępu.

### Numer seryjny woluminu
- Numer seryjny woluminu może być kluczowy do śledzenia konkretnej instancji systemu plików, co jest przydatne w scenariuszach śledczych, gdzie konieczne jest ustalenie pochodzenia pliku na różnych urządzeniach.

### **Szczegóły dotyczące wyłączania systemu**
- Czas wyłączenia i liczba (tylko dla systemu XP) są przechowywane w kluczach **`System\ControlSet001\Control\Windows`** i **`System\ControlSet001\Control\Watchdog\Display`**.

### **Konfiguracja sieciowa**
- Aby uzyskać szczegółowe informacje o interfejsie sieciowym, odwołaj się do klucza **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Pierwsze i ostatnie czasy połączenia sieciowego, w tym połączenia VPN, są rejestrowane w różnych ścieżkach w **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Udostępnione foldery**
- Udostępnione foldery i ustawienia znajdują się w kluczu **`System\ControlSet001\Services\lanmanserver\Shares`**. Ustawienia buforowania po stronie klienta (CSC) określają dostępność plików w trybie offline.

### **Programy uruchamiane automatycznie**
- Ścieżki takie jak **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** i podobne wpisy w `Software\Microsoft\Windows\CurrentVersion` zawierają szczegóły programów ustawionych do uruchamiania podczas uruchamiania systemu.

### **Wyszukiwania i wpisane ścieżki**
- Wyszukiwania w eksploratorze i wpisane ścieżki są śledzone w rejestrze pod kluczem **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** dla WordwheelQuery i TypedPaths, odpowiednio.

### **Ostatnio używane dokumenty i pliki Office**
- Ostatnio używane dokumenty i pliki Office są odnotowywane w `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` oraz w określonych ścieżkach dla konkretnej wersji Office.

### **Najczęściej używane elementy (MRU)**
- Listy MRU, wskazujące ostatnie ścieżki plików i polecenia, są przechowywane w różnych podkluczach `ComDlg32` i `Explorer` w `NTUSER.DAT`.

### **Śledzenie aktywności użytkownika**
- Funkcja User Assist rejestruje szczegółowe statystyki dotyczące używania aplikacji, w tym liczbę uruchomień i czas ostatniego uruchomienia, w **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Analiza Shellbags**
- Shellbags,
