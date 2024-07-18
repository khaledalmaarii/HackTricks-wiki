# Interesujące klucze rejestru systemu Windows

### Interesujące klucze rejestru systemu Windows

{% hint style="success" %}
Dowiedz się i ćwicz hakowanie AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz hakowanie GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}


### **Wersja systemu Windows i informacje o właścicielu**
- W kluczu **`Software\Microsoft\Windows NT\CurrentVersion`** znajdziesz informacje o wersji systemu Windows, Service Pack, czasie instalacji oraz nazwie zarejestrowanego właściciela w prosty sposób.

### **Nazwa komputera**
- Nazwa hosta znajduje się w **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Ustawienia strefy czasowej**
- Strefa czasowa systemu jest przechowywana w **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Śledzenie czasu dostępu**
- Domyślnie śledzenie ostatniego czasu dostępu jest wyłączone (**`NtfsDisableLastAccessUpdate=1`**). Aby je włączyć, użyj:
`fsutil behavior set disablelastaccess 0`

### Wersje systemu Windows i Service Packi
- **Wersja systemu Windows** wskazuje na edycję (np. Home, Pro) i jej wydanie (np. Windows 10, Windows 11), natomiast **Service Packi** to aktualizacje zawierające poprawki i czasem nowe funkcje.

### Włączanie śledzenia ostatniego dostępu
- Włączenie śledzenia ostatniego dostępu pozwala zobaczyć, kiedy pliki były ostatnio otwierane, co może być kluczowe dla analizy sądowej lub monitorowania systemu.

### Szczegóły informacji o sieci
- Rejestr przechowuje obszerne dane na temat konfiguracji sieci, w tym **rodzaje sieci (bezprzewodowe, kablowe, 3G)** i **kategorie sieci (Publiczna, Prywatna/Domowa, Domenowa/Pracownicza)**, które są istotne dla zrozumienia ustawień zabezpieczeń sieciowych i uprawnień.

### Buforowanie po stronie klienta (CSC)
- **CSC** poprawia dostęp do plików w trybie offline poprzez buforowanie kopii udostępnionych plików. Różne ustawienia **CSCFlags** kontrolują sposób i jakie pliki są buforowane, wpływając na wydajność i doświadczenie użytkownika, zwłaszcza w środowiskach z niestabilnym połączeniem.

### Programy uruchamiane automatycznie
- Programy wymienione w różnych kluczach rejestru `Run` i `RunOnce` są automatycznie uruchamiane podczas startu systemu, wpływając na czas uruchamiania systemu i potencjalnie będąc punktami zainteresowania do identyfikacji oprogramowania złośliwego lub niechcianego.

### Shellbags
- **Shellbags** przechowują nie tylko preferencje widoków folderów, ale także dostarczają dowodów sądowych na dostęp do folderów, nawet jeśli folder już nie istnieje. Są nieocenione w dochodzeniach, ujawniając aktywność użytkownika, która nie jest oczywista w inny sposób.

### Informacje i analiza dotycząca USB
- Szczegóły przechowywane w rejestrze na temat urządzeń USB mogą pomóc w śledzeniu, które urządzenia były podłączone do komputera, potencjalnie łącząc urządzenie z transferami plików o wrażliwej zawartości lub incydentami nieautoryzowanego dostępu.

### Numer seryjny woluminu
- Numer seryjny woluminu może być kluczowy do śledzenia określonej instancji systemu plików, przydatny w scenariuszach sądowych, gdzie trzeba ustalić pochodzenie pliku na różnych urządzeniach.

### **Szczegóły wyłączania**
- Czas wyłączenia i liczba (tylko dla XP) są przechowywane w **`System\ControlSet001\Control\Windows`** i **`System\ControlSet001\Control\Watchdog\Display`**.

### **Konfiguracja sieci**
- Dla szczegółowych informacji o interfejsie sieciowym, odwołaj się do **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Pierwsze i ostatnie czasy połączenia sieciowego, w tym połączenia VPN, są rejestrowane pod różnymi ścieżkami w **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Udostępnione foldery**
- Udostępnione foldery i ustawienia znajdują się w **`System\ControlSet001\Services\lanmanserver\Shares`**. Ustawienia buforowania po stronie klienta (CSC) określają dostępność plików w trybie offline.

### **Programy uruchamiane automatycznie**
- Ścieżki takie jak **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** i podobne wpisy w `Software\Microsoft\Windows\CurrentVersion` szczegółowo opisują programy ustawione do uruchamiania podczas startu.

### **Wyszukiwania i wpisane ścieżki**
- Wyszukiwania Exploratora i wpisane ścieżki są śledzone w rejestrze pod **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** dla WordwheelQuery i TypedPaths, odpowiednio.

### **Ostatnio używane dokumenty i pliki biurowe**
- Ostatnio używane dokumenty i pliki biurowe są odnotowywane w `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` oraz w określonych ścieżkach wersji Office.

### **Ostatnio używane elementy (MRU)**
- Listy MRU, wskazujące ostatnie ścieżki plików i polecenia, są przechowywane w różnych podkluczach `ComDlg32` i `Explorer` w `NTUSER.DAT`.

### **Śledzenie aktywności użytkownika**
- Funkcja User Assist rejestruje szczegółowe statystyki użytkowania aplikacji, w tym liczbę uruchomień i czas ostatniego uruchomienia, w **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Analiza Shellbags**
- Shellbags, ujawniające szczegóły dostępu do folderów, są przechowywane w `USRCLASS.DAT` i `NTUSER.DAT` w `Software\Microsoft\Windows\Shell`. Użyj **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** do analizy.

### **Historia urządzeń USB**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** i **`HKLM\SYSTEM\ControlSet001\Enum\USB`** zawierają bogate szczegóły na temat podłączonych urządzeń USB, w tym producenta, nazwę produktu i znaczniki czasu połączenia.
- Użytkownik powiązany z konkretnym urządzeniem USB można zlokalizować, wyszukując żyły `NTUSER.DAT` dla **{GUID}** urządzenia.
- Ostatnie zamontowane urządzenie i jego numer seryjny woluminu można śledzić za pomocą `System\MountedDevices` i `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, odpowiednio.

Ten przewodnik zawiera istotne ścieżki i metody dostępu do szczegółowych informacji o systemie, sieci i aktywności użytkownika w systemach Windows, dążąc do klarowności i użyteczności.



{% hint style="success" %}
Dowiedz się i ćwicz hakowanie AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz hakowanie GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
