# Poziomy integralności

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## Poziomy integralności

W systemach Windows Vista i nowszych, wszystkie chronione elementy mają etykietę **poziomu integralności**. Ta konfiguracja zazwyczaj przypisuje "średni" poziom integralności do plików i kluczy rejestru, z wyjątkiem niektórych folderów i plików, do których Internet Explorer 7 może zapisywać na niskim poziomie integralności. Domyślne zachowanie polega na tym, że procesy inicjowane przez standardowych użytkowników mają średni poziom integralności, podczas gdy usługi zazwyczaj działają na poziomie integralności systemu. Etykieta wysokiej integralności chroni katalog główny.

Kluczową zasadą jest to, że obiekty nie mogą być modyfikowane przez procesy o niższym poziomie integralności niż poziom obiektu. Poziomy integralności to:

* **Nieufny**: Ten poziom jest przeznaczony dla procesów z anonimowymi logowaniami. %%%Przykład: Chrome%%%
* **Niski**: Głównie dla interakcji internetowych, szczególnie w trybie chronionym Internet Explorera, wpływając na powiązane pliki i procesy oraz niektóre foldery, takie jak **Folder tymczasowy Internetu**. Procesy o niskiej integralności napotykają znaczne ograniczenia, w tym brak dostępu do zapisu w rejestrze i ograniczony dostęp do zapisu w profilu użytkownika.
* **Średni**: Domyślny poziom dla większości działań, przypisany do standardowych użytkowników i obiektów bez określonych poziomów integralności. Nawet członkowie grupy Administratorzy działają na tym poziomie domyślnie.
* **Wysoki**: Zarezerwowany dla administratorów, pozwalający im modyfikować obiekty na niższych poziomach integralności, w tym te na wysokim poziomie.
* **System**: Najwyższy poziom operacyjny dla jądra Windows i podstawowych usług, niedostępny nawet dla administratorów, zapewniający ochronę kluczowych funkcji systemu.
* **Instalator**: Unikalny poziom, który stoi ponad wszystkimi innymi, umożliwiający obiektom na tym poziomie odinstalowanie dowolnego innego obiektu.

Możesz uzyskać poziom integralności procesu, używając **Process Explorer** z **Sysinternals**, uzyskując dostęp do **właściwości** procesu i przeglądając zakładkę "**Zabezpieczenia**":

![](<../../.gitbook/assets/image (824).png>)

Możesz również uzyskać swój **aktualny poziom integralności** używając `whoami /groups`

![](<../../.gitbook/assets/image (325).png>)

### Poziomy integralności w systemie plików

Obiekt w systemie plików może wymagać **minimalnego wymogu poziomu integralności**, a jeśli proces nie ma tego poziomu integralności, nie będzie mógł z nim współdziałać.\
Na przykład, stwórzmy **zwykły plik z konsoli zwykłego użytkownika i sprawdźmy uprawnienia**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Teraz przypiszmy minimalny poziom integralności **Wysoki** do pliku. **Musisz to zrobić z konsoli** uruchomionej jako **administrator**, ponieważ **zwykła konsola** będzie działać na poziomie integralności Średnim i **nie będzie mogła** przypisać poziomu integralności Wysokiemu obiektowi:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
To jest miejsce, w którym sprawy stają się interesujące. Możesz zobaczyć, że użytkownik `DESKTOP-IDJHTKP\user` ma **PEŁNE uprawnienia** do pliku (w rzeczywistości to był użytkownik, który stworzył plik), jednak z powodu minimalnego poziomu integralności wdrożonego, nie będzie mógł już modyfikować pliku, chyba że działa w ramach Wysokiego Poziomu Integralności (zauważ, że będzie mógł go odczytać):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Dlatego, gdy plik ma minimalny poziom integralności, aby go zmodyfikować, musisz działać przynajmniej na tym poziomie integralności.**
{% endhint %}

### Poziomy integralności w plikach binarnych

Zrobiłem kopię `cmd.exe` w `C:\Windows\System32\cmd-low.exe` i ustawiłem jej **poziom integralności na niski z konsoli administratora:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Teraz, gdy uruchamiam `cmd-low.exe`, **będzie działać na niskim poziomie integralności** zamiast na średnim:

![](<../../.gitbook/assets/image (313).png>)

Dla ciekawskich, jeśli przypiszesz wysoki poziom integralności do binarnego pliku (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), nie uruchomi się on automatycznie z wysokim poziomem integralności (jeśli wywołasz go z poziomu średniej integralności -- domyślnie -- będzie działać na średnim poziomie integralności).

### Poziomy integralności w procesach

Nie wszystkie pliki i foldery mają minimalny poziom integralności, **ale wszystkie procesy działają na poziomie integralności**. I podobnie jak w przypadku systemu plików, **jeśli proces chce zapisać w innym procesie, musi mieć przynajmniej ten sam poziom integralności**. Oznacza to, że proces z niskim poziomem integralności nie może otworzyć uchwytu z pełnym dostępem do procesu ze średnim poziomem integralności.

Z powodu ograniczeń omówionych w tej i poprzedniej sekcji, z punktu widzenia bezpieczeństwa, zawsze **zaleca się uruchamianie procesu na jak najniższym poziomie integralności**.
