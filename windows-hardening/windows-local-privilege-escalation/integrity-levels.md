<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


# Poziomy integralności

W systemach Windows Vista i nowszych wszystkie chronione elementy są oznaczone poziomem integralności. W większości przypadków przypisywany jest on poziom "średni" dla plików i kluczy rejestru, z wyjątkiem określonych folderów i plików, do których Internet Explorer 7 może zapisywać na poziomie niskiej integralności. Domyślne zachowanie polega na tym, że procesy uruchamiane przez standardowych użytkowników mają poziom integralności średni, podczas gdy usługi zazwyczaj działają na poziomie integralności systemu. Wysoki poziom integralności chroni katalog główny.

Podstawową zasadą jest to, że obiekty nie mogą być modyfikowane przez procesy o niższym poziomie integralności niż poziom obiektu. Poziomy integralności to:

- **Niezaufany**: Ten poziom dotyczy procesów z anonimowymi logowaniami. %%%Przykład: Chrome%%%
- **Niski**: Głównie dla interakcji internetowych, zwłaszcza w trybie chronionym Internet Explorera, wpływający na powiązane pliki i procesy oraz określone foldery, takie jak **Folder tymczasowy Internetu**. Procesy o niskiej integralności mają znaczne ograniczenia, w tym brak dostępu do zapisu w rejestrze i ograniczony dostęp do zapisu profilu użytkownika.
- **Średni**: Domyślny poziom dla większości działań, przypisany do standardowych użytkowników i obiektów bez określonych poziomów integralności. Nawet członkowie grupy Administratorzy działają domyślnie na tym poziomie.
- **Wysoki**: Zarezerwowany dla administratorów, umożliwiający im modyfikowanie obiektów na niższych poziomach integralności, w tym na poziomie wysokim.
- **Systemowy**: Najwyższy poziom operacyjny dla jądra systemu Windows i podstawowych usług, niedostępny nawet dla administratorów, zapewniający ochronę istotnych funkcji systemowych.
- **Instalator**: Unikalny poziom, który stoi ponad wszystkimi innymi, umożliwiający obiektom na tym poziomie odinstalowanie dowolnego innego obiektu.

Możesz uzyskać poziom integralności procesu za pomocą narzędzia **Process Explorer** z **Sysinternals**, uzyskując dostęp do **właściwości** procesu i przeglądając zakładkę "**Bezpieczeństwo**":

![](<../../.gitbook/assets/image (318).png>)

Możesz również sprawdzić swój **bieżący poziom integralności** za pomocą polecenia `whoami /groups`

![](<../../.gitbook/assets/image (319).png>)

## Poziomy integralności w systemie plików

Obiekt w systemie plików może wymagać **minimalnego poziomu integralności** i jeśli proces nie ma tego poziomu integralności, nie będzie mógł z nim współdziałać.\
Na przykład, **utwórzmy zwykły plik z konsoli użytkownika i sprawdźmy uprawnienia**:
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
Teraz przypiszmy plikowi minimalny poziom integralności **Wysoki**. **Musimy to zrobić z konsoli** uruchomionej jako **administrator**, ponieważ **zwykła konsola** działa na poziomie integralności Średni i **nie będzie miała uprawnień** do przypisania poziomu integralności Wysoki obiektowi:
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
To jest moment, w którym sprawy stają się interesujące. Można zauważyć, że użytkownik `DESKTOP-IDJHTKP\user` ma **PEŁNE uprawnienia** do pliku (faktycznie to ten użytkownik utworzył plik), jednak z powodu zastosowanego minimalnego poziomu integralności nie będzie już mógł go modyfikować, chyba że działa w ramach wysokiego poziomu integralności (należy zauważyć, że nadal będzie mógł go czytać):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Dlatego, gdy plik ma minimalny poziom integralności, aby go zmodyfikować, musisz działać co najmniej na tym poziomie integralności.**
{% endhint %}

## Poziomy integralności w plikach binarnych

Utworzyłem kopię `cmd.exe` w `C:\Windows\System32\cmd-low.exe` i ustawiłem mu **poziom integralności na niski z konsoli administratora:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Teraz, gdy uruchamiam `cmd-low.exe`, będzie **działać na poziomie niskiej integralności** zamiast średniej:

![](<../../.gitbook/assets/image (320).png>)

Dla ciekawych osób, jeśli przypiszesz wysoki poziom integralności do pliku binarnego (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), nie będzie on automatycznie uruchamiany z wysokim poziomem integralności (jeśli wywołasz go z poziomu średniej integralności - domyślnie - będzie działał na poziomie średniej integralności).

## Poziomy Integralności w Procesach

Nie wszystkie pliki i foldery mają minimalny poziom integralności, **ale wszystkie procesy działają na określonym poziomie integralności**. Podobnie jak w przypadku systemu plików, **jeśli proces chce zapisywać w innym procesie, musi mieć co najmniej ten sam poziom integralności**. Oznacza to, że proces o niskim poziomie integralności nie może otworzyć uchwytu z pełnym dostępem do procesu o średnim poziomie integralności.

Ze względu na ograniczenia omówione w tej i poprzedniej sekcji, z punktu widzenia bezpieczeństwa zawsze **zaleca się uruchamianie procesu na jak najniższym poziomie integralności**.


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
