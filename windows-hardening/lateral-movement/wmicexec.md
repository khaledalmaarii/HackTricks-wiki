# WmicExec

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Jak to działa - wyjaśnienie

Procesy mogą być uruchamiane na hostach, gdzie znane są nazwa użytkownika oraz hasło lub skrót za pomocą WMI. Polecenia są wykonywane za pomocą WMI przez Wmiexec, zapewniając pół-interaktywne doświadczenie powłoki.

**dcomexec.py:** Korzystając z różnych punktów końcowych DCOM, ten skrypt oferuje pół-interaktywną powłokę podobną do wmiexec.py, wykorzystując specjalnie obiekt DCOM ShellBrowserWindow. Obecnie obsługuje aplikację MMC20, okna powłoki i obiekty okna przeglądarki powłoki. (źródło: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Podstawy WMI

### Przestrzeń nazwowa

Zorganizowana w hierarchii stylu katalogu, głównym kontenerem WMI jest \root, pod którym zorganizowane są dodatkowe katalogi, zwane przestrzeniami nazw.
Polecenia do listowania przestrzeni nazw:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Klasy w obrębie przestrzeni nazw można wymienić za pomocą:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Klasy**

Znajomość nazwy klasy WMI, takiej jak win32\_process, oraz przestrzeni nazw, w której się znajduje, jest kluczowa dla każdej operacji WMI.
Polecenia do wylistowania klas zaczynających się od `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Wywołanie klasy:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Metody

Metody, które są jedną lub więcej wykonywalnych funkcji klas WMI, mogą być uruchamiane.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## Wyliczanie WMI

### Status usługi WMI

Polecenia do sprawdzenia, czy usługa WMI działa poprawnie:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Informacje o systemie i procesach

Zbieranie informacji o systemie i procesach za pomocą WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Dla atakujących WMI jest potężnym narzędziem do wyliczania wrażliwych danych o systemach lub domenach.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
### **Ręczne zdalne zapytania WMI**

Skryte zidentyfikowanie lokalnych administratorów na zdalnej maszynie oraz zalogowanych użytkowników można osiągnąć poprzez konkretne zapytania WMI. `wmic` obsługuje również odczytywanie z pliku tekstowego w celu wykonania poleceń na wielu węzłach jednocześnie.

Aby zdalnie wykonać proces za pomocą WMI, na przykład wdrożyć agenta Empire, stosuje się następującą strukturę polecenia, a udane wykonanie jest wskazywane przez wartość zwrotną "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Ten proces ilustruje zdolności WMI do zdalnego wykonywania poleceń i wyliczania systemu, podkreślając jego użyteczność zarówno dla administracji systemem, jak i testów penetracyjnych.


## Referencje
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Narzędzia automatyczne

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
