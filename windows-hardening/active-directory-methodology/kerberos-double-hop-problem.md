# Problem podwójnego skoku Kerberos

<details>

<summary><strong>Nauka hakerskiego AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć **reklamę swojej firmy na HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Wprowadzenie

Problem "podwójnego skoku" Kerberos pojawia się, gdy atakujący próbuje użyć **uwierzytelnienia Kerberos w dwóch** **skokach**, na przykład za pomocą **PowerShell**/**WinRM**.

Gdy **uwierzytelnienie** zachodzi za pomocą **Kerberos**, **poświadczenia** **nie są** przechowywane w **pamięci**. Dlatego jeśli uruchomisz mimikatz, **nie znajdziesz poświadczeń** użytkownika na maszynie, nawet jeśli uruchamia procesy.

Dzieje się tak, ponieważ podczas łączenia się za pomocą Kerberos zachodzą następujące kroki:

1. Użytkownik1 podaje poświadczenia, a **kontroler domeny** zwraca użytkownikowi1 **TGT** Kerberos.
2. Użytkownik1 używa **TGT** do żądania **biletu usługi** w celu **połączenia** z Serwerem1.
3. Użytkownik1 **łączy się** z **Serwerem1** i dostarcza **bilet usługi**.
4. **Serwer1** **nie ma** **przechowywanych poświadczeń** użytkownika1 ani **TGT** użytkownika1. Dlatego gdy Użytkownik1 z Serwera1 próbuje zalogować się na drugi serwer, nie jest **w stanie się uwierzytelnić**.

### Nieograniczone przekazywanie

Jeśli jest włączone **nieograniczone przekazywanie** na PC, to nie wystąpi ten problem, ponieważ **Serwer** otrzyma **TGT** każdego użytkownika, który się do niego łączy. Ponadto, jeśli jest używane nieograniczone przekazywanie, prawdopodobnie można **skompromitować kontroler domeny** z niego.\
[**Więcej informacji na stronie dotyczącej nieograniczonego przekazywania**](unconstrained-delegation.md).

### CredSSP

Innym sposobem uniknięcia tego problemu, który jest [**zauważalnie niebezpieczny**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), jest **Dostawca Obsługi Bezpieczeństwa Poświadczeń**. Według Microsoftu:

> Uwierzytelnianie CredSSP przekazuje poświadczenia użytkownika z komputera lokalnego do zdalnego komputera. Ta praktyka zwiększa ryzyko bezpieczeństwa operacji zdalnych. Jeśli zdalny komputer zostanie skompromitowany, gdy poświadczenia zostaną do niego przekazane, poświadczenia mogą być użyte do kontrolowania sesji sieciowej.

Zaleca się wyłączenie **CredSSP** na systemach produkcyjnych, wrażliwych sieciach i podobnych środowiskach ze względów bezpieczeństwa. Aby sprawdzić, czy **CredSSP** jest włączone, można uruchomić polecenie `Get-WSManCredSSP`. Polecenie to pozwala na **sprawdzenie stanu CredSSP** i może być nawet wykonane zdalnie, o ile jest włączone **WinRM**.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Metody obejścia

### Wywołanie polecenia

Aby rozwiązać problem podwójnego skoku, przedstawiona jest metoda wykorzystująca zagnieżdżone polecenie `Invoke-Command`. Nie rozwiązuje to problemu bezpośrednio, ale oferuje obejście bez konieczności stosowania specjalnych konfiguracji. Podejście to pozwala na wykonanie polecenia (`hostname`) na drugim serwerze za pomocą polecenia PowerShell wykonanego z początkowego atakującego komputera lub poprzez wcześniej ustanowioną sesję PS-Session z pierwszym serwerem. Oto jak to się robi:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatywnie, ustanowienie sesji PS z pierwszym serwerem i uruchomienie polecenia `Invoke-Command` przy użyciu `$cred` jest sugerowane do scentralizowania zadań.

### Zarejestruj konfigurację sesji PS

Rozwiązaniem umożliwiającym obejście problemu podwójnego skoku jest użycie `Register-PSSessionConfiguration` z `Enter-PSSession`. Ta metoda wymaga innego podejścia niż `evil-winrm` i pozwala na sesję, która nie cierpi z powodu ograniczenia podwójnego skoku.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### Przekierowywanie portów

Dla administratorów lokalnych na docelowym pośrednim serwerze, przekierowywanie portów pozwala na przesyłanie żądań do ostatecznego serwera. Korzystając z `netsh`, można dodać regułę przekierowywania portów, wraz z regułą zapory systemu Windows, aby zezwolić na przekierowany port.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` może być używany do przekazywania żądań WinRM, potencjalnie jako mniej wykrywalna opcja, jeśli obawiasz się monitorowania PowerShell. Poniższe polecenie demonstruje jego użycie:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Instalowanie OpenSSH na pierwszym serwerze umożliwia obejście problemu podwójnego skoku, szczególnie przydatne w scenariuszach skrzynki skokowej. Ta metoda wymaga instalacji wiersza poleceń i konfiguracji OpenSSH dla systemu Windows. Po skonfigurowaniu uwierzytelniania hasłem, pozwala to serwerowi pośredniemu na uzyskanie TGT w imieniu użytkownika.

#### Kroki instalacji OpenSSH

1. Pobierz i przenieś najnowszy plik zip z wydaniem OpenSSH na serwer docelowy.
2. Rozpakuj i uruchom skrypt `Install-sshd.ps1`.
3. Dodaj regułę zapory sieciowej, aby otworzyć port 22 i sprawdź, czy usługi SSH są uruchomione.

Aby rozwiązać błędy `Connection reset`, uprawnienia mogą wymagać aktualizacji, aby umożliwić wszystkim odczyt i wykonanie dostępu do katalogu OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Odnośniki

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? lub chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
