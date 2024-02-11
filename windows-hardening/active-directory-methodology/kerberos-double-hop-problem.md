# Problem podwójnego skoku Kerberos

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**repozytorium hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**repozytorium hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Wprowadzenie

Problem "podwójnego skoku" Kerberos występuje, gdy atakujący próbuje użyć uwierzytelniania **Kerberos** w dwóch **skokach**, na przykład za pomocą **PowerShell**/**WinRM**.

Podczas **uwierzytelniania** za pomocą **Kerberos**, **poświadczenia** **nie są** przechowywane w **pamięci** podręcznej. Dlatego, jeśli uruchomisz mimikatz, **nie znajdziesz poświadczeń** użytkownika na maszynie, nawet jeśli uruchamia procesy.

Dzieje się tak, ponieważ podczas łączenia się za pomocą Kerberos zachodzą następujące kroki:

1. Użytkownik 1 podaje poświadczenia, a **kontroler domeny** zwraca użytkownikowi 1 **TGT** Kerberos.
2. Użytkownik 1 używa **TGT**, aby poprosić o **bilet usługi** w celu **połączenia** z Serwerem 1.
3. Użytkownik 1 **łączy się** z **Serwerem 1** i podaje **bilet usługi**.
4. **Serwer 1** nie ma **poświadczeń** użytkownika 1 w pamięci podręcznej ani **TGT** użytkownika 1. Dlatego, gdy użytkownik 1 z Serwera 1 próbuje zalogować się na drugi serwer, nie jest **w stanie się uwierzytelnić**.

### Nieograniczone przekazywanie

Jeśli **nieograniczone przekazywanie** jest włączone na komputerze, to się nie zdarzy, ponieważ **Serwer** otrzyma **TGT** każdego użytkownika, który się do niego łączy. Ponadto, jeśli używane jest nieograniczone przekazywanie, prawdopodobnie można **skompromitować kontroler domeny**.\
[**Więcej informacji na stronie dotyczącej nieograniczonego przekazywania**](unconstrained-delegation.md).

### CredSSP

Innym sposobem uniknięcia tego problemu, który jest [**znacznie niebezpieczny**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), jest **Credential Security Support Provider** (CredSSP). Według Microsoftu:

> Uwierzytelnianie CredSSP przekazuje poświadczenia użytkownika z komputera lokalnego do komputera zdalnego. Ta praktyka zwiększa ryzyko bezpieczeństwa operacji zdalnych. Jeśli zdalny komputer zostanie skompromitowany, po przekazaniu do niego poświadczeń, można ich użyć do kontrolowania sesji sieciowej.

Zaleca się wyłączenie **CredSSP** na systemach produkcyjnych, wrażliwych sieciach i podobnych środowiskach ze względów bezpieczeństwa. Aby sprawdzić, czy **CredSSP** jest włączone, można uruchomić polecenie `Get-WSManCredSSP`. Polecenie to pozwala na **sprawdzenie stanu CredSSP** i może być wykonane zdalnie, o ile jest włączony **WinRM**.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Rozwiązania tymczasowe

### Invoke Command

Aby rozwiązać problem podwójnego skoku, przedstawiona jest metoda wykorzystująca zagnieżdżone polecenie `Invoke-Command`. Nie rozwiązuje to problemu bezpośrednio, ale oferuje obejście bez konieczności specjalnej konfiguracji. Ta metoda umożliwia wykonanie polecenia (`hostname`) na drugim serwerze za pomocą polecenia PowerShell wykonanego z atakującego komputera lub poprzez wcześniej ustanowioną sesję PS z pierwszym serwerem. Oto jak to się robi:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatywnie, sugeruje się ustanowienie sesji PS z pierwszym serwerem i uruchomienie polecenia `Invoke-Command` przy użyciu `$cred` w celu scentralizowania zadań.

### Rejestrowanie konfiguracji sesji PSSession

Rozwiązaniem umożliwiającym obejście problemu podwójnego skoku jest użycie `Register-PSSessionConfiguration` z `Enter-PSSession`. Ta metoda wymaga innego podejścia niż `evil-winrm` i pozwala na sesję, która nie ma ograniczenia podwójnego skoku.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### Przekierowywanie portów

Dla lokalnych administratorów na pośrednim celu, przekierowywanie portów umożliwia wysyłanie żądań do ostatecznego serwera. Za pomocą polecenia `netsh` można dodać regułę przekierowywania portów, wraz z regułą zapory systemu Windows, która umożliwia przekierowanie portu.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` może być używane do przekazywania żądań WinRM, potencjalnie jako mniej wykrywalna opcja, jeśli obawiasz się monitorowania PowerShell. Poniższa komenda demonstruje jego użycie:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Instalowanie OpenSSH na pierwszym serwerze umożliwia obejście problemu podwójnego skoku, co jest szczególnie przydatne w scenariuszach z użyciem skrzynki pośredniczącej. Ta metoda wymaga instalacji i konfiguracji OpenSSH dla systemu Windows za pomocą wiersza poleceń. Po skonfigurowaniu uwierzytelniania hasłem, umożliwia to serwerowi pośredniczącemu uzyskanie TGT w imieniu użytkownika.

#### Kroki instalacji OpenSSH

1. Pobierz najnowsze wydanie OpenSSH w formacie zip i przenieś je na docelowy serwer.
2. Rozpakuj i uruchom skrypt `Install-sshd.ps1`.
3. Dodaj regułę zapory sieciowej, aby otworzyć port 22 i sprawdź, czy usługi SSH są uruchomione.

Aby rozwiązać błędy `Connection reset`, może być konieczne zaktualizowanie uprawnień, aby umożliwić wszystkim odczyt i wykonanie w katalogu OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Odnośniki

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną na HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do repozytorium** [**hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
