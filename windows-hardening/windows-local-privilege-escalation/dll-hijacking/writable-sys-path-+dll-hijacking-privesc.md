# 쓰기 가능한 시스템 경로 + Dll 하이재킹 권한 상승

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로**부터 **히어로**까지 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 소개

**시스템 경로 폴더에 쓸 수 있다는 것을 발견**했다면 (사용자 경로 폴더에 쓸 수 있는 경우는 작동하지 않음) 시스템에서 **권한 상승**이 가능할 수 있습니다.

이를 위해 **더 높은 권한으로 실행 중인 서비스 또는 프로세스**가 **로드하려는 라이브러리를 하이재킹**할 수 있습니다. 그 서비스가 시스템 전체에 실제로 존재하지 않을 수도 있는 Dll을 로드하려고 시도할 것이며, 이 Dll을 쓸 수 있는 시스템 경로에서 로드하려고 할 것입니다.

**Dll 하이재킹이란 무엇인지**에 대한 자세한 정보는 다음을 확인하세요:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Dll 하이재킹을 사용한 권한 상승

### 누락된 Dll 찾기

먼저 **당신보다 더 높은 권한으로 실행 중인 프로세스**를 식별하고 **시스템 경로에 있는 Dll을 로드하려고 하는 프로세스**를 찾아야 합니다.

이러한 경우의 문제는 아마도 해당 프로세스가 이미 실행 중일 것이라는 것입니다. 필요한 서비스에 누락된 .dll을 찾으려면 프로세스가 로드되기 전에 procmon을 빨리 실행해야 합니다. 따라서 누락된 .dll을 찾으려면 다음을 수행하세요:

* `C:\privesc_hijacking` 폴더를 **생성**하고 해당 경로를 **시스템 경로 환경 변수**에 추가합니다. 이를 **수동**으로 하거나 **PS**로 수행하세요:
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
* **`procmon`**을 실행하고 **`Options`** --> **`Enable boot logging`**으로 이동한 후 **`OK`**을 누릅니다.
* 그런 다음 **시스템을 다시 시작**합니다. 컴퓨터가 다시 시작되면 **`procmon`**이 가능한 빨리 이벤트를 **기록**하기 시작합니다.
* **Windows**가 **시작되면 `procmon`을 실행**하고, 실행 중이었음을 알려주고 이벤트를 파일에 **저장할지 물어봅니다**. **예**를 선택하고 **이벤트를 파일에 저장**합니다.
* **파일**이 **생성된 후**, 열려 있는 **`procmon`** 창을 **닫고 이벤트 파일을 엽니다**.
* 다음 **필터**를 추가하면 쓰기 가능한 시스템 경로 폴더에서 **로드를 시도한 모든 Dlls**를 찾을 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (945).png" alt=""><figcaption></figcaption></figure>

### 누락된 Dlls

이 무료 **가상 (vmware) Windows 11 머신**에서 실행한 결과는 다음과 같습니다:

<figure><img src="../../../.gitbook/assets/image (607).png" alt=""><figcaption></figcaption></figure>

이 경우 .exe 파일은 쓸모가 없으므로 무시하고, 누락된 DLL은 다음과 같습니다:

| 서비스                         | Dll                | CMD 라인                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| 작업 스케줄러 (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| 진단 정책 서비스 (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

이를 발견한 후, [**WptsExtensions.dll을 악용하여 권한 상승**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll)하는 방법을 설명하는 흥미로운 블로그 게시물을 발견했습니다. 이제 **해볼 예정**입니다.

### 악용

따라서 권한을 **상승**하기 위해 라이브러리 **WptsExtensions.dll**을 탈취할 것입니다. **경로**와 **이름**을 가지고 있으면 악의적인 dll을 **생성**하기만 하면 됩니다.

[**다음 예제 중 하나를 사용**](./#creating-and-compiling-dlls)해 볼 수 있습니다. 리버스 쉘 가져오기, 사용자 추가, 비콘 실행 등의 페이로드를 실행할 수 있습니다...

{% hint style="warning" %}
**모든 서비스가** **`NT AUTHORITY\SYSTEM`**으로 실행되는 것은 아닙니다. 일부는 **`NT AUTHORITY\LOCAL SERVICE`**로 실행되며 권한이 **더 낮습니다**. 따라서 사용자를 만들 수 없습니다.\
그러나 해당 사용자에는 **`seImpersonate`** 권한이 있으므로 [**potato suite를 사용하여 권한을 상승**](../roguepotato-and-printspoofer.md)할 수 있습니다. 따라서 리버스 쉘을 만드는 것이 사용자를 만드는 것보다 나은 옵션입니다.
{% endhint %}

작성 시점에서 **작업 스케줄러** 서비스가 **Nt AUTHORITY\SYSTEM**으로 실행됩니다.

악의적인 Dll을 **생성한 후** (제 경우에는 x64 리버스 쉘을 사용하여 쉘을 받았지만, msfvenom에서 가져온 것이라서 디펜더가 죽였습니다), 이를 **WptsExtensions.dll**로 저장하고 **컴퓨터를 다시 시작**합니다 (또는 서비스를 다시 시작하거나 영향을 받는 서비스/프로그램을 다시 실행하는 데 필요한 작업을 수행합니다).

서비스가 다시 시작되면 **dll이 로드되고 실행**될 것입니다 (라이브러리가 예상대로 로드되었는지 확인하려면 **procmon** 트릭을 **재사용**할 수 있습니다).

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)로부터 AWS 해킹을 처음부터 전문가까지 배우세요</strong>!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* 독점 [**NFTs 컬렉션인 The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 팔로우하세요.
* 여러분의 해킹 트릭을 제출하여 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
