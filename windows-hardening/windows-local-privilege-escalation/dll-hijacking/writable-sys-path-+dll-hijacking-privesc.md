# 쓰기 가능한 Sys 경로 + Dll Hijacking Privesc

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 소개

**시스템 경로 폴더에 쓸 수 있다**는 것을 발견했다면 (사용자 경로 폴더에 쓸 수 있는 경우는 작동하지 않음), 시스템에서 **권한 상승**이 가능할 수 있습니다.

이를 위해 권한이 더 많은 서비스 또는 프로세스가 로드하는 라이브러리를 **Dll Hijacking**으로 악용할 수 있습니다. 이 서비스는 시스템 전체에 실제로 존재하지 않을 수도 있는 Dll을 시스템 경로에서 로드하려고 시도할 것입니다.

**Dll Hijacking이란 무엇인지**에 대한 자세한 정보는 다음을 확인하세요:

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## Dll Hijacking을 사용한 권한 상승

### 누락된 Dll 찾기

먼저, **당신보다 더 많은 권한으로 실행되는 프로세스**를 식별해야 합니다. 이 프로세스는 **시스템 경로**에서 Dll을 로드하려고 시도할 것입니다.

이러한 경우에는 이미 실행 중인 프로세스일 가능성이 높습니다. 필요한 서비스에서 누락된 Dll을 찾으려면 프로세스가 로드되기 전에 procmon을 가능한 한 빨리 실행해야 합니다. 따라서 다음을 수행하여 누락된 .dll을 찾을 수 있습니다:

* `C:\privesc_hijacking` 폴더를 **생성**하고 **시스템 경로 환경 변수**에 `C:\privesc_hijacking` 경로를 추가합니다. 이 작업은 **수동으로** 또는 **PS**를 사용하여 수행할 수 있습니다:
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
* **`procmon`**을 실행하고 **`Options`** --> **`Enable boot logging`**으로 이동한 다음, 나타나는 프롬프트에서 **`OK`**를 누릅니다.
* 그런 다음, **재부팅**합니다. 컴퓨터가 재시작되면 **`procmon`**이 가능한 한 빨리 이벤트를 기록하기 시작합니다.
* **Windows**가 **시작되면 `procmon`**을 다시 실행하고, 실행 중이었다는 메시지가 표시되며 이벤트를 파일에 저장할지 묻습니다. **예**를 선택하고 이벤트를 파일에 저장합니다.
* **파일**이 **생성된 후**, 열려 있는 **`procmon`** 창을 닫고 이벤트 파일을 엽니다.
* 다음 **필터**를 추가하면 쓰기 가능한 시스템 경로 폴더에서 로드를 시도한 모든 DLL을 찾을 수 있습니다:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### 누락된 DLL

저는 무료 **가상 (vmware) Windows 11 머신**에서 이를 실행한 결과 다음과 같은 결과를 얻었습니다:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

이 경우 .exe 파일은 사용하지 않으므로 무시하고, 누락된 DLL은 다음과 같습니다:

| 서비스                         | DLL                | CMD 라인                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| 작업 스케줄러 (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| 진단 정책 서비스 (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

이를 발견한 후에는 [**WptsExtensions.dll을 악용하여 권한 상승**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll)하는 방법을 설명하는 흥미로운 블로그 게시물을 찾았습니다. 이제 우리가 할 일입니다.

### 공격

따라서, 권한 상승을 위해 라이브러리 **WptsExtensions.dll**을 하이재킹할 것입니다. **경로**와 **이름**을 가지고 있으므로 악성 DLL을 **생성**하기만 하면 됩니다.

[**이 예제 중 하나를 사용**](../dll-hijacking.md#creating-and-compiling-dlls)해보세요. 리버스 쉘을 실행하거나 사용자를 추가하거나 비콘을 실행할 수 있습니다...

{% hint style="warning" %}
모든 서비스가 **`NT AUTHORITY\SYSTEM`**으로 실행되는 것은 아니므로 주의하세요. 일부 서비스는 **`NT AUTHORITY\LOCAL SERVICE`**로 실행되며 권한이 더 낮으므로 새 사용자를 생성할 수 없습니다.\
그러나 해당 사용자에는 **`seImpersonate`** 권한이 있으므로 [**potato suite를 사용하여 권한 상승**](../roguepotato-and-printspoofer.md)할 수 있습니다. 따라서 이 경우에는 리버스 쉘이 사용자를 생성하는 것보다 좋은 옵션입니다.
{% endhint %}

현재 **작업 스케줄러** 서비스는 **Nt AUTHORITY\SYSTEM**으로 실행됩니다.

악성 DLL을 **생성**한 후 (저는 x64 리버스 쉘을 사용하고 msfvenom에서 생성한 DLL이 Defender에 의해 제거되었습니다), 쓰기 가능한 시스템 경로에 **WptsExtensions.dll**이라는 이름으로 저장하고 컴퓨터를 **재시작**합니다 (또는 서비스를 재시작하거나 해당 서비스/프로그램을 다시 실행하는 데 필요한 작업을 수행합니다).

서비스가 다시 시작되면 **dll이 로드되고 실행**됩니다 (라이브러리가 예상대로 로드되었는지 확인하기 위해 **procmon** 트릭을 재사용할 수 있습니다).

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고**하거나 **PDF로 HackTricks를 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 트릭을 공유**하세요.

</details>
