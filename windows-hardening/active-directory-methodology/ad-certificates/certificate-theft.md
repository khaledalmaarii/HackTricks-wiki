# AD CS Certificate Theft

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**이것은 [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)에서의 훌륭한 연구의 도난 장에 대한 간단한 요약입니다.**

## What can I do with a certificate

인증서를 훔치는 방법을 확인하기 전에 인증서가 무엇에 유용한지 찾는 방법에 대한 정보가 있습니다:
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Exporting Certificates Using the Crypto APIs – THEFT1

**인터랙티브 데스크탑 세션**에서 사용자 또는 머신 인증서와 개인 키를 추출하는 것은 **개인 키가 내보낼 수 있는 경우** 특히 쉽게 수행할 수 있습니다. 이는 `certmgr.msc`에서 인증서를 찾아 마우스 오른쪽 버튼을 클릭하고 `모든 작업 → 내보내기`를 선택하여 비밀번호로 보호된 .pfx 파일을 생성함으로써 달성할 수 있습니다.

**프로그래밍 방식 접근법**으로는 PowerShell `ExportPfxCertificate` cmdlet 또는 [TheWover의 CertStealer C# 프로젝트](https://github.com/TheWover/CertStealer)와 같은 도구가 있습니다. 이들은 **Microsoft CryptoAPI** (CAPI) 또는 Cryptography API: Next Generation (CNG)을 사용하여 인증서 저장소와 상호작용합니다. 이러한 API는 인증서 저장 및 인증에 필요한 다양한 암호화 서비스를 제공합니다.

그러나 개인 키가 내보낼 수 없는 것으로 설정된 경우, CAPI와 CNG는 일반적으로 이러한 인증서의 추출을 차단합니다. 이 제한을 우회하기 위해 **Mimikatz**와 같은 도구를 사용할 수 있습니다. Mimikatz는 개인 키의 내보내기를 허용하기 위해 해당 API를 패치하는 `crypto::capi` 및 `crypto::cng` 명령을 제공합니다. 구체적으로, `crypto::capi`는 현재 프로세스 내의 CAPI를 패치하고, `crypto::cng`는 패치를 위해 **lsass.exe**의 메모리를 타겟으로 합니다.

## User Certificate Theft via DPAPI – THEFT2

DPAPI에 대한 더 많은 정보는 다음에서 확인할 수 있습니다:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windows에서 **인증서 개인 키는 DPAPI에 의해 보호됩니다**. **사용자 및 머신 개인 키의 저장 위치**가 다르며, 파일 구조는 운영 체제가 사용하는 암호화 API에 따라 다르다는 점을 인식하는 것이 중요합니다. **SharpDPAPI**는 DPAPI 블롭을 해독할 때 이러한 차이를 자동으로 탐색할 수 있는 도구입니다.

**사용자 인증서**는 주로 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`의 레지스트리에 저장되지만, 일부는 `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` 디렉토리에서도 찾을 수 있습니다. 이러한 인증서에 대한 해당 **개인 키**는 일반적으로 **CAPI** 키의 경우 `%APPDATA%\Microsoft\Crypto\RSA\User SID\`에, **CNG** 키의 경우 `%APPDATA%\Microsoft\Crypto\Keys\`에 저장됩니다.

**인증서와 관련된 개인 키를 추출하기 위해** 과정은 다음과 같습니다:

1. **사용자의 저장소에서 대상 인증서를 선택하고** 해당 키 저장소 이름을 검색합니다.
2. **해당 개인 키를 해독하기 위해 필요한 DPAPI 마스터 키를 찾습니다.**
3. **평문 DPAPI 마스터 키를 사용하여 개인 키를 해독합니다.**

**평문 DPAPI 마스터 키를 획득하기 위해** 다음 접근 방식을 사용할 수 있습니다:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
마스터키 파일과 개인 키 파일의 복호화를 간소화하기 위해, [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)의 `certificates` 명령이 유용합니다. 이 명령은 개인 키와 연결된 인증서를 복호화하기 위해 `/pvk`, `/mkfile`, `/password` 또는 `{GUID}:KEY`를 인수로 받아들여, 이후 `.pem` 파일을 생성합니다.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Machine Certificate Theft via DPAPI – THEFT3

Windows에 의해 레지스트리에 저장된 머신 인증서 `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates`와 관련된 개인 키는 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI의 경우) 및 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG의 경우)에 위치하며, 머신의 DPAPI 마스터 키를 사용하여 암호화됩니다. 이러한 키는 도메인의 DPAPI 백업 키로 복호화할 수 없으며, 대신 **DPAPI_SYSTEM LSA 비밀**이 필요합니다. 이 비밀은 오직 SYSTEM 사용자만 접근할 수 있습니다.

수동 복호화는 **Mimikatz**에서 `lsadump::secrets` 명령을 실행하여 DPAPI_SYSTEM LSA 비밀을 추출한 다음, 이 키를 사용하여 머신 마스터 키를 복호화함으로써 달성할 수 있습니다. 또는, 이전에 설명한 대로 CAPI/CNG를 패치한 후 Mimikatz의 `crypto::certificates /export /systemstore:LOCAL_MACHINE` 명령을 사용할 수 있습니다.

**SharpDPAPI**는 인증서 명령을 통해 보다 자동화된 접근 방식을 제공합니다. `/machine` 플래그가 상승된 권한으로 사용될 때, SYSTEM으로 상승하고 DPAPI_SYSTEM LSA 비밀을 덤프한 후, 이를 사용하여 머신 DPAPI 마스터 키를 복호화하고, 이러한 평문 키를 조회 테이블로 사용하여 모든 머신 인증서 개인 키를 복호화합니다.


## Finding Certificate Files – THEFT4

인증서는 때때로 파일 시스템 내에서 직접 발견되며, 파일 공유 또는 다운로드 폴더와 같은 위치에 있습니다. Windows 환경을 대상으로 하는 가장 일반적으로 접하는 인증서 파일 유형은 `.pfx` 및 `.p12` 파일입니다. 덜 자주 나타나는 파일 확장자로는 `.pkcs12` 및 `.pem`이 있습니다. 추가로 주목할 만한 인증서 관련 파일 확장자는 다음과 같습니다:
- 개인 키용 `.key`,
- 인증서 전용 `.crt`/`.cer`,
- 인증서 또는 개인 키를 포함하지 않는 인증서 서명 요청용 `.csr`,
- Java 애플리케이션에서 사용되는 인증서와 개인 키를 포함할 수 있는 Java 키 저장소용 `.jks`/`.keystore`/`.keys`.

이 파일들은 언급된 확장자를 검색하여 PowerShell 또는 명령 프롬프트를 사용하여 찾을 수 있습니다.

PKCS#12 인증서 파일이 발견되고 비밀번호로 보호되는 경우, [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html)에서 사용할 수 있는 `pfx2john.py`를 통해 해시를 추출할 수 있습니다. 이후, JohnTheRipper를 사용하여 비밀번호를 크랙하려고 시도할 수 있습니다.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5

주어진 내용은 PKINIT를 통한 NTLM 자격 증명 도용 방법, 특히 THEFT5로 레이블이 붙은 도용 방법을 설명합니다. 다음은 수동태로 재설명하며, 내용이 익명화되고 요약된 것입니다:

Kerberos 인증을 지원하지 않는 애플리케이션을 위해 NTLM 인증 [MS-NLMP]을 지원하기 위해, KDC는 PKCA가 사용될 때 권한 속성 인증서(PAC) 내에서 사용자의 NTLM 일방향 함수(OWF)를 반환하도록 설계되었습니다. 따라서 계정이 PKINIT를 통해 인증하고 티켓 부여 티켓(TGT)을 확보할 경우, 현재 호스트가 TGT에서 NTLM 해시를 추출하여 레거시 인증 프로토콜을 유지할 수 있도록 하는 메커니즘이 본질적으로 제공됩니다. 이 과정은 NTLM 평문을 NDR 직렬화된 형태로 나타내는 `PAC_CREDENTIAL_DATA` 구조체의 복호화를 포함합니다.

유틸리티 **Kekeo**는 [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo)에서 접근할 수 있으며, 이 특정 데이터를 포함하는 TGT를 요청할 수 있는 기능이 있다고 언급됩니다. 이를 위한 명령은 다음과 같습니다:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
또한, Kekeo는 pin을 검색할 수 있는 경우 스마트카드 보호 인증서를 처리할 수 있다고 언급되며, [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe)와 관련이 있습니다. 동일한 기능이 **Rubeus**에서도 지원된다고 하며, 이는 [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)에서 사용할 수 있습니다.

이 설명은 PKINIT을 통한 NTLM 자격 증명 도용 과정과 관련 도구를 요약하며, PKINIT을 사용하여 얻은 TGT를 통해 NTLM 해시를 검색하는 데 중점을 두고, 이 과정을 용이하게 하는 유틸리티를 다룹니다.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
