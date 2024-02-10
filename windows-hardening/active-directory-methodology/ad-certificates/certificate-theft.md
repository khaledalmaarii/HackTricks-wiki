# AD CS 인증서 도난

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

**이것은 [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)의 멋진 연구의 도난 장에 대한 작은 요약입니다.**


## 인증서로 무엇을 할 수 있을까요

인증서를 도난하는 방법을 확인하기 전에 인증서가 어떤 용도로 사용되는지에 대한 정보를 제공합니다:
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
## Crypto API를 사용하여 인증서 추출 - THEFT1

**대화형 데스크톱 세션**에서는 사용자 또는 기계 인증서와 개인 키를 추출하는 것이 쉽게 가능하며, 특히 **개인 키가 내보낼 수 있는 경우**에는 더욱 쉽게 할 수 있습니다. 이를 위해서는 `certmgr.msc`에서 인증서로 이동한 다음, 해당 인증서를 마우스 오른쪽 버튼으로 클릭하고 `모든 작업 → 내보내기`를 선택하여 암호로 보호된 .pfx 파일을 생성하면 됩니다.

**프로그래밍 방식**으로는 PowerShell의 `ExportPfxCertificate` cmdlet 또는 [TheWover의 CertStealer C# 프로젝트](https://github.com/TheWover/CertStealer)와 같은 도구를 사용할 수 있습니다. 이러한 도구는 **Microsoft CryptoAPI** (CAPI) 또는 Cryptography API: Next Generation (CNG)을 사용하여 인증서 저장소와 인증에 필요한 암호화 서비스를 제공하는 API와 상호 작용합니다.

그러나 개인 키가 내보낼 수 없도록 설정된 경우, CAPI와 CNG는 일반적으로 해당 인증서의 추출을 차단합니다. 이러한 제한을 우회하기 위해 **Mimikatz**와 같은 도구를 사용할 수 있습니다. Mimikatz는 `crypto::capi` 및 `crypto::cng` 명령을 제공하여 해당 API를 패치하여 개인 키를 내보낼 수 있도록 합니다. 특히, `crypto::capi`는 현재 프로세스 내의 CAPI를 패치하고, `crypto::cng`는 패치하기 위해 **lsass.exe**의 메모리를 대상으로 합니다.

## DPAPI를 통한 사용자 인증서 도난 - THEFT2

DPAPI에 대한 자세한 정보는 다음에서 확인할 수 있습니다:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windows에서는 **인증서 개인 키는 DPAPI로 보호**됩니다. 사용자 및 기계 개인 키의 **저장 위치**는 다르며, 파일 구조는 운영 체제에서 사용하는 암호화 API에 따라 다릅니다. **SharpDPAPI**는 DPAPI 블롭을 해독할 때 이러한 차이를 자동으로 탐색할 수 있는 도구입니다.

**사용자 인증서**는 주로 레지스트리의 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`에 저장되지만, 일부 인증서는 `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` 디렉토리에서도 찾을 수 있습니다. 이러한 인증서에 해당하는 **개인 키**는 일반적으로 **CAPI** 키의 경우 `%APPDATA%\Microsoft\Crypto\RSA\User SID\`에 저장되고, **CNG** 키의 경우 `%APPDATA%\Microsoft\Crypto\Keys\`에 저장됩니다.

인증서와 해당하는 개인 키를 **추출**하기 위한 과정은 다음과 같습니다:

1. 사용자 저장소에서 **대상 인증서를 선택**하고 해당 키 저장소 이름을 검색합니다.
2. 해당하는 개인 키를 복호화하기 위해 필요한 **DPAPI 마스터 키를 찾습니다**.
3. 평문 DPAPI 마스터 키를 사용하여 개인 키를 **복호화**합니다.

평문 DPAPI 마스터 키를 **획득**하기 위해 다음 접근 방식을 사용할 수 있습니다:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
마스터키 파일과 개인 키 파일의 복호화를 간소화하기 위해 [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)의 `certificates` 명령이 유용합니다. 이 명령은 `/pvk`, `/mkfile`, `/password` 또는 `{GUID}:KEY`를 인수로 받아 개인 키와 연결된 인증서를 복호화하고 `.pem` 파일을 생성합니다.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## DPAPI를 통한 기계 인증서 도난 - THEFT3

Windows에서는 레지스트리의 `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates`에 기계 인증서를 저장하고, 관련된 개인 키는 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI용) 및 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG용)에 저장합니다. 이러한 키는 기계의 DPAPI 마스터 키를 사용하여 암호화됩니다. 이러한 키는 도메인의 DPAPI 백업 키로 복호화할 수 없으며, 대신 SYSTEM 사용자만 액세스할 수 있는 **DPAPI_SYSTEM LSA 비밀**이 필요합니다.

수동 복호화는 **Mimikatz**에서 `lsadump::secrets` 명령을 실행하여 DPAPI_SYSTEM LSA 비밀을 추출한 다음, 이 키를 사용하여 기계 마스터 키를 복호화함으로써 수행할 수 있습니다. 또는 이전에 설명한대로 CAPI/CNG를 패치한 후 Mimikatz의 `crypto::certificates /export /systemstore:LOCAL_MACHINE` 명령을 사용할 수도 있습니다.

**SharpDPAPI**는 certificates 명령을 사용하여 더 자동화된 접근 방식을 제공합니다. 관리자 권한으로 `/machine` 플래그를 사용하면 SYSTEM으로 승격하여 DPAPI_SYSTEM LSA 비밀을 덤프하고, 이를 사용하여 기계 DPAPI 마스터 키를 복호화한 다음, 이 평문 키를 사용하여 기계 인증서 개인 키를 복호화하는 룩업 테이블로 사용합니다.


## 인증서 파일 찾기 - THEFT4

인증서는 때때로 파일 시스템 내에서 직접 찾을 수 있습니다. 예를 들어 파일 공유나 다운로드 폴더에 있을 수 있습니다. Windows 환경을 대상으로 하는 가장 일반적으로 사용되는 인증서 파일 유형은 `.pfx` 및 `.p12` 파일입니다. 덜 자주 사용되지만 `.pkcs12` 및 `.pem` 확장자를 가진 파일도 있습니다. 기타 주목할만한 인증서 관련 파일 확장자는 다음과 같습니다:
- 개인 키에 대한 `.key`,
- 인증서만을 위한 `.crt`/`.cer`,
- 인증서나 개인 키를 포함하지 않는 인증서 서명 요청인 `.csr`,
- Java 애플리케이션에서 사용되는 인증서와 개인 키를 보유할 수 있는 Java 키스토어인 `.jks`/`.keystore`/`.keys`.

이러한 파일은 PowerShell이나 명령 프롬프트를 사용하여 언급된 확장자를 찾아 검색할 수 있습니다.

PKCS#12 인증서 파일이 발견되고 비밀번호로 보호되어 있는 경우, `pfx2john.py`를 사용하여 해시를 추출할 수 있습니다. 이는 [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html)에서 사용할 수 있습니다. 그런 다음 JohnTheRipper를 사용하여 비밀번호를 크랙하는 시도를 할 수 있습니다.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## PKINIT을 통한 NTLM 자격 증명 도용 - THEFT5

주어진 내용은 PKINIT을 통한 NTLM 자격 증명 도용 방법, 특히 THEFT5로 레이블된 도용 방법에 대해 설명합니다. 다음은 내용을 수동태로 다시 설명하며, 필요한 경우 내용을 익명화하고 요약합니다:

Kerberos 인증을 지원하지 않는 응용 프로그램을 위해 NTLM 인증 [MS-NLMP]을 지원하기 위해 KDC는 PKCA를 사용할 때 특히 `PAC_CREDENTIAL_INFO` 버퍼 내에서 사용자의 NTLM 일방향 함수 (OWF)를 반환하도록 설계되었습니다. 따라서 계정이 PKINIT을 통해 인증하고 TGT (Ticket-Granting Ticket)를 안전하게 획득하는 경우, 현재 호스트는 NTLM 해시를 추출하여 레거시 인증 프로토콜을 유지할 수 있는 기능이 내재적으로 제공됩니다. 이 과정은 기본적으로 NTLM 평문의 NDR 직렬화 표현인 `PAC_CREDENTIAL_DATA` 구조체의 복호화를 수반합니다.

[https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo)에서 제공되는 유틸리티 **Kekeo**는 이 특정 데이터를 포함하는 TGT를 요청할 수 있는 기능을 갖추고 있다고 언급됩니다. 이를 위해 사용되는 명령은 다음과 같습니다:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
또한, Kekeo는 스마트카드로 보호된 인증서를 처리할 수 있으며, 핀을 검색할 수 있다는 사실이 언급되었다. 이에 관련하여 [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe)를 참조하라. 동일한 기능은 **Rubeus**에서도 지원된다고 알려져 있으며, [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)에서 사용할 수 있다.

이 설명은 PKINIT를 통한 NTLM 자격 증명 도용에 관련된 프로세스와 도구를 포함하고 있으며, PKINIT를 사용하여 얻은 TGT를 통해 NTLM 해시를 검색하는 것에 초점을 맞추고 이 과정을 용이하게 하는 유틸리티를 다루고 있다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왑**](https://peass.creator-spring.com)을 구매하세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **자신의 해킹 기법을 공유**하세요.

</details>
