# BloodHound 및 기타 AD 열거 도구

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks) 및 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)는 Sysinternal Suite에서 제공하는 도구입니다:

> 고급 Active Directory (AD) 뷰어 및 편집기입니다. AD Explorer를 사용하여 AD 데이터베이스를 쉽게 탐색하고 즐겨찾기 위치를 정의하고 대화 상자를 열지 않고 개체 속성 및 속성을 볼 수 있으며 권한을 편집하고 개체 스키마를 보고 저장하고 다시 실행할 수 있는 정교한 검색을 실행할 수 있습니다.

### 스냅샷

AD Explorer를 사용하여 AD의 스냅샷을 생성하여 오프라인에서 확인할 수 있습니다.\
이를 사용하여 오프라인에서 취약점을 발견하거나 AD DB의 다른 상태를 비교할 수 있습니다.

사용자 이름, 비밀번호 및 연결 방향이 필요합니다 (AD 사용자는 필수입니다).

AD의 스냅샷을 찍으려면 `File` --> `Create Snapshot`으로 이동하고 스냅샷에 이름을 입력하세요.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon)은 AD 환경에서 다양한 아티팩트를 추출하고 결합하는 도구입니다. 정보는 **특별히 포맷된** Microsoft Excel **보고서**에 제공되며, 분석을 용이하게 하고 대상 AD 환경의 현재 상태를 전체적으로 파악할 수 있는 메트릭과 요약 뷰를 포함합니다.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

[https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)에서 가져온 내용입니다.

> BloodHound는 [Linkurious](http://linkurio.us/)를 기반으로 한 페이지의 자바스크립트 웹 애플리케이션으로, [Electron](http://electron.atom.io/)으로 컴파일되며, C# 데이터 수집기로 구성된 Neo4j 데이터베이스를 사용합니다.

BloodHound는 그래프 이론을 사용하여 Active Directory 또는 Azure 환경 내에서 숨겨진 그리고 종종 의도하지 않은 관계를 드러냅니다. 공격자는 BloodHound를 사용하여 일반적으로 빠르게 식별하기 어려운 매우 복잡한 공격 경로를 쉽게 식별할 수 있습니다. 방어자는 BloodHound를 사용하여 해당 공격 경로를 식별하고 제거할 수 있습니다. 블루 팀과 레드 팀 모두 BloodHound를 사용하여 Active Directory 또는 Azure 환경에서 권한 관계에 대한 깊은 이해를 쉽게 얻을 수 있습니다.

따라서, [Bloodhound](https://github.com/BloodHoundAD/BloodHound)는 도메인을 자동으로 열거하고 모든 정보를 저장하며, 가능한 권한 상승 경로를 찾고 그래프를 사용하여 모든 정보를 표시할 수 있는 놀라운 도구입니다.

Bloodhound는 **인게스터(ingestors)**와 **시각화 애플리케이션(visualisation application)** 두 가지 주요 구성 요소로 구성됩니다.

**인게스터(ingestors)**는 도메인을 열거하고 모든 정보를 추출하기 위해 사용됩니다. 추출된 정보는 시각화 애플리케이션이 이해할 수 있는 형식으로 저장됩니다.

**시각화 애플리케이션(visualisation application)**은 neo4j를 사용하여 정보 간의 관계를 보여주고 도메인 내에서 권한 상승을 위한 다양한 방법을 보여줍니다.

### 설치
BloodHound CE가 생성된 후, 전체 프로젝트는 사용 편의성을 위해 Docker와 함께 업데이트되었습니다. 가장 쉬운 방법은 미리 구성된 Docker Compose 구성을 사용하는 것입니다.

1. Docker Compose를 설치합니다. 이는 [Docker Desktop](https://www.docker.com/products/docker-desktop/) 설치에 포함되어 있어야 합니다.
2. 다음을 실행합니다:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Docker Compose의 터미널 출력에서 무작위로 생성된 비밀번호를 찾으세요.
4. 브라우저에서 http://localhost:8080/ui/login으로 이동하세요. admin 사용자 이름과 로그에서 무작위로 생성된 비밀번호로 로그인하세요.

이후에는 무작위로 생성된 비밀번호를 변경해야 하며, 새로운 인터페이스를 사용할 수 있게 됩니다. 이 인터페이스에서 직접 인젝터를 다운로드할 수 있습니다.

### SharpHound

여러 옵션이 있지만, 현재 도메인에 가입된 PC에서 현재 사용자로 SharpHound를 실행하고 모든 정보를 추출하려면 다음을 수행하세요:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> **CollectionMethod**에 대해 더 자세히 알아보고 세션 루프에 대해서는 [여기](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)에서 읽을 수 있습니다.

다른 자격 증명을 사용하여 SharpHound를 실행하려면 CMD netonly 세션을 생성하고 거기에서 SharpHound를 실행할 수 있습니다:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Bloodhound에 대해 더 알아보세요.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r)은 Active Directory와 관련된 **그룹 정책**에서 **취약점**을 찾는 도구입니다. \
도메인 내의 호스트에서 **어떤 도메인 사용자**를 사용하여 **group3r을 실행**해야 합니다.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/)은 AD 환경의 보안 상태를 평가하고 그래프와 함께 보고서를 제공합니다.

실행하려면 `PingCastle.exe` 바이너리를 실행하면 대화식 세션으로 시작되며 옵션 메뉴가 표시됩니다. 사용할 기본 옵션은 도메인의 기본 개요를 수립하고 구성 오류와 취약점을 찾는 **`healthcheck`**입니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹 배우기!</summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요. 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>
