# 리눅스 환경 변수

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **해킹 트릭을 공유하려면 PR을 제출하여** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 기여하세요.

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## 전역 변수

전역 변수는 **자식 프로세스에게 상속**됩니다.

현재 세션에 대한 전역 변수를 만들려면 다음을 수행할 수 있습니다:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
이 변수는 현재 세션 및 해당 하위 프로세스에서 접근할 수 있습니다.

다음을 수행하여 변수를 **제거**할 수 있습니다:
```bash
unset MYGLOBAL
```
## 로컬 변수

**로컬 변수**는 현재 쉘/스크립트에서만 **액세스**할 수 있습니다.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## 현재 변수 목록
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## 일반 변수

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – **X**에서 사용하는 디스플레이. 이 변수는 일반적으로 현재 컴퓨터의 첫 번째 디스플레이인 **:0.0**로 설정됩니다.
* **EDITOR** – 사용자가 선호하는 텍스트 편집기.
* **HISTFILESIZE** – 히스토리 파일에 포함된 최대 라인 수.
* **HISTSIZE** – 사용자가 세션을 종료할 때 히스토리 파일에 추가되는 라인 수
* **HOME** – 홈 디렉토리.
* **HOSTNAME** – 컴퓨터의 호스트 이름.
* **LANG** – 현재 언어.
* **MAIL** – 사용자 메일 스풀의 위치. 일반적으로 **/var/spool/mail/USER**.
* **MANPATH** – 매뉴얼 페이지를 검색할 디렉토리 목록.
* **OSTYPE** – 운영 체제 유형.
* **PS1** – bash의 기본 프롬프트.
* **PATH** – 실행하려는 이진 파일이 있는 모든 디렉토리의 경로를 저장하며, 파일의 이름만 지정하여 상대 또는 절대 경로를 사용하지 않고 실행할 수 있습니다.
* **PWD** – 현재 작업 디렉토리.
* **SHELL** – 현재 명령 셸의 경로 (예: **/bin/bash**).
* **TERM** – 현재 터미널 유형 (예: **xterm**).
* **TZ** – 사용자의 시간대.
* **USER** – 현재 사용자 이름.

## 해킹에 흥미로운 변수

### **HISTFILESIZE**

**이 변수의 값을 0으로 변경**하여 세션을 **종료할 때 히스토리 파일** (\~/.bash\_history) **이 삭제**되도록 합니다.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

이 변수의 **값을 0으로 변경**하여 세션을 **종료할 때** 어떤 명령어도 **히스토리 파일** (\~/.bash\_history)에 추가되지 않도록 합니다.
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

프로세스는 여기에 선언된 **프록시**를 사용하여 **http 또는 https**를 통해 인터넷에 연결됩니다.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

프로세스는 **이 환경 변수에서** 지정된 인증서를 신뢰합니다.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

프롬프트의 모양을 변경합니다.

[**이것은 예시입니다**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

루트:

![](<../.gitbook/assets/image (897).png>)

일반 사용자:

![](<../.gitbook/assets/image (740).png>)

하나, 둘, 셋이 백그라운드로 실행 중인 작업:

![](<../.gitbook/assets/image (145).png>)

하나의 백그라운드 작업, 하나는 멈추고 마지막 명령이 올바르게 완료되지 않음:

![](<../.gitbook/assets/image (715).png>)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>제로부터 히어로가 되기까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유하세요.**

</details>
