# 도커 포렌식

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}

## 컨테이너 수정

어떤 도커 컨테이너가 침해당했을 가능성이 있습니다:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
당신은 쉽게 다음을 사용하여 **이 컨테이너에 대한 이미지와 관련된 수정 사항을 찾을 수 있습니다**:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
이전 명령어에서 **C**는 **변경됨**을 의미하고 **A**는 **추가됨**을 의미합니다.\
만약 `/etc/shadow`와 같은 흥미로운 파일이 수정되었다면, 악의적인 활동을 확인하기 위해 해당 파일을 컨테이너에서 다운로드할 수 있습니다:
```bash
docker cp wordpress:/etc/shadow.
```
당신은 새 컨테이너를 실행하고 그 파일을 추출하여 원본과 비교할 수도 있습니다:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
만약 **의심스러운 파일이 추가된 것을 발견**하면 컨테이너에 액세스하여 확인할 수 있습니다:
```bash
docker exec -it wordpress bash
```
## 이미지 수정

내보낸 도커 이미지(아마도 `.tar` 형식)가 주어지면 [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)를 사용하여 **수정 사항 요약을 추출**할 수 있습니다:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
그럼 이미지를 **압축 해제**하고 **블롭에 액세스**하여 변경 이력에서 발견한 의심스러운 파일을 검색할 수 있습니다:
```bash
tar -xf image.tar
```
### 기본 분석

이미지를 실행하여 **기본 정보**를 얻을 수 있습니다:
```bash
docker inspect <image>
```
요약된 **변경 이력**을 다음과 같이 얻을 수도 있습니다:
```bash
docker history --no-trunc <image>
```
이미지에서 **도커파일을 생성**할 수도 있습니다:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### 다이브

도커 이미지에서 추가/수정된 파일을 찾으려면 [**dive**](https://github.com/wagoodman/dive)를 사용할 수도 있습니다 ([**릴리스**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)에서 다운로드).
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
이를 통해 **도커 이미지의 다른 덩어리를 탐색**하고 어떤 파일이 수정/추가되었는지 확인할 수 있습니다. **빨간색**은 추가된 것을 의미하고 **노란색**은 수정된 것을 의미합니다. **탭**을 사용하여 다른 뷰로 이동하고 **스페이스**를 사용하여 폴더를 축소/열기할 수 있습니다.

Die를 사용하면 이미지의 다른 단계의 내용에 액세스할 수 없습니다. 이를 위해 **각 레이어를 압축 해제하고 액세스해야**합니다.\
이미지의 모든 레이어를 압축 해제하려면 이미지가 압축 해제된 디렉토리에서 다음을 실행하십시오:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## 메모리에서 자격 증명

호스트 내에서 도커 컨테이너를 실행할 때 **호스트에서 컨테이너에서 실행 중인 프로세스를 볼 수 있습니다**. 단순히 `ps -ef`를 실행하면 됩니다.

따라서 (루트로) 호스트에서 **프로세스의 메모리를 덤프**하고 [**다음 예시와 같이**](../../linux-hardening/privilege-escalation/#process-memory) **자격 증명을 검색**할 수 있습니다.

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}
