# 도커 포렌식

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>

## 컨테이너 수정

어떤 도커 컨테이너가 침해당했을 가능성이 있습니다:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
이 컨테이너에 대한 이미지와 관련하여 수행된 수정 사항을 쉽게 찾을 수 있습니다. 다음과 같이 하면 됩니다:
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
이전 명령어에서 **C**는 **변경됨(Changed)**을 의미하고, **A**는 **추가됨(Added)**을 의미합니다.\
만약 `/etc/shadow`와 같은 흥미로운 파일이 수정되었다고 판단된다면, 악성 활동을 확인하기 위해 해당 컨테이너에서 다운로드할 수 있습니다:
```bash
docker cp wordpress:/etc/shadow.
```
새 컨테이너를 실행하고 파일을 추출하여 원본과 비교할 수도 있습니다:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
만약 **의심스러운 파일이 추가**되었다는 것을 발견한다면, 컨테이너에 접근하여 확인할 수 있습니다:
```bash
docker exec -it wordpress bash
```
## 이미지 수정

당신에게 내보낸 도커 이미지 (아마도 `.tar` 형식일 것입니다)가 주어지면 [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)를 사용하여 **수정 내용 요약을 추출**할 수 있습니다:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
그런 다음 이미지를 **압축 해제**하고 **블롭에 액세스**하여 변경 내역에서 발견한 수상한 파일을 검색할 수 있습니다:
```bash
tar -xf image.tar
```
### 기본 분석

이미지를 실행하여 **기본 정보**를 얻을 수 있습니다:
```bash
docker inspect <image>
```
다음과 같이 **변경 내역의 요약**을 얻을 수도 있습니다:
```bash
docker history --no-trunc <image>
```
이미지에서 **도커파일을 생성**할 수도 있습니다. 다음과 같이 하면 됩니다:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

도커 이미지에서 추가/수정된 파일을 찾기 위해 [**dive**](https://github.com/wagoodman/dive)도 사용할 수 있습니다. (다음 [**릴리스**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)에서 다운로드할 수 있습니다.) 유틸리티:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
이를 통해 도커 이미지의 다른 덩어리를 탐색하고 수정/추가된 파일을 확인할 수 있습니다. **빨간색**은 추가된 것을 의미하고 **노란색**은 수정된 것을 의미합니다. **탭**을 사용하여 다른 뷰로 이동하고 **스페이스바**를 사용하여 폴더를 축소/확장할 수 있습니다.

die를 사용하면 이미지의 다른 단계의 내용에 액세스할 수 없습니다. 이를 위해 각 레이어를 압축 해제하고 액세스해야 합니다.\
이미지가 압축 해제된 디렉토리에서 모든 레이어를 압축 해제할 수 있습니다. 다음을 실행하세요.
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## 메모리에서 자격 증명 얻기

참고로 호스트 내에서 도커 컨테이너를 실행할 때 **호스트에서 컨테이너에서 실행 중인 프로세스를 볼 수 있습니다**. `ps -ef`를 실행하면 됩니다.

따라서 (루트 권한으로) 호스트에서 **프로세스의 메모리를 덤프**하고 [**다음 예시처럼**](../../linux-hardening/privilege-escalation/#process-memory) **자격 증명을 검색**할 수 있습니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왑**](https://peass.creator-spring.com)을 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
