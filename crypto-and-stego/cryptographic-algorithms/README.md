# 암호화/압축 알고리즘

## 암호화/압축 알고리즘

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 팁을 공유하려면 PR을 제출하여** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소를 이용하세요.

</details>
{% endhint %}

## 알고리즘 식별

만약 코드가 **시프트 우측 및 좌측, XOR 및 여러 산술 연산**을 사용한다면, 그것이 **암호화 알고리즘의 구현**일 가능성이 높습니다. 여기에서는 **각 단계를 역으로 추적할 필요 없이 사용된 알고리즘을 식별하는 방법**을 소개합니다.

### API 함수

**CryptDeriveKey**

이 함수가 사용된 경우, 두 번째 매개변수의 값을 확인하여 **사용된 알고리즘을 확인**할 수 있습니다:

![](<../../.gitbook/assets/image (156).png>)

가능한 알고리즘 및 해당 값에 대한 테이블은 여기에서 확인할 수 있습니다: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

주어진 데이터 버퍼를 압축하거나 해제합니다.

**CryptAcquireContext**

[문서](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta)에 따르면 **CryptAcquireContext** 함수는 특정 암호화 서비스 제공자(CSP) 내의 특정 키 컨테이너에 대한 핸들을 획득하는 데 사용됩니다. **이 반환된 핸들은 선택된 CSP를 사용하는 CryptoAPI 함수 호출에 사용**됩니다.

**CryptCreateHash**

데이터 스트림의 해싱을 시작합니다. 이 함수가 사용된 경우, 두 번째 매개변수의 값을 확인하여 **사용된 알고리즘을 확인**할 수 있습니다:

![](<../../.gitbook/assets/image (549).png>)

\
가능한 알고리즘 및 해당 값에 대한 테이블은 여기에서 확인할 수 있습니다: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### 코드 상수

때로는 특별하고 고유한 값을 사용해야 하는 알고리즘을 식별하는 것이 매우 쉽습니다.

![](<../../.gitbook/assets/image (833).png>)

첫 번째 상수를 구글에서 검색하면 다음과 같은 결과가 나옵니다:

![](<../../.gitbook/assets/image (529).png>)

따라서, 디컴파일된 함수가 **sha256 계산기**임을 가정할 수 있습니다.\
다른 상수 중 하나를 검색하면 (아마도) 동일한 결과를 얻을 수 있습니다.

### 데이터 정보

코드에 중요한 상수가 없는 경우, **.data 섹션에서 정보를 로드**할 수 있습니다.\
해당 데이터에 액세스하여 **첫 번째 dword를 그룹화**하고 이전 섹션에서 수행한 것과 같이 구글에서 검색할 수 있습니다:

![](<../../.gitbook/assets/image (531).png>)

이 경우, **0xA56363C6**을 검색하면 **AES 알고리즘의 테이블**과 관련된 것임을 알 수 있습니다.

## RC4 **(대칭 암호)**

### 특징

* **초기화 단계/**: 0x00에서 0xFF(총 256바이트, 0x100)까지의 값 테이블을 생성합니다. 이 테이블은 일반적으로 **치환 상자**(또는 SBox)라고 합니다.
* **혼돈 단계**: 이전에 생성된 테이블을 반복하여(다시 0x100 반복) 각 값을 **반 랜덤** 바이트로 수정합니다. 이 반 랜덤 바이트를 만들기 위해 RC4 **키가 사용**됩니다. RC4 **키**는 **1바이트에서 256바이트** 사이일 수 있지만, 일반적으로 5바이트 이상을 권장합니다. 일반적으로 RC4 키는 16바이트입니다.
* **XOR 단계**: 마지막으로, 평문 또는 암호문이 **이전에 생성된 값과 XOR**됩니다. 암호화 및 복호화를 위한 함수는 동일합니다. 이를 위해 생성된 256바이트를 **필요한 만큼 반복**합니다. 이는 일반적으로 디컴파일된 코드에서 **%256(mod 256)**로 인식됩니다.

{% hint style="info" %}
**디어셈블리/디컴파일된 코드에서 RC4를 식별하려면 0x100 크기의 2개의 루프(키 사용)와 256개의 값으로 생성된 입력 데이터의 XOR를 확인할 수 있습니다. 이때 2개의 루프에서 생성된 256개의 값은 아마도 %256(mod 256)를 사용하여 입력 데이터와 XOR됩니다.**
{% endhint %}

### **초기화 단계/치환 상자:** (256이라는 카운터 사용 및 256개 문자의 각 위치에 0이 작성된 것에 주목)

![](<../../.gitbook/assets/image (584).png>)

### **혼돈 단계:**

![](<../../.gitbook/assets/image (835).png>)

### **XOR 단계:**

![](<../../.gitbook/assets/image (904).png>)

## **AES (대칭 암호)**

### **특징**

* **치환 상자 및 룩업 테이블 사용**
* 특정 룩업 테이블 값(상수) 사용으로 **AES를 식별**할 수 있습니다. _상수는 이진 파일에 **저장**되거나 **동적으로 생성**될 수 있음에 유의하십시오._
* **암호화 키**는 **16의 배수**여야 하며 일반적으로 32바이트이며 일반적으로 16바이트 IV가 사용됩니다.

### SBox 상수

![](<../../.gitbook/assets/image (208).png>)

## Serpent **(대칭 암호)**

### 특징

* 악성 코드에서 사용하는 것은 드물지만 예시가 있습니다(Ursnif)
* 알고리즘이 Serpent인지 아닌지를 결정하는 것은 길이(매우 긴 함수)를 기반으로 합니다.

### 식별

다음 이미지에서 상수 **0x9E3779B9**가 사용된 것에 주목하세요(이 상수는 **TEA**(Tiny Encryption Algorithm)와 같은 다른 암호 알고리즘에서도 사용됩니다).\
또한 **루프의 크기**(132)와 **디어셈블리 명령** 및 **코드 예제**에서의 **XOR 작업 수**에 주목하세요:

![](<../../.gitbook/assets/image (547).png>)

이전에 언급한대로, 이 코드는 **내부에 점프가 없는 매우 긴 함수**로 시각화될 수 있습니다. 디컴파일된 코드는 다음과 같이 보일 수 있습니다:

![](<../../.gitbook/assets/image (513).png>)

따라서, **매직 넘버**와 **초기 XOR**를 확인하고 **매우 긴 함수**를 보고 **일부 명령어**를 **구현**(예: 7비트 왼쪽 시프트 및 22비트 왼쪽 회전)과 **비교**하여 이 알고리즘을 식별할 수 있습니다.
## RSA **(비대칭 암호화)**

### 특징

* 대칭 알고리즘보다 복잡함
* 상수가 없음! (사용자 정의 구현이 어려움)
* RSA에 대한 힌트를 제공하지 못하는 KANAL (암호 분석기)는 상수에 의존함.

### 비교를 통한 식별

![](<../../.gitbook/assets/image (1113).png>)

* 11번째 줄 (왼쪽)에는 `+7) >> 3`이 있고, 35번째 줄 (오른쪽)에는 `+7) / 8`과 동일함
* 12번째 줄 (왼쪽)은 `modulus_len < 0x040`을 확인하고, 36번째 줄 (오른쪽)은 `inputLen+11 > modulusLen`을 확인함

## MD5 & SHA (해시)

### 특징

* Init, Update, Final 3가지 함수
* 유사한 초기화 함수

### 식별

**Init**

상수를 확인하여 두 가지를 식별할 수 있음. MD5에는 없는 상수가 sha\_init에 1개 있다는 점에 유의:

![](<../../.gitbook/assets/image (406).png>)

**MD5 Transform**

더 많은 상수 사용에 유의

![](<../../.gitbook/assets/image (253) (1) (1).png>)

## CRC (해시)

* 데이터의 우발적인 변경을 찾는 함수로 작동하여 더 작고 효율적임
* 상수를 식별할 수 있도록 룩업 테이블 사용

### 식별

**룩업 테이블 상수** 확인:

![](<../../.gitbook/assets/image (508).png>)

CRC 해시 알고리즘은 다음과 같음:

![](<../../.gitbook/assets/image (391).png>)

## APLib (압축)

### 특징

* 식별할 수 없는 상수
* 파이썬으로 알고리즘을 작성하고 온라인에서 유사한 것을 검색해볼 수 있음

### 식별

그래프가 매우 큼:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

**식별하기 위한 3가지 비교** 확인:

![](<../../.gitbook/assets/image (430).png>)
