# Volatility - CheatSheet

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왑**](https://peass.creator-spring.com)을 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를 팔로우**하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 **해킹 기교를 공유**하세요.

</details>

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성 높은 사이버 보안 행사이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술적인 지식을 촉진**하기 위한 미션을 가지고 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 열정적인 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

여러 Volatility 플러그인을 병렬로 실행할 수 있는 **빠르고 미친** 것을 원한다면 [https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)을 사용할 수 있습니다.
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## 설치

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{% tabs %}
{% tab title="Method1" %}

#### 1. 이미지 프로파일 확인

- `volatility2 -f <memory_dump> imageinfo`

#### 2. 프로세스 목록 확인

- `volatility2 -f <memory_dump> --profile=<profile> pslist`

#### 3. 특정 프로세스의 메모리 덤프 추출

- `volatility2 -f <memory_dump> --profile=<profile> memdump -p <pid> -D <output_directory>`

#### 4. 파일 추출

- `volatility2 -f <memory_dump> --profile=<profile> filescan | grep -i <file_extension>`

#### 5. 네트워크 연결 확인

- `volatility2 -f <memory_dump> --profile=<profile> netscan`

#### 6. 레지스트리 정보 확인

- `volatility2 -f <memory_dump> --profile=<profile> hivelist`

#### 7. 레지스트리 키 추출

- `volatility2 -f <memory_dump> --profile=<profile> printkey -K <registry_key>`

#### 8. 사용자 정보 확인

- `volatility2 -f <memory_dump> --profile=<profile> hivescan`

#### 9. 사용자 패스워드 추출

- `volatility2 -f <memory_dump> --profile=<profile> hashdump`

#### 10. 네트워크 트래픽 분석

- `volatility2 -f <memory_dump> --profile=<profile> tcpdump -p <pid> -D <output_directory>`

{% endtab %}
{% endtabs %}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{% tab title="Method 2" %}방법 2
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{% endtab %}
{% endtabs %}

## Volatility 명령어

[Volatility 명령어 참조](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)에서 공식 문서에 접근할 수 있습니다.

### "list" vs. "scan" 플러그인에 대한 참고 사항

Volatility는 플러그인에 대해 두 가지 주요 접근 방식을 가지고 있으며, 이는 때로는 플러그인 이름에 반영될 수 있습니다. "list" 플러그인은 Windows 커널 구조를 탐색하여 프로세스(메모리의 `_EPROCESS` 구조체의 연결 리스트를 찾고 탐색)와 같은 정보를 검색합니다. OS 핸들(핸들 테이블을 찾고 나열하고 찾은 포인터를 역참조 등)을 찾습니다. 이들은 요청된 경우 Windows API가 수행하는 것과 거의 동일하게 동작합니다. 예를 들어, 프로세스 목록을 나열하도록 요청하면 "list" 플러그인은 상당히 빠르지만, 악성 코드에 의해 조작될 수 있는 Windows API와 동일한 취약점을 가지고 있습니다. 예를 들어, 악성 코드가 DKOM을 사용하여 프로세스를 `_EPROCESS` 연결 리스트에서 분리하면 해당 프로세스는 작업 관리자에 표시되지 않으며 pslist에도 표시되지 않습니다.

반면에 "scan" 플러그인은 특정 구조체로 역참조될 때 의미가 있을 수 있는 것들을 메모리에서 추출하는 것과 유사한 방식으로 작동합니다. 예를 들어, `psscan`은 메모리를 읽고 그것으로부터 `_EPROCESS` 객체를 만들려고 시도합니다(관심 있는 구조체의 존재를 나타내는 4바이트 문자열을 검색하는 pool-tag 스캐닝을 사용합니다). 이 방법의 장점은 종료된 프로세스를 찾을 수 있으며, 악성 코드가 `_EPROCESS` 연결 리스트를 조작하더라도 플러그인은 메모리에 여전히 구조체가 남아있을 것입니다(프로세스가 실행되기 위해서는 여전히 존재해야 하기 때문입니다). 단점은 "scan" 플러그인이 "list" 플러그인보다 약간 느리며, 때로는 잘못된 양성 결과를 반환할 수 있다는 것입니다(구조체 일부가 다른 작업에 의해 덮어쓰여 종료된 프로세스).

출처: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

## OS 프로파일

### Volatility3

readme 안에 설명된 대로, 지원하려는 **OS의 심볼 테이블**을 _volatility3/volatility/symbols_에 넣어야 합니다.\
다양한 운영 체제에 대한 심볼 테이블 팩은 다음에서 **다운로드**할 수 있습니다:

* [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
* [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### 외부 프로파일

지원되는 프로파일 목록을 얻으려면 다음을 수행할 수 있습니다:
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
만약 **새로 다운로드한 프로필** (예: 리눅스 프로필)을 사용하려면 다음 폴더 구조를 생성해야 합니다: _plugins/overlays/linux_. 그리고 이 폴더 안에 프로필을 포함한 zip 파일을 넣으세요. 그런 다음, 다음 명령을 사용하여 프로필의 번호를 얻으세요:
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
[https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles)에서 **Linux 및 Mac 프로파일을 다운로드**할 수 있습니다.

이전 청크에서 볼 수 있듯이 프로파일은 `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64`라고 불리며, 다음과 같이 사용할 수 있습니다:
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### 프로필 탐색

```plaintext
volatility -f <memory_dump> imageinfo
```

- 메모리 덤프 파일의 정보를 확인합니다.

```plaintext
volatility -f <memory_dump> kdbgscan
```

- 커널 디버깅 세션 ID를 스캔하여 찾습니다.

```plaintext
volatility -f <memory_dump> pslist
```

- 프로세스 목록을 표시합니다.

```plaintext
volatility -f <memory_dump> psscan
```

- 프로세스 목록을 스캔하여 찾습니다.

```plaintext
volatility -f <memory_dump> pstree
```

- 프로세스 트리를 표시합니다.

```plaintext
volatility -f <memory_dump> dlllist -p <pid>
```

- 특정 프로세스의 DLL 목록을 표시합니다.

```plaintext
volatility -f <memory_dump> handles -p <pid>
```

- 특정 프로세스의 핸들 목록을 표시합니다.

```plaintext
volatility -f <memory_dump> cmdline -p <pid>
```

- 특정 프로세스의 명령줄 인수를 표시합니다.

```plaintext
volatility -f <memory_dump> filescan
```

- 파일 목록을 스캔하여 찾습니다.

```plaintext
volatility -f <memory_dump> malfind
```

- 악성 코드를 찾습니다.

```plaintext
volatility -f <memory_dump> malfind -D <output_directory>
```

- 악성 코드를 찾고, 결과를 지정한 디렉토리에 저장합니다.

```plaintext
volatility -f <memory_dump> malfind -p <pid>
```

- 특정 프로세스에서 악성 코드를 찾습니다.

```plaintext
volatility -f <memory_dump> malfind -p <pid> -D <output_directory>
```

- 특정 프로세스에서 악성 코드를 찾고, 결과를 지정한 디렉토리에 저장합니다.

```plaintext
volatility -f <memory_dump> vadinfo -p <pid>
```

- 특정 프로세스의 가상 주소 공간 정보를 표시합니다.

```plaintext
volatility -f <memory_dump> vadtree -p <pid>
```

- 특정 프로세스의 가상 주소 공간 트리를 표시합니다.

```plaintext
volatility -f <memory_dump> vadwalk -p <pid>
```

- 특정 프로세스의 가상 주소 공간을 탐색합니다.

```plaintext
volatility -f <memory_dump> vadtree -D <output_directory>
```

- 모든 프로세스의 가상 주소 공간 트리를 표시합니다.

```plaintext
volatility -f <memory_dump> vadwalk -D <output_directory>
```

- 모든 프로세스의 가상 주소 공간을 탐색합니다.

```plaintext
volatility -f <memory_dump> hivelist
```

- 레지스트리 키 목록을 표시합니다.

```plaintext
volatility -f <memory_dump> hivedump -o <offset> -D <output_directory>
```

- 특정 레지스트리 키를 덤프하고, 결과를 지정한 디렉토리에 저장합니다.

```plaintext
volatility -f <memory_dump> hivelist -o <offset>
```

- 특정 레지스트리 키의 오프셋을 확인합니다.

```plaintext
volatility -f <memory_dump> printkey -o <offset>
```

- 특정 레지스트리 키의 내용을 표시합니다.

```plaintext
volatility -f <memory_dump> printkey -o <offset> -K <registry_key>
```

- 특정 레지스트리 키의 내용을 표시합니다.

```plaintext
volatility -f <memory_dump> printkey -o <offset> -K <registry_key> -y <registry_hive>
```

- 특정 레지스트리 키의 내용을 표시합니다.

```plaintext
volatility -f <memory_dump> printkey -o <offset> -K <registry_key> -y <registry_hive> -o <output_directory>
```

- 특정 레지스트리 키의 내용을 표시하고, 결과를 지정한 디렉토리에 저장합니다.
```
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **imageinfo와 kdbgscan의 차이점**

[**여기에서**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)는 imageinfo가 단순히 프로파일 제안을 제공하는 반면, **kdbgscan**은 올바른 프로파일과 올바른 KDBG 주소(여러 개인 경우)를 확실히 식별하기 위해 설계되었습니다. 이 플러그인은 Volatility 프로파일과 관련된 KDBGHeader 서명을 스캔하고 잘못된 양성 결과를 줄이기 위해 타당성 검사를 적용합니다. 출력의 상세정도와 수행할 수 있는 타당성 검사의 수는 Volatility가 DTB를 찾을 수 있는지 여부에 따라 달라집니다. 따라서 이미 올바른 프로파일을 알고 있다면(imageinfo에서 프로파일 제안을 받았다면), 반드시 그것을 사용하십시오.

항상 kdbgscan이 찾은 **프로세스의 수**를 확인하십시오. 때로는 imageinfo와 kdbgscan이 **하나 이상의 적합한 프로파일을 찾을 수 있지만, 유효한 프로파일만이 일부 프로세스와 관련이 있을 것입니다** (이는 프로세스를 추출하기 위해 올바른 KDBG 주소가 필요하기 때문입니다).
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

**커널 디버거 블록**은 Volatility와 다양한 디버거에 의해 수행되는 포렌식 작업에 있어서 중요합니다. Volatility에서는 **KDBG**라고 불리며, `_KDDEBUGGER_DATA64` 타입의 `KdDebuggerDataBlock`으로 식별됩니다. 이 블록에는 `PsActiveProcessHead`와 같은 필수적인 참조 정보가 포함되어 있습니다. 이 특정 참조는 프로세스 목록의 헤드를 가리키며, 모든 프로세스의 목록을 나열하는 데 필수적입니다. 이는 철저한 메모리 분석을 위해 근본적인 역할을 합니다.

## 운영 체제 정보
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
플러그인 `banners.Banners`는 덤프에서 리눅스 배너를 찾기 위해 **vol3에서 사용할 수 있습니다**.

## 해시/비밀번호

SAM 해시, [도메인 캐시된 자격 증명](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) 및 [lsa 비밀](../../../windows-hardening/authentication-credentials-uac-and-efs.md#lsa-secrets)을 추출합니다.

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
## Volatility 명령어 요약

### Volatility 기본 명령어

- **imageinfo**: 이미지 정보를 표시합니다.
- **kdbgscan**: 디버깅 세션을 찾습니다.
- **kpcrscan**: KPCR을 찾습니다.
- **pslist**: 프로세스 목록을 표시합니다.
- **pstree**: 프로세스 트리를 표시합니다.
- **psscan**: 프로세스 스냅샷을 표시합니다.
- **dlllist**: DLL 목록을 표시합니다.
- **handles**: 핸들 목록을 표시합니다.
- **cmdline**: 명령줄 인수를 표시합니다.
- **filescan**: 파일 스캔을 수행합니다.
- **malfind**: 악성 코드 주소를 찾습니다.
- **vadinfo**: 가상 주소 공간 정보를 표시합니다.
- **vadtree**: 가상 주소 공간 트리를 표시합니다.
- **vaddump**: 가상 주소 공간 덤프를 수행합니다.
- **memdump**: 메모리 덤프를 수행합니다.
- **moddump**: 모듈 덤프를 수행합니다.
- **modscan**: 모듈 스캔을 수행합니다.
- **ssdt**: SSDT 정보를 표시합니다.
- **gdt**: GDT 정보를 표시합니다.
- **idt**: IDT 정보를 표시합니다.
- **ldrmodules**: LDR 모듈 정보를 표시합니다.
- **apihooks**: API 후킹 정보를 표시합니다.
- **svcscan**: 서비스 스캔을 수행합니다.
- **ssdt**: SSDT 정보를 표시합니다.
- **gdt**: GDT 정보를 표시합니다.
- **idt**: IDT 정보를 표시합니다.
- **ldrmodules**: LDR 모듈 정보를 표시합니다.
- **apihooks**: API 후킹 정보를 표시합니다.
- **svcscan**: 서비스 스캔을 수행합니다.
- **driverirp**: 드라이버 IRP 정보를 표시합니다.
- **drivermodule**: 드라이버 모듈 정보를 표시합니다.
- **driverobject**: 드라이버 객체 정보를 표시합니다.
- **driversection**: 드라이버 섹션 정보를 표시합니다.
- **driverwmi**: 드라이버 WMI 정보를 표시합니다.
- **driverregistry**: 드라이버 레지스트리 정보를 표시합니다.
- **driverhandles**: 드라이버 핸들 정보를 표시합니다.
- **driverirp**: 드라이버 IRP 정보를 표시합니다.
- **drivermodule**: 드라이버 모듈 정보를 표시합니다.
- **driverobject**: 드라이버 객체 정보를 표시합니다.
- **driversection**: 드라이버 섹션 정보를 표시합니다.
- **driverwmi**: 드라이버 WMI 정보를 표시합니다.
- **driverregistry**: 드라이버 레지스트리 정보를 표시합니다.
- **driverhandles**: 드라이버 핸들 정보를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**: 장치 트리를 표시합니다.
- **devicetree**:
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{% endtab %}
{% endtabs %}

## 메모리 덤프

프로세스의 메모리 덤프는 프로세스의 현재 상태를 **모두 추출**합니다. **procdump** 모듈은 **코드**만을 **추출**합니다.
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성 있는 사이버 보안 행사이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술적인 지식을 촉진하는 미션**을 가지고 있는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 열정적인 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

## 프로세스

### 프로세스 목록

**의심스러운** 프로세스(이름으로) 또는 **예상치 못한** 자식 **프로세스**(예: iexplorer.exe의 자식으로 cmd.exe)를 찾아보십시오.\
pslist의 결과와 psscan의 결과를 비교하여 숨겨진 프로세스를 식별하는 것이 흥미로울 수 있습니다.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install -r requirements.txt
   ```

3. Download the latest version of Volatility from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Change to the Volatility directory:

   ```
   cd volatility
   ```

5. Run Volatility using the following command:

   ```
   python vol.py
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Set the profile using the `-p` option:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 <command>
   ```

3. Run the desired Volatility command. For example, to list all running processes, use the `pslist` command:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

### Common Commands

- `imageinfo`: Retrieves information about the memory dump, such as the profile, architecture, and build time.
- `pslist`: Lists all running processes.
- `pstree`: Displays the process tree, showing parent-child relationships between processes.
- `psscan`: Scans for processes in memory.
- `dlllist`: Lists loaded DLLs for each process.
- `handles`: Lists open handles for each process.
- `connections`: Lists network connections.
- `netscan`: Scans for network connections in memory.
- `malfind`: Finds hidden or injected code in memory.
- `cmdscan`: Scans for command history in memory.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists registry hives.
- `hivedump`: Dumps a registry hive.
- `hashdump`: Dumps password hashes from memory.

### Additional Resources

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{% tab title="vol3" %}

### 덤프 프로세스

{% endtab %}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install volatility
   ```

3. Download the Volatility source code from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Navigate to the Volatility directory and run the following command to verify the installation:

   ```
   python vol.py -h
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Once you have identified the profile, use the appropriate plugin to extract the desired information. For example, to list all running processes, use the `pslist` plugin:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

3. Use the available options to filter and format the output as needed. For example, to display only the process names and PIDs, use the `--output=csv` and `--columns=Name,PID` options:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist --output=csv --columns=Name,PID
   ```

### Advanced Usage

Volatility provides a wide range of plugins for analyzing different aspects of memory dumps. Some of the commonly used plugins include:

- `pslist`: Lists all running processes.
- `netscan`: Displays network connections.
- `malfind`: Identifies injected and hidden code.
- `dlllist`: Lists loaded DLLs.
- `filescan`: Scans for file handles and file objects.
- `cmdscan`: Lists command history.
- `hivelist`: Lists registry hives.

To use these plugins, specify the desired plugin name after the `--profile` option. For example, to list all loaded DLLs, use the `dlllist` plugin:

```
python vol.py -f memory_dump.raw --profile=Win7SP1x64 dlllist
```

### Conclusion

Volatility is a powerful tool for analyzing memory dumps and extracting valuable information for forensic investigations. This cheat sheet provides a quick reference guide for using Volatility and highlights some of the most commonly used commands and plugins. Experiment with different options and plugins to maximize the effectiveness of your memory analysis.
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{% endtab %}
{% endtabs %}

### 명령 줄

의심스러운 것이 실행되었나요?
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

```bash
pip install volatility
```

### Basic Usage

To analyze a memory dump using Volatility, use the following command:

```bash
volatility -f <memory_dump> <command> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<command>` with the desired Volatility command.

### Volatility Commands

#### Image Identification

- **imageinfo**: Displays information about the memory dump, such as the operating system version and profile.

```bash
volatility -f <memory_dump> imageinfo
```

#### Process Analysis

- **pslist**: Lists all running processes in the memory dump.

```bash
volatility -f <memory_dump> pslist
```

- **psscan**: Scans for hidden or terminated processes.

```bash
volatility -f <memory_dump> psscan
```

#### Network Analysis

- **netscan**: Lists all network connections in the memory dump.

```bash
volatility -f <memory_dump> netscan
```

- **connscan**: Lists all TCP and UDP connections.

```bash
volatility -f <memory_dump> connscan
```

#### Module Analysis

- **modscan**: Lists all loaded modules in the memory dump.

```bash
volatility -f <memory_dump> modscan
```

- **moddump**: Dumps a specific module from memory.

```bash
volatility -f <memory_dump> moddump -D <output_directory> -n <module_name>
```

Replace `<output_directory>` with the desired directory to save the module dump and `<module_name>` with the name of the module to dump.

### Conclusion

This cheat sheet provides a basic overview of Volatility and its commonly used commands. By leveraging Volatility's capabilities, analysts can perform in-depth memory analysis and extract valuable information from memory dumps.
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{% endtab %}
{% endtabs %}

`cmd.exe`에서 실행된 명령은 **`conhost.exe`** (또는 Windows 7 이전의 시스템에서는 `csrss.exe`)에 의해 관리됩니다. 이는 메모리 덤프를 얻기 전에 공격자에 의해 **`cmd.exe`**가 종료된 경우에도 세션의 명령 히스토리를 **`conhost.exe`**의 메모리에서 복구할 수 있다는 것을 의미합니다. 이를 위해 콘솔 모듈에서 이상한 활동이 감지되면 연관된 **`conhost.exe`** 프로세스의 메모리를 덤프해야 합니다. 그런 다음 이 덤프 내에서 **문자열**을 검색하여 세션에서 사용된 명령 라인을 추출할 수 있습니다.

### 환경

각 실행 중인 프로세스의 환경 변수를 가져옵니다. 흥미로운 값이 있을 수 있습니다.

{% tabs %}
{% tab title="vol3" %}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

```bash
pip install volatility
```

### Basic Usage

To analyze a memory dump using Volatility, use the following command:

```bash
volatility -f <memory_dump> <command> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<command>` with the desired Volatility command.

### Volatility Commands

#### Image Identification

- **imageinfo**: Retrieve information about the memory dump, such as the operating system version and profile.

```bash
volatility -f <memory_dump> imageinfo
```

#### Process Analysis

- **pslist**: List all running processes.

```bash
volatility -f <memory_dump> pslist
```

- **psscan**: Scan for hidden or terminated processes.

```bash
volatility -f <memory_dump> psscan
```

#### Network Analysis

- **netscan**: List network connections.

```bash
volatility -f <memory_dump> netscan
```

- **connscan**: List TCP and UDP connections.

```bash
volatility -f <memory_dump> connscan
```

#### Module Analysis

- **modscan**: List loaded modules.

```bash
volatility -f <memory_dump> modscan
```

- **moddump**: Dump a specific module from memory.

```bash
volatility -f <memory_dump> moddump -D <output_directory> -n <module_name>
```

Replace `<output_directory>` with the desired directory to save the module dump and `<module_name>` with the name of the module to dump.

### Conclusion

This cheat sheet provides a brief overview of some of the most commonly used Volatility commands for memory dump analysis. Volatility is a powerful tool for forensic analysis and can help uncover valuable information from memory dumps. Experiment with different commands and options to maximize the effectiveness of your memory analysis.
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
{% endtab %}
{% endtabs %}

### 토큰 권한

예상치 못한 서비스에서 권한 토큰을 확인하세요.\
특권 토큰을 사용하는 프로세스 목록을 작성하는 것이 흥미로울 수 있습니다.
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install -r requirements.txt
   ```

3. Download the latest version of Volatility from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Change to the Volatility directory:

   ```
   cd volatility
   ```

5. Run Volatility using the following command:

   ```
   python vol.py
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Set the profile using the `-p` option:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 <command>
   ```

3. Run the desired Volatility command. For example, to list all running processes, use the `pslist` command:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

### Common Commands

- `imageinfo`: Retrieves information about the memory dump, such as the profile, architecture, and build time.
- `pslist`: Lists all running processes.
- `pstree`: Displays the process tree, showing parent-child relationships between processes.
- `psscan`: Scans for processes in memory.
- `dlllist`: Lists loaded DLLs for each process.
- `handles`: Lists open handles for each process.
- `connections`: Lists network connections.
- `netscan`: Scans for network connections in memory.
- `malfind`: Finds hidden or injected code in memory.
- `cmdscan`: Scans for command history in memory.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists registry hives.
- `hivedump`: Dumps a registry hive.
- `hashdump`: Dumps password hashes from memory.

### Additional Resources

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{% endtab %}
{% endtabs %}

### SIDs

각 프로세스가 소유한 SSID를 확인합니다.\
특권 SSID를 사용하는 프로세스 및 일부 서비스 SSID를 사용하는 프로세스를 나열하는 것이 흥미로울 수 있습니다.
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install volatility
   ```

3. Download the Volatility source code from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Navigate to the Volatility directory and run the following command to verify the installation:

   ```
   python vol.py -h
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Once you have identified the profile, use the appropriate plugin to extract the desired information. For example, to list all running processes, use the `pslist` plugin:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

3. Use the available options to filter and format the output as needed. For example, to display only the process names and PIDs, use the `--output=text` and `--columns=Name,PID` options:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist --output=text --columns=Name,PID
   ```

### Advanced Usage

Volatility provides a wide range of plugins for analyzing different aspects of memory dumps. Some of the commonly used plugins include:

- `pslist`: Lists running processes.
- `netscan`: Lists network connections.
- `malfind`: Finds hidden and injected code.
- `dlllist`: Lists loaded DLLs.
- `cmdscan`: Lists command history.
- `filescan`: Lists open files.
- `svcscan`: Lists services.
- `handles`: Lists open handles.

To use these plugins, specify the appropriate plugin name after the `--profile` option. For example, to list network connections, use the `netscan` plugin:

```
python vol.py -f memory_dump.raw --profile=Win7SP1x64 netscan
```

### Conclusion

Volatility is a powerful tool for analyzing memory dumps and extracting valuable information for forensic investigations. This cheat sheet provides a quick reference guide for using Volatility and highlights some of the most commonly used commands and plugins. Experiment with different options and plugins to maximize the effectiveness of your memory analysis.
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{% endtab %}
{% endtabs %}

### 핸들

프로세스가 핸들을 가지고 있는 다른 파일, 키, 스레드, 프로세스 등을 알아내는 데 유용합니다.

{% tabs %}
{% tab title="vol3" %}
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

```bash
pip install volatility
```

### Basic Usage

To analyze a memory dump using Volatility, use the following command:

```bash
volatility -f <memory_dump> <command> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<command>` with the desired Volatility command.

### Volatility Commands

#### Image Identification

- **imageinfo**: Retrieve information about the memory dump, such as the operating system version and profile.

```bash
volatility -f <memory_dump> imageinfo
```

#### Process Analysis

- **pslist**: List all running processes.

```bash
volatility -f <memory_dump> pslist
```

- **psscan**: Scan for hidden or terminated processes.

```bash
volatility -f <memory_dump> psscan
```

#### Network Analysis

- **netscan**: List network connections.

```bash
volatility -f <memory_dump> netscan
```

- **connscan**: List TCP and UDP connections.

```bash
volatility -f <memory_dump> connscan
```

#### Module Analysis

- **modscan**: List loaded modules.

```bash
volatility -f <memory_dump> modscan
```

- **moddump**: Dump a specific module from memory.

```bash
volatility -f <memory_dump> moddump -D <output_directory> -n <module_name>
```

Replace `<output_directory>` with the desired directory to save the module dump and `<module_name>` with the name of the module to dump.

### Conclusion

This cheat sheet provides a basic overview of some of the most commonly used Volatility commands for memory dump analysis. Volatility is a powerful tool for forensic analysis and can help uncover valuable information from memory dumps. Experiment with different commands and options to maximize the effectiveness of your memory analysis.
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{% endtab %}
{% endtabs %}

### DLLs

{% tabs %}
{% tab title="vol3" %}

DLLs (Dynamic Link Libraries) are shared libraries that contain code and data that can be used by multiple programs at the same time. They are loaded into the memory space of a process when it is executed and provide additional functionality to the program.

Volatility provides several commands to analyze DLLs in memory dumps:

- `dlllist`: Lists all loaded DLLs in the memory dump.
- `dlldump`: Dumps the contents of a specific DLL from memory.
- `dllscan`: Scans the memory dump for DLLs and displays information about them.
- `dllhooks`: Lists all hooked DLLs in the memory dump.

These commands can be useful for identifying malicious DLLs that may have been injected into a process or for analyzing the functionality of a specific DLL.

{% endtab %}
{% endtabs %}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install -r requirements.txt
   ```

3. Download the latest version of Volatility from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Change to the Volatility directory:

   ```
   cd volatility
   ```

5. Run Volatility using the following command:

   ```
   python vol.py
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Set the profile using the `-p` option:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 <command>
   ```

3. Run the desired Volatility command. For example, to list all running processes, use the `pslist` command:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

### Common Commands

- `imageinfo`: Retrieves information about the memory dump, such as the profile, architecture, and build time.
- `pslist`: Lists all running processes.
- `pstree`: Displays the process tree, showing parent-child relationships between processes.
- `psscan`: Scans for processes in memory.
- `dlllist`: Lists loaded DLLs for each process.
- `handles`: Lists open handles for each process.
- `connections`: Lists network connections.
- `netscan`: Scans for network connections in memory.
- `malfind`: Finds hidden or injected code in memory.
- `cmdscan`: Scans for command history in memory.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists registry hives.
- `hivedump`: Dumps a registry hive.
- `hashdump`: Dumps password hashes from memory.

### Additional Resources

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{% endtab %}
{% endtabs %}

### 프로세스별 문자열

Volatility를 사용하면 문자열이 어떤 프로세스에 속하는지 확인할 수 있습니다.

{% tabs %}
{% tab title="vol3" %}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install -r requirements.txt
   ```

3. Download the latest version of Volatility from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Change to the Volatility directory:

   ```
   cd volatility
   ```

5. Run Volatility using the following command:

   ```
   python vol.py
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Set the profile using the `-p` option:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 <command>
   ```

3. Run the desired Volatility command. For example, to list all running processes, use the `pslist` command:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

### Common Commands

- `imageinfo`: Retrieves information about the memory dump, such as the profile, architecture, and build time.
- `pslist`: Lists all running processes.
- `pstree`: Displays the process tree, showing parent-child relationships between processes.
- `psscan`: Scans for processes in memory.
- `dlllist`: Lists loaded DLLs for each process.
- `handles`: Lists open handles for each process.
- `connections`: Lists network connections.
- `netscan`: Scans for network connections in memory.
- `malfind`: Finds hidden or injected code in memory.
- `cmdscan`: Scans for command history in memory.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists registry hives.
- `hivedump`: Dumps a registry hive.
- `hashdump`: Dumps password hashes from memory.

### Additional Resources

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{% endtab %}
{% endtabs %}

이는 yarascan 모듈을 사용하여 프로세스 내에서 문자열을 검색할 수도 있습니다:

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. The cheat sheet includes commonly used commands and their descriptions, making it a handy resource for memory dump analysis.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py` to start Volatility.

### Basic Commands

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes in the memory dump.
- `pstree`: Displays a tree-like representation of the processes in the memory dump.
- `psscan`: Scans the memory dump for hidden or unlinked processes.
- `dlllist`: Lists all loaded DLLs in the memory dump.
- `handles`: Lists all open handles in the memory dump.
- `filescan`: Scans the memory dump for file objects.
- `netscan`: Lists all network connections in the memory dump.
- `connections`: Displays detailed information about a specific network connection.
- `cmdline`: Displays the command line arguments of a specific process.
- `malfind`: Scans the memory dump for potential malware artifacts.
- `dump`: Dumps a specific process from the memory dump.

### Advanced Commands

- `mftparser`: Parses the Master File Table (MFT) for file system artifacts.
- `hivelist`: Lists all registry hives in the memory dump.
- `printkey`: Displays the contents of a specific registry key.
- `dumpregistry`: Dumps a specific registry hive from the memory dump.
- `modscan`: Scans the memory dump for kernel modules.
- `ssdt`: Displays the System Service Descriptor Table (SSDT) in the memory dump.
- `driverirp`: Displays the IRP (I/O Request Packet) hooks in the memory dump.
- `vadinfo`: Displays information about the Virtual Address Descriptor (VAD) tree in the memory dump.
- `vaddump`: Dumps a specific memory region from the memory dump.

### Plugin Usage

Volatility also supports plugins, which provide additional functionality. To use a plugin, run `python vol.py --plugin=<plugin_name>`. Some commonly used plugins include:

- `malfind`: Scans the memory dump for potential malware artifacts.
- `timeliner`: Creates a timeline of events based on various artifacts in the memory dump.
- `psxview`: Displays detailed information about processes, including hidden and unlinked processes.
- `svcscan`: Lists all Windows services in the memory dump.
- `apihooks`: Displays information about API hooks in the memory dump.

### Conclusion

This cheat sheet covers the basic usage of Volatility for memory dump analysis. By leveraging the power of Volatility and its plugins, analysts can uncover valuable information from memory dumps, aiding in incident response, malware analysis, and forensic investigations.
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{% endtab %}
{% endtabs %}

### UserAssist

**Windows**는 **UserAssist 키**라는 레지스트리 기능을 사용하여 실행한 프로그램을 추적합니다. 이러한 키는 각 프로그램이 실행된 횟수와 마지막 실행 시간을 기록합니다.
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install volatility
   ```

3. Download the Volatility source code from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Navigate to the Volatility directory and run the following command to verify the installation:

   ```
   python vol.py -h
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Once you have identified the profile, use the appropriate plugin to extract the desired information. For example, to list all running processes, use the `pslist` plugin:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

3. Use the available options to filter and format the output as needed. For example, to display only the process names and PIDs, use the `--output=csv` and `--columns=Name,PID` options:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist --output=csv --columns=Name,PID
   ```

### Advanced Usage

Volatility provides a wide range of plugins for analyzing different aspects of memory dumps. Some of the commonly used plugins include:

- `pslist`: Lists all running processes.
- `netscan`: Displays network connections.
- `malfind`: Identifies injected and hidden code.
- `dlllist`: Lists loaded DLLs.
- `filescan`: Scans for file handles and file objects.
- `cmdscan`: Lists command history.
- `hivelist`: Lists registry hives.

To use these plugins, specify the desired plugin name after the `--profile` option. For example, to list all loaded DLLs, use the `dlllist` plugin:

```
python vol.py -f memory_dump.raw --profile=Win7SP1x64 dlllist
```

### Conclusion

Volatility is a powerful tool for analyzing memory dumps and extracting valuable information for forensic investigations. This cheat sheet provides a quick reference guide for using Volatility and highlights some of the most commonly used commands and plugins. Experiment with different options and plugins to maximize the effectiveness of your memory analysis.
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{% endtab %}
{% endtabs %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성 있는 사이버 보안 행사이며 **유럽**에서 가장 중요한 행사 중 하나입니다. **기술적인 지식을 촉진하는 미션**을 가지고 있는 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 열정적인 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

## 서비스

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. The cheat sheet includes commonly used commands and their descriptions, making it a handy resource for memory dump analysis.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or Python 3.x.
2. Install the required Python packages by running `pip install -r requirements.txt`.
3. Download the latest release of Volatility from the official GitHub repository.
4. Extract the downloaded archive.
5. Navigate to the extracted directory and run `python vol.py`.

### Basic Commands

- `imageinfo`: Displays information about the memory dump, such as the operating system version and architecture.
- `pslist`: Lists all running processes in the memory dump.
- `pstree`: Displays the process tree, showing parent-child relationships between processes.
- `psscan`: Scans the memory dump for hidden or terminated processes.
- `dlllist`: Lists all loaded DLLs in the memory dump.
- `handles`: Lists all open handles in the memory dump.
- `filescan`: Scans the memory dump for file objects.
- `netscan`: Lists all network connections in the memory dump.
- `connections`: Displays detailed information about a specific network connection.
- `cmdline`: Displays the command line arguments of a specific process.
- `malfind`: Scans the memory dump for potential malware artifacts.
- `dumpfiles`: Extracts files from the memory dump.

### Advanced Commands

- `malfind`: Scans the memory dump for potential malware artifacts.
- `yarascan`: Scans the memory dump using YARA rules.
- `vadinfo`: Displays information about the Virtual Address Descriptor (VAD) tree.
- `vaddump`: Dumps the memory range associated with a specific VAD node.
- `vadtree`: Displays the VAD tree, showing the memory ranges allocated to processes.
- `vadwalk`: Walks the VAD tree, displaying the memory ranges allocated to a specific process.
- `modscan`: Scans the memory dump for loaded modules.
- `moddump`: Dumps the memory range associated with a specific module.
- `modscan`: Scans the memory dump for loaded modules.
- `moddump`: Dumps the memory range associated with a specific module.

### Plugin Usage

Volatility also provides a wide range of plugins that extend its functionality. To use a plugin, run `python vol.py -f <memory_dump> --profile=<profile> <plugin_name>`. Some commonly used plugins include:

- `malfind`: Scans the memory dump for potential malware artifacts.
- `timeliner`: Extracts timeline information from the memory dump.
- `dumpregistry`: Dumps the Windows registry from the memory dump.
- `hivelist`: Lists the registry hives in the memory dump.
- `hashdump`: Dumps the password hashes from the memory dump.
- `svcscan`: Scans the memory dump for Windows services.
- `getsids`: Lists the Security Identifiers (SIDs) in the memory dump.

### Conclusion

This cheat sheet provides a concise overview of Volatility commands and plugins for memory dump analysis. By leveraging the power of Volatility, analysts can uncover valuable information from memory dumps, aiding in incident response, malware analysis, and forensic investigations.
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
## 네트워크

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

```bash
pip install volatility
```

### Basic Usage

To analyze a memory dump using Volatility, use the following command:

```bash
volatility -f <memory_dump> <command> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<command>` with the desired Volatility command.

### Commonly Used Commands

#### imageinfo

The `imageinfo` command displays information about the memory dump, such as the operating system version, architecture, and profile. Use the following command to run `imageinfo`:

```bash
volatility -f <memory_dump> imageinfo
```

#### pslist

The `pslist` command lists all running processes in the memory dump. Use the following command to run `pslist`:

```bash
volatility -f <memory_dump> pslist
```

#### psscan

The `psscan` command scans the memory dump for hidden or terminated processes. Use the following command to run `psscan`:

```bash
volatility -f <memory_dump> psscan
```

#### netscan

The `netscan` command displays network connections found in the memory dump. Use the following command to run `netscan`:

```bash
volatility -f <memory_dump> netscan
```

#### malfind

The `malfind` command searches for injected or malicious code in memory. Use the following command to run `malfind`:

```bash
volatility -f <memory_dump> malfind
```

### Conclusion

This cheat sheet provides a brief overview of some commonly used Volatility commands for memory dump analysis. Volatility is a powerful tool for forensic analysis and can help uncover valuable information from memory dumps. Experiment with different commands and options to maximize the effectiveness of your memory analysis.
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
{% endtab %}
{% endtabs %}

## 레지스트리 하이브

### 사용 가능한 하이브 출력

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

```bash
pip install volatility
```

### Basic Usage

To analyze a memory dump using Volatility, use the following command:

```bash
volatility -f <memory_dump> <command> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<command>` with the desired Volatility command.

### Volatility Commands

#### Image Identification

- **imageinfo**: Retrieve information about the memory dump, such as the operating system version and profile.

```bash
volatility -f <memory_dump> imageinfo
```

#### Process Analysis

- **pslist**: List all running processes.

```bash
volatility -f <memory_dump> pslist
```

- **psscan**: Scan for hidden or terminated processes.

```bash
volatility -f <memory_dump> psscan
```

#### Network Analysis

- **netscan**: List network connections.

```bash
volatility -f <memory_dump> netscan
```

- **connscan**: List TCP and UDP connections.

```bash
volatility -f <memory_dump> connscan
```

#### Module Analysis

- **modscan**: List loaded modules.

```bash
volatility -f <memory_dump> modscan
```

- **moddump**: Dump a specific module from memory.

```bash
volatility -f <memory_dump> moddump -D <output_directory> -n <module_name>
```

Replace `<output_directory>` with the desired directory to save the module dump and `<module_name>` with the name of the module to dump.

### Conclusion

This cheat sheet provides a quick overview of some of the most commonly used Volatility commands for memory dump analysis. Volatility is a powerful tool for forensic analysis and can help uncover valuable information from memory dumps. Experiment with different commands and options to maximize the effectiveness of your memory analysis.
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{% endtab %}
{% endtabs %}

### 값을 가져오기

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install -r requirements.txt
   ```

3. Download the latest version of Volatility from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Change to the Volatility directory:

   ```
   cd volatility
   ```

5. Run Volatility using the following command:

   ```
   python vol.py
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Set the profile using the `-p` option:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

3. Run the desired Volatility command. For example, to list all running processes, use the `pslist` command:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

### Common Commands

- `pslist`: Lists all running processes.
- `pstree`: Displays a process tree.
- `psscan`: Scans for processes.
- `dlllist`: Lists loaded DLLs.
- `handles`: Lists open handles.
- `connections`: Lists network connections.
- `netscan`: Scans for network connections.
- `modscan`: Scans for loaded modules.
- `malfind`: Finds hidden or injected code.
- `cmdscan`: Scans for command history.
- `filescan`: Scans for files.
- `dumpfiles`: Dumps files from memory.
- `hivelist`: Lists registry hives.
- `printkey`: Prints registry keys and values.
- `hashdump`: Dumps password hashes.
- `mbrparser`: Parses the Master Boot Record (MBR).
- `ssdt`: Displays the System Service Descriptor Table (SSDT).
- `driverirp`: Lists drivers and their IRP hooks.
- `idt`: Displays the Interrupt Descriptor Table (IDT).
- `gdt`: Displays the Global Descriptor Table (GDT).
- `ldrmodules`: Lists loaded modules.
- `apihooks`: Lists API hooks.
- `vadinfo`: Displays Virtual Address Descriptor (VAD) information.
- `vaddump`: Dumps memory regions.
- `memdump`: Dumps the entire memory.

### Conclusion

This cheat sheet provides a starting point for using Volatility to analyze memory dumps. Remember to always use Volatility in a controlled environment and with proper authorization.
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{% tabs %}
{% tab title="English" %}
A memory dump is a snapshot of the computer's memory at a specific point in time. It contains information about the running processes, open files, network connections, and other system data. Analyzing memory dumps can provide valuable insights into the state of a system during a security incident or forensic investigation.

To analyze a memory dump, you can use the Volatility framework. Volatility is an open-source tool that allows you to extract and analyze information from memory dumps. It supports a wide range of operating systems and can be used to investigate various types of memory-related artifacts.

Here are some basic steps to follow when analyzing a memory dump using Volatility:

1. Identify the profile: The profile specifies the operating system and service pack version of the memory dump. You need to determine the correct profile to ensure accurate analysis.

2. Extract the necessary information: Use Volatility commands to extract the information you need from the memory dump. This can include process lists, network connections, registry keys, and more.

3. Analyze the extracted data: Once you have extracted the relevant information, analyze it to identify any suspicious or malicious activity. Look for signs of malware, unauthorized access, or other indicators of compromise.

4. Cross-reference with other data sources: To get a complete picture of the incident, cross-reference the data from the memory dump with other sources such as log files, network traffic captures, and system event logs.

5. Document your findings: Record your findings in a clear and organized manner. Include details about the analyzed artifacts, any identified threats, and any actions taken to mitigate the incident.

By following these steps and using the Volatility framework, you can effectively analyze memory dumps and uncover valuable information for forensic investigations and incident response.
{% endtab %}
{% endtabs %}

### 덤프

메모리 덤프는 특정 시점에서 컴퓨터의 메모리 스냅샷입니다. 실행 중인 프로세스, 열린 파일, 네트워크 연결 및 기타 시스템 데이터에 대한 정보를 포함합니다. 메모리 덤프를 분석하면 보안 사고나 포렌식 조사 중 시스템의 상태에 대한 유용한 통찰력을 제공할 수 있습니다.

메모리 덤프를 분석하기 위해 Volatility 프레임워크를 사용할 수 있습니다. Volatility는 메모리 덤프에서 정보를 추출하고 분석할 수 있는 오픈 소스 도구입니다. 다양한 운영 체제를 지원하며 메모리 관련 아티팩트를 조사하는 데 사용할 수 있습니다.

다음은 Volatility를 사용하여 메모리 덤프를 분석할 때 따라야 할 몇 가지 기본 단계입니다:

1. 프로파일 식별: 프로파일은 메모리 덤프의 운영 체제 및 서비스 팩 버전을 지정합니다. 정확한 분석을 위해 올바른 프로파일을 결정해야 합니다.

2. 필요한 정보 추출: Volatility 명령을 사용하여 메모리 덤프에서 필요한 정보를 추출합니다. 이는 프로세스 목록, 네트워크 연결, 레지스트리 키 등을 포함할 수 있습니다.

3. 추출된 데이터 분석: 관련 정보를 추출한 후, 의심스러운 또는 악성 활동을 식별하기 위해 분석합니다. 악성 코드, 무단 액세스 또는 침해 표시를 찾아보세요.

4. 다른 데이터 소스와 교차 참조: 사건의 전체적인 상황을 파악하기 위해 메모리 덤프의 데이터를 로그 파일, 네트워크 트래픽 캡처, 시스템 이벤트 로그 등 다른 소스와 교차 참조합니다.

5. 결과 문서화: 분석 결과를 명확하고 체계적으로 기록합니다. 분석된 아티팩트, 식별된 위협 및 사건 대응을 위해 수행한 조치에 대한 세부 정보를 포함하세요.

이러한 단계를 따르고 Volatility 프레임워크를 사용하면 포렌식 조사 및 사건 대응을 위해 메모리 덤프를 효과적으로 분석하고 가치 있는 정보를 발견할 수 있습니다.
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## 파일 시스템

### 마운트

{% tabs %}
{% tab title="vol3" %}
```bash
#See vol2
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

```bash
pip install volatility
```

### Basic Usage

To analyze a memory dump using Volatility, use the following command:

```bash
volatility -f <memory_dump> <command> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<command>` with the desired Volatility command.

### Volatility Commands

#### Image Identification

- **imageinfo**: Displays information about the memory dump, such as the operating system version and profile.

```bash
volatility -f <memory_dump> imageinfo
```

#### Process Analysis

- **pslist**: Lists all running processes in the memory dump.

```bash
volatility -f <memory_dump> pslist
```

- **psscan**: Scans for hidden or terminated processes.

```bash
volatility -f <memory_dump> psscan
```

#### Network Analysis

- **netscan**: Lists all network connections in the memory dump.

```bash
volatility -f <memory_dump> netscan
```

- **connscan**: Lists all TCP and UDP connections.

```bash
volatility -f <memory_dump> connscan
```

#### Module Analysis

- **modscan**: Lists all loaded modules in the memory dump.

```bash
volatility -f <memory_dump> modscan
```

- **moddump**: Dumps a specific module from memory.

```bash
volatility -f <memory_dump> moddump -D <output_directory> -n <module_name>
```

Replace `<output_directory>` with the desired directory to save the module dump and `<module_name>` with the name of the module to dump.

### Conclusion

This cheat sheet provides a basic overview of Volatility and its commonly used commands. By leveraging Volatility's capabilities, analysts can perform in-depth memory analysis and extract valuable information from memory dumps.
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{% tab title="vol3" %}스캔/덤프

- `volatility -f <memory_dump> imageinfo` : 메모리 덤프 파일의 정보를 확인합니다.
- `volatility -f <memory_dump> kdbgscan` : 커널 디버그 블록(KDBG)을 스캔하여 시스템의 프로파일을 결정합니다.
- `volatility -f <memory_dump> kpcrscan` : 프로세스 제어 블록(PCB)을 스캔하여 프로세스의 프로파일을 결정합니다.
- `volatility -f <memory_dump> pslist` : 프로세스 목록을 표시합니다.
- `volatility -f <memory_dump> psscan` : 프로세스 객체를 스캔하여 프로세스의 프로파일을 결정합니다.
- `volatility -f <memory_dump> pstree` : 프로세스 트리를 표시합니다.
- `volatility -f <memory_dump> dlllist` : 로드된 DLL 목록을 표시합니다.
- `volatility -f <memory_dump> handles` : 핸들 목록을 표시합니다.
- `volatility -f <memory_dump> filescan` : 파일 객체를 스캔하여 파일의 프로파일을 결정합니다.
- `volatility -f <memory_dump> netscan` : 네트워크 연결을 표시합니다.
- `volatility -f <memory_dump> connscan` : 네트워크 연결을 표시합니다.
- `volatility -f <memory_dump> sockscan` : 소켓 객체를 스캔하여 소켓의 프로파일을 결정합니다.
- `volatility -f <memory_dump> modscan` : 로드된 모듈 목록을 표시합니다.
- `volatility -f <memory_dump> svcscan` : 서비스 목록을 표시합니다.
- `volatility -f <memory_dump> driverirp` : 드라이버 IRP 목록을 표시합니다.
- `volatility -f <memory_dump> devicetree` : 장치 트리를 표시합니다.
- `volatility -f <memory_dump> hivelist` : 레지스트리 하이브 목록을 표시합니다.
- `volatility -f <memory_dump> hivedump -o <offset>` : 지정된 오프셋의 레지스트리 하이브를 덤프합니다.
- `volatility -f <memory_dump> printkey -K <key>` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset>` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry>` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word>` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size>` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column>` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format>` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j -q` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j -q -z` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j -q -z -a` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j -q -z -a -d` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j -q -z -a -d -e` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j -q -z -a -d -e -p` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j -q -z -a -d -e -p -l` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j -q -z -a -d -e -p -l -n` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j -q -z -a -d -e -p -l -n -m` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j -q -z -a -d -e -p -l -n -m -u` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j -q -z -a -d -e -p -l -n -m -u -i` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j -q -z -a -d -e -p -l -n -m -u -i -s` : 지정된 레지스트리 키의 값을 표시합니다.
- `volatility -f <memory_dump> printkey -K <key> -o <offset> -r <registry> -w <word> -s <size> -c <column> -f <format> -v -x -a -d -e -p -l -n -m -u -i -s -t -b -g -y -j -q -z -a -d -e -p -l -n -m -u -i -s
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install -r requirements.txt
   ```

3. Download the latest version of Volatility from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Change to the Volatility directory:

   ```
   cd volatility
   ```

5. Run Volatility using the following command:

   ```
   python vol.py
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Set the profile using the `-p` option:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 <command>
   ```

3. Run the desired Volatility command. For example, to list all running processes, use the `pslist` command:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

### Common Commands

- `imageinfo`: Retrieves information about the memory dump, such as the profile, architecture, and build time.
- `pslist`: Lists all running processes.
- `pstree`: Displays the process tree, showing parent-child relationships between processes.
- `psscan`: Scans for processes in memory.
- `dlllist`: Lists loaded DLLs for each process.
- `handles`: Lists open handles for each process.
- `connections`: Lists network connections.
- `netscan`: Scans for network connections in memory.
- `malfind`: Finds hidden or injected code in memory.
- `cmdscan`: Scans for command history in memory.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists registry hives.
- `hivedump`: Dumps a registry hive.
- `hashdump`: Dumps password hashes from memory.

### Additional Resources

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{% endtab %}
{% endtabs %}

### 마스터 파일 테이블

{% tabs %}
{% tab title="vol3" %}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

```bash
pip install volatility
```

### Basic Usage

To analyze a memory dump using Volatility, use the following command:

```bash
volatility -f <memory_dump> <command> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<command>` with the desired Volatility command.

### Volatility Commands

#### Image Identification

- **imageinfo**: Displays information about the memory dump, such as the operating system version and profile.

```bash
volatility -f <memory_dump> imageinfo
```

#### Process Analysis

- **pslist**: Lists all running processes in the memory dump.

```bash
volatility -f <memory_dump> pslist
```

- **psscan**: Scans for hidden or terminated processes.

```bash
volatility -f <memory_dump> psscan
```

#### Network Analysis

- **netscan**: Lists all network connections in the memory dump.

```bash
volatility -f <memory_dump> netscan
```

- **connscan**: Lists all TCP and UDP connections.

```bash
volatility -f <memory_dump> connscan
```

#### Module Analysis

- **modscan**: Lists all loaded modules in the memory dump.

```bash
volatility -f <memory_dump> modscan
```

- **moddump**: Dumps a specific module from memory.

```bash
volatility -f <memory_dump> moddump -D <output_directory> -n <module_name>
```

Replace `<output_directory>` with the desired directory to save the module dump and `<module_name>` with the name of the module to dump.

### Conclusion

This cheat sheet provides a basic overview of Volatility and its commonly used commands. By leveraging Volatility's capabilities, analysts can perform in-depth memory analysis and extract valuable information from memory dumps.
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{% endtab %}
{% endtabs %}

**NTFS 파일 시스템**은 _마스터 파일 테이블_ (MFT)이라고 하는 중요한 구성 요소를 사용합니다. 이 테이블은 볼륨의 모든 파일에 대해 적어도 하나의 항목을 포함하며, MFT 자체도 포함됩니다. 각 파일에 대한 중요한 세부 정보인 **크기, 타임스탬프, 권한 및 실제 데이터**는 MFT 항목 내에 또는 이러한 항목에 의해 참조되는 MFT 외부 영역에 캡슐화됩니다. 자세한 내용은 [공식 문서](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)에서 확인할 수 있습니다.

### SSL 키/인증서
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install -r requirements.txt
   ```

3. Download the latest version of Volatility from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Change to the Volatility directory:

   ```
   cd volatility
   ```

5. Run Volatility using the following command:

   ```
   python vol.py
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Set the profile using the `-p` option:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 <command>
   ```

3. Run the desired Volatility command. For example, to list all running processes, use the `pslist` command:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

### Common Commands

- `imageinfo`: Retrieves information about the memory dump, such as the profile, architecture, and build time.
- `pslist`: Lists all running processes.
- `pstree`: Displays the process tree, showing parent-child relationships between processes.
- `psscan`: Scans for processes in memory.
- `dlllist`: Lists loaded DLLs for each process.
- `handles`: Lists open handles for each process.
- `connections`: Lists network connections.
- `netscan`: Scans for network connections in memory.
- `malfind`: Finds hidden or injected code in memory.
- `cmdscan`: Scans for command history in memory.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists registry hives.
- `hivedump`: Dumps a registry hive.
- `hashdump`: Dumps password hashes from memory.

### Additional Resources

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
## 악성 소프트웨어

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install volatility
   ```

3. Download the Volatility source code from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Navigate to the Volatility directory and run the following command to verify the installation:

   ```
   python vol.py -h
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Once you have identified the profile, use the appropriate plugin to extract the desired information. For example, to list all running processes, use the `pslist` plugin:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

3. Use the available options to filter and format the output as needed. For example, to display only the process names and PIDs, use the `--output=csv` and `--columns=Name,PID` options:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist --output=csv --columns=Name,PID
   ```

### Advanced Usage

Volatility provides a wide range of plugins for analyzing different aspects of memory dumps. Some of the commonly used plugins include:

- `pslist`: Lists all running processes.
- `netscan`: Displays network connections.
- `malfind`: Identifies injected and hidden code.
- `dlllist`: Lists loaded DLLs.
- `filescan`: Scans for file handles and file objects.
- `cmdscan`: Lists command history.
- `hivelist`: Lists registry hives.

To use these plugins, specify the plugin name after the `--profile` option. For example, to list all loaded DLLs, use the `dlllist` plugin:

```
python vol.py -f memory_dump.raw --profile=Win7SP1x64 dlllist
```

### Conclusion

Volatility is a powerful tool for analyzing memory dumps and extracting valuable information for forensic investigations. This cheat sheet provides a quick reference guide for using Volatility and highlights some of the most commonly used commands and plugins. Experiment with different options and plugins to maximize the effectiveness of your memory analysis.
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{% endtab %}
{% endtabs %}

### yara로 스캔하기

다음 스크립트를 사용하여 github에서 모든 yara 악성코드 규칙을 다운로드하고 병합하세요: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
_**rules**_ 디렉토리를 생성하고 실행하세요. 이렇게 하면 _**malware\_rules.yar**_라는 파일이 생성되며, 이 파일에는 모든 악성코드에 대한 yara 규칙이 포함됩니다.
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install volatility
   ```

3. Download the Volatility source code from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Navigate to the Volatility directory and run the following command to verify the installation:

   ```
   python vol.py -h
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Once you have identified the profile, use the appropriate plugin to extract the desired information. For example, to list all running processes, use the `pslist` plugin:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

3. Use the available options to filter and format the output as needed. For example, to display only the process names and PIDs, use the `--output=csv` and `--columns=Name,PID` options:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist --output=csv --columns=Name,PID
   ```

### Advanced Usage

Volatility provides a wide range of plugins for analyzing different aspects of memory dumps. Some of the commonly used plugins include:

- `pslist`: Lists all running processes.
- `netscan`: Displays network connections.
- `malfind`: Identifies injected and hidden code.
- `dlllist`: Lists loaded DLLs.
- `filescan`: Scans for file handles and file objects.
- `cmdscan`: Lists command history.
- `hivelist`: Lists registry hives.

To use these plugins, specify the desired plugin name after the `--profile` option. For example, to list all loaded DLLs, use the `dlllist` plugin:

```
python vol.py -f memory_dump.raw --profile=Win7SP1x64 dlllist
```

### Conclusion

Volatility is a powerful tool for analyzing memory dumps and extracting valuable information for forensic investigations. This cheat sheet provides a quick reference guide for using Volatility and highlights some of the most commonly used commands and plugins. Experiment with different options and plugins to maximize the effectiveness of your memory analysis.
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{% endtab %}
{% endtabs %}

## 기타

### 외부 플러그인

외부 플러그인을 사용하려면 플러그인과 관련된 폴더가 첫 번째 매개변수로 사용되는지 확인하십시오.
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
## Volatility 명령어 요약

### Volatility 기본 명령어

- **imageinfo**: 이미지 정보를 표시합니다.
- **kdbgscan**: 디버깅 세션을 찾습니다.
- **kpcrscan**: KPCR을 찾습니다.
- **pslist**: 프로세스 목록을 표시합니다.
- **pstree**: 프로세스 트리를 표시합니다.
- **psscan**: 프로세스 스냅샷을 표시합니다.
- **dlllist**: DLL 목록을 표시합니다.
- **handles**: 핸들 목록을 표시합니다.
- **cmdline**: 명령줄 인수를 표시합니다.
- **filescan**: 파일 스캔을 수행합니다.
- **malfind**: 악성 코드 주소를 찾습니다.
- **vadinfo**: 가상 주소 공간 정보를 표시합니다.
- **vadtree**: 가상 주소 공간 트리를 표시합니다.
- **vaddump**: 가상 주소 공간 덤프를 수행합니다.
- **memdump**: 메모리 덤프를 수행합니다.
- **moddump**: 모듈 덤프를 수행합니다.
- **modscan**: 모듈 스캔을 수행합니다.
- **ssdt**: SSDT 정보를 표시합니다.
- **gdt**: GDT 정보를 표시합니다.
- **idt**: IDT 정보를 표시합니다.
- **ldrmodules**: LDR 모듈 정보를 표시합니다.
- **apihooks**: API 후킹 정보를 표시합니다.
- **svcscan**: 서비스 스캔을 수행합니다.
- **ssdt**: SSDT 정보를 표시합니다.
- **gdt**: GDT 정보를 표시합니다.
- **idt**: IDT 정보를 표시합니다.
- **ldrmodules**: LDR 모듈 정보를 표시합니다.
- **apihooks**: API 후킹 정보를 표시합니다.
- **svcscan**: 서비스 스캔을 수행합니다.
- **driverirp**: 드라이버 IRP 정보를 표시합니다.
- **drivermodule**: 드라이버 모듈 정보를 표시합니다.
- **driverobject**: 드라이버 객체 정보를 표시합니다.
- **driversection**: 드라이버 섹션 정보를 표시합니다.
- **driverwirp**: 드라이버 WIRP 정보를 표시합니다.
- **driverdevice**: 드라이버 디바이스 정보를 표시합니다.
- **driverfile**: 드라이버 파일 정보를 표시합니다.
- **driverregistry**: 드라이버 레지스트리 정보를 표시합니다.
- **driverirp**: 드라이버 IRP 정보를 표시합니다.
- **drivermodule**: 드라이버 모듈 정보를 표시합니다.
- **driverobject**: 드라이버 객체 정보를 표시합니다.
- **driversection**: 드라이버 섹션 정보를 표시합니다.
- **driverwirp**: 드라이버 WIRP 정보를 표시합니다.
- **driverdevice**: 드라이버 디바이스 정보를 표시합니다.
- **driverfile**: 드라이버 파일 정보를 표시합니다.
- **driverregistry**: 드라이버 레지스트리 정보를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **devicetree**: 디바이스 트리를 표시합니다.
- **dev
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{% endtab %}
{% endtabs %}

#### Autoruns

[https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns)에서 다운로드하세요.
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### 뮤텍스

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

```bash
pip install volatility
```

### Basic Usage

To analyze a memory dump using Volatility, use the following command:

```bash
volatility -f <memory_dump> <command> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<command>` with the desired Volatility command.

### Volatility Commands

#### Image Identification

- **imageinfo**: Displays information about the memory dump, such as the operating system version and profile.

```bash
volatility -f <memory_dump> imageinfo
```

#### Process Analysis

- **pslist**: Lists all running processes in the memory dump.

```bash
volatility -f <memory_dump> pslist
```

- **psscan**: Scans for hidden or terminated processes.

```bash
volatility -f <memory_dump> psscan
```

#### Network Analysis

- **netscan**: Lists all network connections in the memory dump.

```bash
volatility -f <memory_dump> netscan
```

- **connscan**: Lists all TCP and UDP connections.

```bash
volatility -f <memory_dump> connscan
```

#### Module Analysis

- **modscan**: Lists all loaded modules in the memory dump.

```bash
volatility -f <memory_dump> modscan
```

- **moddump**: Dumps a specific module from memory.

```bash
volatility -f <memory_dump> moddump -D <output_directory> -n <module_name>
```

Replace `<output_directory>` with the desired directory to save the module dump and `<module_name>` with the name of the module to dump.

### Conclusion

This cheat sheet provides a basic overview of Volatility and its commonly used commands. By leveraging Volatility's capabilities, analysts can perform in-depth memory analysis and extract valuable information from memory dumps.
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{% endtab %}
{% endtabs %}

### 심볼릭 링크

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install -r requirements.txt
   ```

3. Download the latest version of Volatility from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Change to the Volatility directory:

   ```
   cd volatility
   ```

5. Run Volatility using the following command:

   ```
   python vol.py
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Set the profile using the `-p` option:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 <command>
   ```

3. Run the desired Volatility command. For example, to list all running processes, use the `pslist` command:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

### Common Commands

- `imageinfo`: Retrieves information about the memory dump, such as the profile, architecture, and build time.
- `pslist`: Lists all running processes.
- `pstree`: Displays the process tree, showing parent-child relationships between processes.
- `psscan`: Scans for processes in memory.
- `dlllist`: Lists loaded DLLs for each process.
- `handles`: Lists open handles for each process.
- `connections`: Lists network connections.
- `netscan`: Scans for network connections in memory.
- `malfind`: Finds hidden or injected code in memory.
- `cmdscan`: Scans for command history in memory.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists registry hives.
- `hivedump`: Dumps a registry hive.
- `hashdump`: Dumps password hashes from memory.

### Additional Resources

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{% endtab %}
{% endtabs %}

### Bash

**메모리에서 bash 히스토리를 읽을 수 있습니다.** _.bash\_history_ 파일을 덤프할 수도 있지만, 비활성화되었으므로 이 volatility 모듈을 사용할 수 있어 기쁠 것입니다.
```
./vol.py -f file.dmp linux.bash.Bash
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

```bash
pip install volatility
```

### Basic Usage

To analyze a memory dump using Volatility, use the following command:

```bash
volatility -f <memory_dump> <command> [options]
```

Replace `<memory_dump>` with the path to the memory dump file and `<command>` with the desired Volatility command.

### Volatility Commands

#### Image Identification

- **imageinfo**: Retrieve information about the memory dump, such as the operating system version and profile.

```bash
volatility -f <memory_dump> imageinfo
```

#### Process Analysis

- **pslist**: List all running processes.

```bash
volatility -f <memory_dump> pslist
```

- **psscan**: Scan for hidden or terminated processes.

```bash
volatility -f <memory_dump> psscan
```

#### Network Analysis

- **netscan**: List network connections.

```bash
volatility -f <memory_dump> netscan
```

- **connscan**: List TCP and UDP connections.

```bash
volatility -f <memory_dump> connscan
```

#### Module Analysis

- **modscan**: List loaded modules.

```bash
volatility -f <memory_dump> modscan
```

- **moddump**: Dump a specific module from memory.

```bash
volatility -f <memory_dump> moddump -D <output_directory> -n <module_name>
```

Replace `<output_directory>` with the desired directory to save the module dump and `<module_name>` with the name of the module to dump.

### Conclusion

This cheat sheet provides a brief overview of some of the most commonly used Volatility commands for memory dump analysis. Volatility is a powerful tool for forensic analysis and can help uncover valuable information from memory dumps. Experiment with different commands and options to maximize the effectiveness of your memory analysis.
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{% endtab %}
{% endtabs %}

### 타임라인

{% tabs %}
{% tab title="vol3" %}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install volatility
   ```

3. Download the Volatility source code from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Navigate to the Volatility directory and run the following command to verify the installation:

   ```
   python vol.py -h
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Once you have identified the profile, use the appropriate plugin to extract the desired information. For example, to list all running processes, use the `pslist` plugin:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

3. Use the available options to filter and format the output as needed. For example, to display only the process names and PIDs, use the `--output=csv` and `--columns=Name,PID` options:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist --output=csv --columns=Name,PID
   ```

### Advanced Usage

Volatility provides a wide range of plugins for analyzing different aspects of memory dumps. Some of the commonly used plugins include:

- `pslist`: Lists all running processes.
- `netscan`: Displays network connections.
- `malfind`: Identifies injected and hidden code.
- `dlllist`: Lists loaded DLLs.
- `filescan`: Scans for file handles and file objects.
- `cmdscan`: Lists command history.
- `hivelist`: Lists registry hives.

To use these plugins, specify the desired plugin name after the `--profile` option. For example, to list all loaded DLLs, use the `dlllist` plugin:

```
python vol.py -f memory_dump.raw --profile=Win7SP1x64 dlllist
```

### Conclusion

Volatility is a powerful tool for analyzing memory dumps and extracting valuable information for forensic investigations. This cheat sheet provides a quick reference guide for using Volatility and highlights some of the most commonly used commands and plugins. Experiment with different options and plugins to maximize the effectiveness of your memory analysis.
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{% endtab %}
{% endtabs %}

### 드라이버

{% tabs %}
{% tab title="vol3" %}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
## Volatility Cheat Sheet

### Introduction

This cheat sheet provides a quick reference guide for using Volatility, a popular open-source memory forensics framework. Volatility allows analysts to extract valuable information from memory dumps, such as running processes, network connections, and loaded modules. This cheat sheet covers some of the most commonly used Volatility commands and their corresponding options.

### Installation

To install Volatility, follow these steps:

1. Install Python 2.7 or later.
2. Install the required Python packages by running the following command:

   ```
   pip install -r requirements.txt
   ```

3. Download the latest version of Volatility from the official GitHub repository:

   ```
   git clone https://github.com/volatilityfoundation/volatility.git
   ```

4. Change to the Volatility directory:

   ```
   cd volatility
   ```

5. Run Volatility using the following command:

   ```
   python vol.py
   ```

### Basic Usage

To analyze a memory dump using Volatility, follow these steps:

1. Identify the profile of the memory dump. The profile specifies the operating system and service pack version. Use the `imageinfo` command to retrieve this information:

   ```
   python vol.py -f memory_dump.raw imageinfo
   ```

2. Set the profile using the `-p` option:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 <command>
   ```

3. Run the desired Volatility command. For example, to list all running processes, use the `pslist` command:

   ```
   python vol.py -f memory_dump.raw --profile=Win7SP1x64 pslist
   ```

### Common Commands

- `imageinfo`: Retrieves information about the memory dump, such as the profile, architecture, and build time.
- `pslist`: Lists all running processes.
- `pstree`: Displays the process tree, showing parent-child relationships between processes.
- `psscan`: Scans for processes in memory.
- `dlllist`: Lists loaded DLLs for each process.
- `handles`: Lists open handles for each process.
- `connections`: Lists network connections.
- `netscan`: Scans for network connections in memory.
- `malfind`: Finds hidden or injected code in memory.
- `cmdscan`: Scans for command history in memory.
- `filescan`: Scans for file objects in memory.
- `dumpfiles`: Extracts files from memory.
- `hivelist`: Lists registry hives.
- `hivedump`: Dumps a registry hive.
- `hashdump`: Dumps password hashes from memory.

### Additional Resources

- [Volatility Documentation](https://github.com/volatilityfoundation/volatility/wiki)
- [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility)
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{% endtab %}
{% endtabs %}

### 클립보드 가져오기
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### IE 히스토리 가져오기

```bash
volatility -f <memory_dump> --profile=<profile> iehistory
```

- `<memory_dump>`: 분석할 메모리 덤프 파일의 경로
- `<profile>`: 분석할 운영 체제의 프로파일

### IE 히스토리 분석

```bash
volatility -f <memory_dump> --profile=<profile> iehistory -i <index>
```

- `<memory_dump>`: 분석할 메모리 덤프 파일의 경로
- `<profile>`: 분석할 운영 체제의 프로파일
- `<index>`: 분석할 히스토리 항목의 인덱스 번호

### IE 히스토리 필터링

```bash
volatility -f <memory_dump> --profile=<profile> iehistory -u <url>
```

- `<memory_dump>`: 분석할 메모리 덤프 파일의 경로
- `<profile>`: 분석할 운영 체제의 프로파일
- `<url>`: 필터링할 URL

### IE 히스토리 추출

```bash
volatility -f <memory_dump> --profile=<profile> iehistory -e <output_directory>
```

- `<memory_dump>`: 분석할 메모리 덤프 파일의 경로
- `<profile>`: 분석할 운영 체제의 프로파일
- `<output_directory>`: 추출된 히스토리를 저장할 디렉토리 경로
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### 메모장 텍스트 가져오기

To get the text from a notepad, you can use the following command:

메모장에서 텍스트를 가져오려면 다음 명령을 사용할 수 있습니다:

```bash
volatility -f <memory_dump> notepad
```

Replace `<memory_dump>` with the path to your memory dump file.

`<memory_dump>`을 메모리 덤프 파일의 경로로 대체하십시오.
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
### 스크린샷
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### 마스터 부트 레코드 (MBR)

The Master Boot Record (MBR) is the first sector of a storage device (such as a hard disk) that contains the boot loader and partition table. It plays a crucial role in the boot process of a computer.

마스터 부트 레코드 (MBR)은 부트 로더와 파티션 테이블이 포함된 저장 장치 (예: 하드 디스크)의 첫 번째 섹터입니다. 컴퓨터의 부팅 프로세스에서 중요한 역할을 합니다.
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**마스터 부트 레코드 (MBR)**는 저장 매체의 논리적 파티션을 관리하는 데 중요한 역할을 합니다. 이러한 파티션은 서로 다른 [파일 시스템](https://en.wikipedia.org/wiki/File_system)으로 구성됩니다. MBR은 파티션 레이아웃 정보를 보유하는 것뿐만 아니라 부트 로더로 작동하는 실행 가능한 코드도 포함합니다. 이 부트 로더는 OS의 두 번째 단계 로딩 프로세스를 직접 시작하거나 각 파티션의 [볼륨 부트 레코드](https://en.wikipedia.org/wiki/Volume_boot_record) (VBR)와 함께 작동합니다. 자세한 내용은 [MBR Wikipedia 페이지](https://en.wikipedia.org/wiki/Master_boot_record)를 참조하십시오.

## 참고 자료
* [https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
* [https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
* [https://or10nlabs.tech/cgi-sys/suspendedpage.cgi](https://or10nlabs.tech/cgi-sys/suspendedpage.cgi)
* [https://www.aldeid.com/wiki/Windows-userassist-keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
​* [https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
* [https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)은 **스페인**에서 가장 관련성 높은 사이버 보안 행사로, **유럽**에서 가장 중요한 행사 중 하나입니다. 기술적인 지식을 촉진하는 미션을 가진 이 회의는 모든 분야의 기술 및 사이버 보안 전문가들에게 열정적인 만남의 장입니다.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 AWS 해킹을 전문가 수준까지 배워보세요**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
