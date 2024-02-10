# FISSURE - RF 프레임워크

**주파수 독립 SDR 기반 신호 이해 및 역공학**

FISSURE는 신호 감지 및 분류, 프로토콜 탐색, 공격 실행, IQ 조작, 취약점 분석, 자동화 및 AI/ML을 위한 후크를 갖춘 모든 기술 수준을 위한 오픈 소스 RF 및 역공학 프레임워크입니다. 이 프레임워크는 소프트웨어 모듈, 라디오, 프로토콜, 신호 데이터, 스크립트, 플로우 그래프, 참조 자료 및 타사 도구의 신속한 통합을 촉진하기 위해 구축되었습니다. FISSURE는 소프트웨어를 한 곳에 유지하고 특정 Linux 배포판에 대한 동일한 검증된 기준 구성을 공유하면서 팀이 쉽게 업무에 적응할 수 있도록 지원하는 워크플로우 활성화 도구입니다.

FISSURE와 함께 제공되는 프레임워크 및 도구는 RF 에너지의 존재를 감지하고 신호의 특성을 이해하며 샘플을 수집하고 분석하며, 전송 및 주입 기술을 개발하고 사용자 정의 페이로드 또는 메시지를 작성하는 데 사용됩니다. FISSURE에는 식별, 패킷 작성 및 퍼징을 지원하기 위한 프로토콜 및 신호 정보의 라이브러리가 포함되어 있습니다. 온라인 아카이브 기능을 사용하여 신호 파일을 다운로드하고 트래픽을 시뮬레이션하고 시스템을 테스트하기 위한 재생 목록을 작성할 수 있습니다.

친숙한 Python 코드베이스와 사용자 인터페이스를 통해 초보자들은 RF 및 역공학에 관련된 인기있는 도구와 기술에 대해 빠르게 학습할 수 있습니다. 사이버 보안 및 엔지니어링 교육자는 내장된 자료를 활용하거나 프레임워크를 사용하여 자신의 실제 응용 프로그램을 시연할 수 있습니다. 개발자와 연구원은 FISSURE를 일상 업무에 사용하거나 혁신적인 솔루션을 보다 넓은 관객에게 노출시키기 위해 사용할 수 있습니다. FISSURE의 커뮤니티에서 인식과 사용이 증가함에 따라 기능의 범위와 포함 기술의 폭도 확장될 것입니다.

**추가 정보**

* [AIS 페이지](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 슬라이드](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 논문](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 비디오](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [해킹 채팅 기록](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## 시작하기

**지원되는 운영 체제**

FISSURE에는 파일 탐색을 쉽게하고 코드 중복을 줄이기 위해 세 가지 브랜치가 있습니다. Python2\_maint-3.7 브랜치는 Python2, PyQt4 및 GNU Radio 3.7을 기반으로 한 코드베이스를 포함하고 있으며, Python3\_maint-3.8 브랜치는 Python3, PyQt5 및 GNU Radio 3.8을 기반으로 한 코드베이스를 포함하고 있으며, Python3\_maint-3.10 브랜치는 Python3, PyQt5 및 GNU Radio 3.10을 기반으로 한 코드베이스를 포함하고 있습니다.

|   운영 체제   |   FISSURE 브랜치   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**진행 중인 작업 (베타)**

이러한 운영 체제는 아직 베타 상태입니다. 개발 중이며 일부 기능이 누락되었음을 알 수 있습니다. 설치 프로그램의 항목은 기존 프로그램과 충돌할 수 있거나 상태가 제거될 때까지 설치에 실패할 수 있습니다.

|     운영 체제     |    FISSURE 브랜치   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

참고: 일부 소프트웨어 도구는 모든 운영 체제에서 작동하지 않을 수 있습니다. [소프트웨어 및 충돌](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)를 참조하십시오.

**설치**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
이것은 PyQt 소프트웨어 설치 GUI를 시작하기 위해 필요한 종속성을 설치합니다. 

다음으로, 운영 체제와 가장 일치하는 옵션을 선택하십시오 (운영 체제가 옵션과 일치하는 경우 자동으로 감지됩니다).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

기존 충돌을 피하기 위해 깨끗한 운영 체제에 FISSURE를 설치하는 것이 좋습니다. FISSURE 내에서 다양한 도구를 사용할 때 오류를 피하기 위해 모든 권장 체크박스 (기본 버튼)를 선택하십시오. 설치 중에는 권한 상승 및 사용자 이름을 요청하는 여러 프롬프트가 표시됩니다. 항목 끝에 "Verify" 섹션이 포함된 경우 설치 프로그램은 해당 명령을 실행하고 명령에 의해 생성된 오류에 따라 체크박스 항목을 녹색 또는 빨간색으로 강조 표시합니다. "Verify" 섹션이 없는 선택된 항목은 설치 후에도 검은색으로 유지됩니다.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**사용법**

터미널을 열고 다음을 입력하세요:
```
fissure
```
## 세부사항

**구성요소**

* 대시보드
* 중앙 허브 (HIPRFISR)
* 대상 신호 식별 (TSI)
* 프로토콜 탐색 (PD)
* 플로우 그래프 및 스크립트 실행기 (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**기능**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**신호 탐지기**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ 조작**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**신호 조회**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**패턴 인식**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**공격**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**퍼징**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**신호 재생 목록**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**이미지 갤러리**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**패킷 조작**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy 통합**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC 계산기**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**로그 기록**_            |

**하드웨어**

다음은 "지원되는" 하드웨어 목록입니다. 각 하드웨어는 다양한 수준의 통합을 지원합니다:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 어댑터
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## 레슨

FISSURE에는 다양한 기술과 기법에 익숙해지기 위한 여러 가이드가 포함되어 있습니다. 많은 가이드에는 FISSURE에 통합된 다양한 도구를 사용하는 단계가 포함되어 있습니다.

* [레슨1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [레슨2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [레슨3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [레슨4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [레슨5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [레슨6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [레슨7: 데이터 유형](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [레슨8: 사용자 정의 GNU Radio 블록](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [레슨9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [레슨10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [레슨11: Wi-Fi 도구](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## 로드맵

* [ ] 더 많은 하드웨어 유형, RF 프로토콜, 신호 매개변수, 분석 도구 추가
* [ ] 더 많은 운영 체제 지원
* [ ] FISSURE 주변의 수업 자료 개발 (RF 공격, Wi-Fi, GNU Radio, PyQt 등)
* [ ] 선택 가능한 AI/ML 기술을 사용한 신호 조건부, 특징 추출 및 신호 분류기 구현
* [ ] 알려지지 않은 신호에서 비트 스트림을 생성하기 위한 재귀적인 복조 메커니즘 구현
* [ ] 주요 FISSURE 구성 요소를 일반적인 센서 노드 배치 체계로 전환

## 기여

FISSURE를 개선하기 위한 제안은 강력히 권장됩니다. [토론](https://github.com/ainfosec/FISSURE/discussions) 페이지나 Discord 서버에서 의견을 남겨주시기 바랍니다. 다음과 관련된 생각이 있다면 알려주세요:

* 새로운 기능 제안 및 디자인 변경
* 소프트웨어 도구와 설치 단계
* 새로운 레슨 또는 기존 레슨에 대한 추가 자료
* 관심 있는 RF 프로토콜
* 통합을 위한 더 많은 하드웨어 및 SDR 유형
* Python에서 IQ 분석 스크립트
* 설치 수정 및 개선

FISSURE를 개선하기 위한 기여는 그 개발을 가속화하는 데 중요합니다. 기여해주시는 모든 분들께 감사드립니다. 코드 개발을 통해 기여하고자 하는 경우, 저장소를 포크하고 풀 리퀘스트를 생성해주세요:

1. 프로젝트를 포크합니다.
2. 기능 브랜치를 생성합니다 (`git checkout -b feature/AmazingFeature`).
3. 변경 사항을 커밋합니다 (`git commit -m 'Add some AmazingFeature'`).
4. 브랜치를 푸시합니다 (`git push origin feature/AmazingFeature`).
5. 풀 리퀘스트를 엽니다.

버그에 대한 주의를 환기시키기 위해 [이슈](https://github.com/ainfosec/FISSURE/issues)를 생성하는 것도 환영합니다.

## 협업

FISSURE 협업 기회를 제안하고 형식화하기 위해 확실한 정보 보안, Inc. (AIS) 비즈니스 개발팀에 문의하여 소프트웨어 통합에 시간을 할애하거나 AIS의 역량 있는 인재들이 기술적인 도전에 대한 솔루션을 개발하거나 FISSURE를 다른 플랫폼/응용 프로그램에 통합하는 등의 협력 기회를 협의해주세요.

## 라이선스

GPL-3.0

라이선스 세부사항은 LICENSE 파일을 참조하세요.
## 연락처

Discord 서버 가입: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter 팔로우: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

비즈니스 개발 - Assured Information Security, Inc. - bd@ainfosec.com

## 크레딧

다음 개발자들에게 감사의 인사를 전합니다:

[크레딧](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## 감사의 말

이 프로젝트에 기여한 Dr. Samuel Mantravadi와 Joseph Reith에게 특별한 감사를 전합니다.
