# FISSURE - The RF Framework

**Qa'Hom SDR-based Signal Understanding and Reverse Engineering**

FISSURE Hoch open-source RF je reverse engineering framework Hoch designed Hoch all skill levels Hoch hooks Hoch signal detection je classification, protocol discovery, attack execution, IQ manipulation, vulnerability analysis, automation, je AI/ML. Hoch framework Hoch built Hoch promote Hoch rapid integration Hoch software modules, radios, protocols, signal data, scripts, flow graphs, reference material, je third-party tools. FISSURE Hoch workflow enabler Hoch keeps software Hoch one location je allows teams Hoch effortlessly get up Hoch speed while sharing Hoch same proven baseline configuration Hoch specific Linux distributions.

Hoch framework je tools Hoch included Hoch FISSURE Hoch designed Hoch detect Hoch presence Hoch RF energy, understand Hoch characteristics Hoch signal, collect je analyze samples, develop transmit je/or injection techniques, je craft custom payloads je messages. FISSURE Hoch growing library Hoch protocol je signal information Hoch assist Hoch identification, packet crafting, je fuzzing. Online archive capabilities Hoch exist Hoch download signal files je build playlists Hoch simulate traffic je test systems.

Hoch friendly Python codebase je user interface allows beginners Hoch quickly learn about popular tools je techniques involving RF je reverse engineering. Educators Hoch cybersecurity je engineering can take advantage Hoch built-in material je utilize Hoch framework Hoch demonstrate their own real-world applications. Developers je researchers can use FISSURE Hoch their daily tasks je Hoch expose their cutting-edge solutions Hoch a wider audience. As awareness je usage Hoch FISSURE grows Hoch the community, so will Hoch extent Hoch its capabilities je Hoch breadth Hoch the technology it encompasses.

**Additional Information**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**Supported**

There are three branches within FISSURE to make file navigation easier and reduce code redundancy. The Python2\_maint-3.7 branch contains a codebase built around Python2, PyQt4, je GNU Radio 3.7; the Python3\_maint-3.8 branch is built around Python3, PyQt5, je GNU Radio 3.8; je the Python3\_maint-3.10 branch is built around Python3, PyQt5, je GNU Radio 3.10.

|   Operating System   |   FISSURE Branch   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**In-Progress (beta)**

These operating systems are still in beta status. They are under development je several features are known to be missing. Items Hoch the installer might conflict with existing programs je fail Hoch install until Hoch status Hoch removed.

|     Operating System     |    FISSURE Branch   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Note: Certain software tools do not work for every OS. Refer Hoch [Software je Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
**Usage**

Open a terminal and enter:

**Usage**

Open a terminal and enter:

**Usage**

Open a terminal and enter:
```
fissure
```
## Details

**Components**

* **Dashboard** (Qa'vIn)
* **Central Hub** (HIPRFISR) (Qa'vIn Hub)
* **Target Signal Identification** (TSI) (Qa'vIn Signal Identification)
* **Protocol Discovery** (PD) (Qa'vIn Discovery)
* **Flow Graph & Script Executor** (FGE) (Qa'vIn Flow Graph & Script Executor)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capabilities**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

The following is a list of "supported" hardware with varying levels of integration:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lessons

FISSURE comes with several helpful guides to become familiar with different technologies and techniques. Many include steps for using various tools that are integrated into FISSURE.

* [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lesson2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lesson3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lesson4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lesson5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lesson7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lesson8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lesson10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lesson11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Roadmap

* [ ] Add more hardware types, RF protocols, signal parameters, analysis tools
* [ ] Support more operating systems
* [ ] Develop class material around FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt, etc.)
* [ ] Create a signal conditioner, feature extractor, and signal classifier with selectable AI/ML techniques
* [ ] Implement recursive demodulation mechanisms for producing a bitstream from unknown signals
* [ ] Transition the main FISSURE components to a generic sensor node deployment scheme

## Contributing

Suggestions for improving FISSURE are strongly encouraged. Leave a comment in the [Discussions](https://github.com/ainfosec/FISSURE/discussions) page or in the Discord Server if you have any thoughts regarding the following:

* New feature suggestions and design changes
* Software tools with installation steps
* New lessons or additional material for existing lessons
* RF protocols of interest
* More hardware and SDR types for integration
* IQ analysis scripts in Python
* Installation corrections and improvements

Contributions to improve FISSURE are crucial to expediting its development. Any contributions you make are greatly appreciated. If you wish to contribute through code development, please fork the repo and create a pull request:

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a pull request

Creating [Issues](https://github.com/ainfosec/FISSURE/issues) to bring attention to bugs is also welcomed.

## Collaborating

Contact Assured Information Security, Inc. (AIS) Business Development to propose and formalize any FISSURE collaboration opportunities–whether that is through dedicating time towards integrating your software, having the talented people at AIS develop solutions for your technical challenges, or integrating FISSURE into other platforms/applications.

## License

GPL-3.0

For license details, see LICENSE file.
## Qapla'

Join the Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Follow on Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Credits

We acknowledge and are grateful to these developers:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Acknowledgments

Special thanks to Dr. Samuel Mantravadi and Joseph Reith for their contributions to this project.
