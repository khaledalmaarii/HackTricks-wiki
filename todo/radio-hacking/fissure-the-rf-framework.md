# FISSURE - RF框架

**频率无关的基于SDR的信号理解和逆向工程**

FISSURE是一个开源的RF和逆向工程框架，适用于各种技能水平，具有信号检测和分类、协议发现、攻击执行、IQ操作、漏洞分析、自动化和AI/ML的钩子。该框架旨在促进软件模块、无线电、协议、信号数据、脚本、流图、参考资料和第三方工具的快速集成。FISSURE是一个工作流程启用器，将软件集中在一个位置，并允许团队轻松上手，同时共享特定Linux发行版的相同的经过验证的基线配置。

FISSURE框架和工具旨在检测RF能量的存在，理解信号的特征，收集和分析样本，开发发送和/或注入技术，并构建自定义的负载或消息。FISSURE包含一个不断增长的协议和信号信息库，以帮助识别、数据包构造和模糊测试。在线存档功能可下载信号文件并构建播放列表以模拟流量和测试系统。

友好的Python代码库和用户界面使初学者能够快速了解与RF和逆向工程相关的流行工具和技术。网络安全和工程教育者可以利用内置材料或利用该框架展示自己的实际应用。开发人员和研究人员可以使用FISSURE进行日常任务，或将其前沿解决方案展示给更广泛的受众。随着FISSURE在社区中的认知和使用增长，其功能的范围和所涵盖技术的广度也将增加。

**附加信息**

* [AIS页面](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22幻灯片](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22论文](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22视频](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat记录](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## 入门指南

**支持的**

FISSURE有三个分支，以便更轻松地进行文件导航并减少代码冗余。Python2\_maint-3.7分支基于Python2、PyQt4和GNU Radio 3.7构建；Python3\_maint-3.8分支基于Python3、PyQt5和GNU Radio 3.8构建；Python3\_maint-3.10分支基于Python3、PyQt5和GNU Radio 3.10构建。

|   操作系统   |   FISSURE分支   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**进行中（测试版）**

这些操作系统仍处于测试版状态。它们正在开发中，已知缺少一些功能。安装程序中的项目可能与现有程序冲突，或者在状态被移除之前无法安装。

|     操作系统     |    FISSURE分支   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

注意：某些软件工具不适用于每个操作系统。请参考[软件和冲突](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**安装**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
这将安装PyQt软件所需的依赖项，以便在找不到它们时启动安装GUI。

接下来，选择与您的操作系统最匹配的选项（如果您的操作系统与某个选项匹配，则会自动检测到）。

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

建议在干净的操作系统上安装FISSURE，以避免现有冲突。选择所有推荐的复选框（默认按钮），以避免在FISSURE中使用各种工具时出现错误。安装过程中会出现多个提示，主要是要求提升权限和用户名。如果某个项目在末尾包含“Verify”部分，则安装程序将运行后面的命令，并根据命令是否产生任何错误来突出显示复选框项目的绿色或红色。安装完成后，没有“Verify”部分的选中项目将保持黑色。

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**用法**

打开终端并输入：
```
fissure
```
请参考FISSURE帮助菜单以获取更多使用细节。

## 详情

**组件**

* 仪表板
* 中央枢纽（HIPRFISR）
* 目标信号识别（TSI）
* 协议发现（PD）
* 流图和脚本执行器（FGE）

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**功能**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**信号检测器**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ操作**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**信号查询**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**模式识别**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**攻击**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**模糊测试**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**信号播放列表**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**图像库**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**数据包构造**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy集成**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC计算器**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**日志记录**_            |

**硬件**

以下是一些具有不同集成级别的“支持”硬件的列表：

* USRP：X3xx、B2xx、B20xmini、USRP2、N2xx
* HackRF
* RTL2832U
* 802.11适配器
* LimeSDR
* bladeRF、bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## 教程

FISSURE附带了几个有用的指南，以熟悉不同的技术和技巧。其中许多包括使用FISSURE集成工具的步骤。

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

## 路线图

* [ ] 添加更多硬件类型、RF协议、信号参数和分析工具
* [ ] 支持更多操作系统
* [ ] 开发围绕FISSURE的课程材料（RF攻击、Wi-Fi、GNU Radio、PyQt等）
* [ ] 创建一个可选择AI/ML技术的信号调节器、特征提取器和信号分类器
* [ ] 实现递归解调机制，从未知信号生成比特流
* [ ] 将主要FISSURE组件转换为通用传感器节点部署方案

## 贡献

强烈鼓励提出改进FISSURE的建议。如果您对以下事项有任何想法，请在[讨论](https://github.com/ainfosec/FISSURE/discussions)页面或Discord服务器中留言：

* 新功能建议和设计更改
* 安装步骤的软件工具
* 新教程或现有教程的附加材料
* 感兴趣的RF协议
* 更多硬件和SDR类型的集成
* Python中的IQ分析脚本
* 安装纠正和改进

改进FISSURE的贡献对于加快其发展至关重要。非常感谢您所做的任何贡献。如果您希望通过代码开发进行贡献，请fork该仓库并创建一个pull请求：

1. Fork项目
2. 创建您的功能分支（`git checkout -b feature/AmazingFeature`）
3. 提交您的更改（`git commit -m 'Add some AmazingFeature'`）
4. 推送到分支（`git push origin feature/AmazingFeature`）
5. 打开一个pull请求

欢迎创建[问题](https://github.com/ainfosec/FISSURE/issues)以引起对错误的关注。
## 合作

联系Assured Information Security, Inc. (AIS)商务发展部，提出并正式确定任何FISSURE合作机会，无论是通过投入时间来集成您的软件，还是让AIS的人才为您的技术挑战开发解决方案，或者将FISSURE集成到其他平台/应用程序中。

## 许可证

GPL-3.0

有关许可证详细信息，请参阅LICENSE文件。

## 联系方式

加入Discord服务器：[https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

关注Twitter：[@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

商务发展部 - Assured Information Security, Inc. - bd@ainfosec.com

## 鸣谢

我们感谢以下开发人员：

[鸣谢](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## 致谢

特别感谢Samuel Mantravadi博士和Joseph Reith对该项目的贡献。
