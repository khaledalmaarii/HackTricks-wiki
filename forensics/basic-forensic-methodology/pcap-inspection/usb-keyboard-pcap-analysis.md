如果你有一个带有许多中断的USB连接的pcap文件，那么很可能是一个USB键盘连接。

像这样的Wireshark过滤器可能会有用：`usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

重要的是要知道以"02"开头的数据是使用Shift键按下的。

你可以在以下链接中阅读更多信息并找到一些关于如何分析这些数据的脚本：

* [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
* [https://github.com/tanc7/HacktheBox\_Deadly\_Arthropod\_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
