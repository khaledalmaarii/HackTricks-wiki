# Radio

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks AWS Red Team Expert</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)is a free digital signal analyzer for GNU/Linux and macOS, designed to extract information of unknown radio signals. It supports a variety of SDR devices through SoapySDR, and allows adjustable demodulation of FSK, PSK and ASK signals, decode analog video, analyze bursty signals and listen to analog voice channels (all in real time).

### Basic Config

After installing there are a few things that you could consider configuring.\
In settings (the second tab button) you can select the **SDR device** or **select a file** to read and which frequency to syntonise and the Sample rate (recommended to up to 2.56Msps if your PC support it)\\

![](<../../.gitbook/assets/image (655) (1).png>)

In the GUI behaviour it's recommended to enable a few things if your PC support it:

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
If you realise that your PC is not capturing things try to disable OpenGL and lowering the sample rate.
{% endhint %}

### Uses

* Just to **capture some time of a signal and analyze it** just maintain the button "Push to capture" as long as you need.

![](<../../.gitbook/assets/image (631).png>)

* The **Tuner** of SigDigger helps to **capture better signals** (but it can also degrade them). Ideally start with 0 and keep **making it bigger until** you find the **noise** introduce is **bigger** than the **improvement of the signal** you need).

![](<../../.gitbook/assets/image (658).png>)

### Synchronize with radio channel

With [**SigDigger** ](https://github.com/BatchDrake/SigDigger)synchronize with the channel you want to hear, configure "Baseband audio preview" option, configure the bandwith to get all the info being sent and then set the Tuner to the level before the noise is really starting to increase:

![](<../../.gitbook/assets/image (389).png>)

## Interesting tricks

* When a device is sending bursts of information, usually the **first part is going to be a preamble** so you **don't** need to **worry** if you **don't find information** in there **or if there are some errors** there.
* In frames of information you usually should **find different frames well aligned between them**:

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **After recovering the bits you might need to process them someway**. For example, in Manchester codification a up+down will be a 1 or 0 and a down+up will be the other one. So pairs of 1s and 0s (ups and downs) will be a real 1 or a real 0.
* Even if a signal is using Manchester codification (it's impossible to find more than two 0s or 1s in a row), you might **find several 1s or 0s together in the preamble**!

### Uncovering modulation type with IQ

There are 3 ways to store information in signals: Modulating the **amplitude**, **frequency** or **phase**.\
If you are checking a signal there are different ways to try to figure out what is being used to store information (fin more ways below) but a good one is to check the IQ graph.

![](<../../.gitbook/assets/image (630).png>)

* **Detecting AM**: If in the IQ graph appears for example **2 circles** (probably one in 0 and other in a different amplitude), it could means that this is an AM signal. This is because in the IQ graph the distance between the 0 and the circle is the amplitude of the signal, so it's easy to visualize different amplitudes being used.
* **Detecting PM**: Like in the previous image, if you find small circles not related between them it probably means that a phase modulation is used. This is because in the IQ graph, the angle between the point and the 0,0 is the phase of the signal, so that means that 4 different phases are used.
* Note that if the information is hidden in the fact that a phase is changed and not in the phase itself, you won't see different phases clearly differentiated.
* **Detecting FM**: IQ doesn't have a field to identify frequencies (distance to centre is amplitude and angle is phase).\
Therefore, to identify FM, you should **only see basically a circle** in this graph.\
Moreover, a different frequency is "represented" by the IQ graph by a **speed acceleration across the circle** (so in SysDigger selecting the signal the IQ graph is populated, if you find an acceleration or change of direction in the created circle it could mean that this is FM):

## AM Example

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Uncovering AM

#### Checking the envelope

Checking AM info with [**SigDigger** ](https://github.com/BatchDrake/SigDigger)and just looking at the **envelop** you can see different clear amplitude levels. The used signal is sending pulses with information in AM, this is how one pulse looks like:

![](<../../.gitbook/assets/image (636).png>)

And this is how part of the symbol looks like with the waveform:

![](<../../.gitbook/assets/image (650) (1).png>)

#### Checking the Histogram

You can **select the whole signal** where information is located, select **Amplitude** mode and **Selection** and click on **Histogram.** You can observer that 2 clear levels are only found

![](<../../.gitbook/assets/image (647) (1) (1).png>)

For example, if you select Frequency instead of Amplitude in this AM signal you find just 1 frequency (no way information modulated in frequency is just using 1 freq).

![](<../../.gitbook/assets/image (637) (1) (1).png>)

If you find a lot of frequencies potentially this won't be a FM, probably the signal frequency was just modified because of the channel.
#### jIq

vaj example vItlhutlh **Dochmey** 'ej **lot points** vIleghlaHbe'.

![](<../../.gitbook/assets/image (640).png>)

### Get Symbol Rate

#### jIq wa'logh

vaj wa'logh vItlhutlh **Dochmey** (vaj vItlhutlh 1) 'ej check "Selection freq". vaj vItlhutlh 1.013kHz (vaj 1kHz) vIleghlaHbe':

![](<../../.gitbook/assets/image (638) (1).png>)

#### Dochmey wa'logh

vaj Dochmey vItlhutlh number 'ej SigDigger vItlhutlh 1 Dochmey frequency (vaj Dochmey vItlhutlh vItlhutlh 'ej vaj Dochmey vItlhutlh 1.004 Khz) vIleghlaHbe':

![](<../../.gitbook/assets/image (635).png>)

### Get Bits

vaj **AM modulated** signal 'ej **symbol rate** vItlhutlh (vaj 'ej vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhutlh 0 vaj vItlhutlh 1 vaj vItlhut
