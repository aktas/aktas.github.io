---
title: Arçelik Mobile Reverse Question
published: true
---

In this article, I will explain the solution of the mobile question in the ctf event organized by Arçelik. You can download the apk file from [here](assets/RemoteWhiz.apk). I will show 2 different solutions. In the first solution I used the `jadx-gui` tool and `apktool`. In solution 2, I got the flag with `jadx-gui` and `frida`.

### [](#header-3)Solution 1
After opening the apk file with jadx-gui, we look at the first classes.
![Book logo](/assets/class.png)
