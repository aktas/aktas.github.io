---
title: Anti Analysis Techniques[TR]
published: true
---

<div style="text-align:center"><img src="/assets/captan.jpg" alt="FlapJack Captain" ></div>

Günümüzde, kötü niyetli yazılım geliştiricileri yazdıkları kötü amaçlı yazılımların incelenmesini zorlaştırmak için "Anti-analiz" olarak adlandırılan teknikleri kullanır. Bu teknikler, malware analistlerin sıkça kullandığı analiz araçlarını ve yöntemlerini etkisiz hale getirmeyi veya karmaşıklaştırmayı amaçlar. Bu araçlar ve yöntemler arasında disassembling, debugging ve virtual machine bulunabilir.

Bu yazıda size öğrendiğim teknikleri göstereceğim. Yazı, yeni teknikler öğrendikçe sürekli olarak güncellenecektir. Kodların tamamına ulaşmak için [bu repo](https://github.com/aktas/Anti-Analysis)'yu ziyaret edin.

### [](#header-2)Anti Disassembly Techniques

Anti-Disassembly tekniği, kodun analiz edilmesini zorlaştırmayı amaçlar ve genellikle kodun çalışma mantığını anlamaya çalışan tersine mühendislik uzmanlarına karşı kullanılır. Bu yöntem, runtime analizde önemini yitirse de, statik analizde işi zorlaştırabilir.

### [](#header-3)Impossible Disassembly

<div style="text-align:center"><img src="/assets/ImpossibleDisassembly.png" alt="FlapJack Captain" ></div>

Resmi incelediğimizde `loc_4046D3` adresinde anlamsız hex ifadeleri görüyoruz. IDA Pro kodu düzgünce okuyamıyor. Burada kodun gizlendiği anlaşılıyor. `loc_4046D3` adresine sıçrayan `jl short near ptr loc_4046D3+2` satırı dikkatimizi çekiyor. Bu kısımda, program çalışma anında `loc_4046D3` adresinden başlayarak `2` bayt sonrasındaki adrese atlayarak çalışıyor. Ancak kullandığımız disassembler araçları, kodu ilk bayttan okumaya başladığı için düzgün şekilde çözümleyemiyor ve karmaşık bir sonuç ortaya çıkıyor.

Her ne kadar tekniğin ismi `Impossible Disassembly` olsa da çözümü oldukça basit. Program runtime da çalışırken `loc_4046D3` adresinin ilk `2` byte'ını es geçtiği için ve disassembler aracı ilk byte'dan okumaya başladığı için yapmamız gerek ilk `2` byte'ı `NOP` kodu ile değiştirmek. Bu işlemi yapmak için hex editor gibi bir araç kullanabilirsiniz. `E9` ve `74` adreslerini `90` ile değiştirdiğimizde disassembler aracımız kodu düzgünce yorumlayabiliyor.

<div style="text-align:center"><img src="/assets/opcode_patching.png" alt="FlapJack Captain" ></div>
<div style="text-align:center"><img src="/assets/ImpossibleDisassembly2.png" alt="FlapJack Captain" ></div>

32 bit programlarda bu tekniği otomatik olarak çözen script'e [bu](https://github.com/aktas/Anti-Analysis/tree/main/ImpossibleDisassembly) linkten ulaşabilirsiniz.

### [](#header-3)API Obfuscation

`GetModuleHandleA` ve `GetProcAddress` işlevleri ile API çağrılarını doğrudan çağırmak yerine program çalışırken dinamik olarak çağırabiliriz. Bu sayede kullanacağımız API çağrılarının statik analizde tespit edilmemesini sağlamış oluruz. Ayrıca bu yöntemi `data obfuscation` ile biraz daha karmaşık hale getirebiliriz. 

```
#include <windows.h>
#include <iostream>
using namespace std;

void dynamicApiResolving(const char* str, const char* str2)
{
	string decryptedString;
	string decryptedString2;

	for (int i = 0; i < strlen(str); i++) {
		decryptedString += str[i] ^ 0x11;
	}
	for (int i = 0; i < strlen(str2); i++) {
		decryptedString2 += str2[i] ^ 0x11;
	}

	const char* szMessage = "Hello World!";
	const char* szCaption = "Hello!";
	HMODULE hModule = GetModuleHandleA(decryptedString2.c_str());
	if (!hModule)
		cout << "error" << endl;
	FARPROC fFuncProc = GetProcAddress(hModule, decryptedString.c_str());
	((int (WINAPI*)(HWND, LPCSTR, LPCSTR, UINT)) fFuncProc)(0, szMessage, szCaption, 0);
	FreeLibrary(hModule);
}

string xorFunc(const char* str) {
	string encryptedString;

	for (int i = 0; i < strlen(str); i++) {
		encryptedString += str[i] ^ 0x11;
	}

	return encryptedString;
}

int main()
{
	
	//cout << xorFunc("MessageBoxA") << endl;
	ShowWindow(GetConsoleWindow(), 0);
	if (FreeConsole()) {
		dynamicApiResolving("\\tbbpvtS~iP", "dbtc\"#?u}}"); // api, dll
	}

	return 0;
}
```


### [](#header-2)Anti Debug Techniques

Anti debug tekniği ile bir programın debugger tarafından incelenmesini veya analiz edilmesini engellemek amaçlanır.

### [](#header-3)IsDebuggerPresent & CheckRemoteDebuggerPresent

`IsDebuggerPresent` ve `CheckRemoteDebuggerPresent`, bir programın bir debugger tarafından incelenip incelenmediğini belirlemek için kullanılır. `CheckRemoteDebuggerPresent` işlevi, belirli bir işlemin PID değerini alarak debugger tarafından incelenip incelenmediğini kontrol eder.

```
#include <iostream>
#include <windows.h>

using namespace std;

int main() {

	if (IsDebuggerPresent()) {
		ExitProcess(0);
	}

	BOOL isDebuggerPresent = false;
	HANDLE hProcess = GetCurrentProcess();
	CheckRemoteDebuggerPresent(hProcess, &isDebuggerPresent);
	if (isDebuggerPresent) {
		ExitProcess(0);
	}

	cout << "Everything's OK" << endl;

	return 0;
}
```

### [](#header-3)BlockInput

`BlockInput` fonksiyonu, kullanıcının giriş aygıtlarını (klavye ve fare) geçici olarak devre dışı bırakma veya etkinleştirme yeteneğine sahiptir. Kod, bu fonksiyonu iki kez çağırarak hata ayıklama aracının bu fonksiyonu engelleyip engellemediğini kontrol etmeye çalışıyor. Normalde, bir hata ayıklama aracı bu tür işlemleri engelleyemez, bu nedenle eğer fonksiyon çağrıları başarılıysa, hata ayıklama aracı var gibi düşünülebilir.

```
#include <iostream>
#include <windows.h>

using namespace std;

bool IsHooked()
{
    BOOL bFirstResult = FALSE, bSecondResult = FALSE;
    __try
    {
        bFirstResult = BlockInput(TRUE);
        bSecondResult = BlockInput(TRUE);
    }
    __finally
    {
        BlockInput(FALSE);
    }
    return bFirstResult && bSecondResult;
}

int main()
{
    if (IsHooked()) {
        cout << "Detect Debugger!" << endl;
    } 
}
```

### [](#header-3)FindWindow

`FindWindow` ile pencere sınıflarının varlığı kontrol edilerek debugger'ın varlığının tespit edilmesi amaçlanır.

```
#include <iostream>
#include <windows.h>
#include <vector>

using namespace std;

const vector<string> vWindowClasses = {
  "antidbg",
  "ID", // Immunity Debugger
  "ntdll.dll", 
  "ObsidianGUI",
  "OLLYDBG",
  "Rock Debugger",
  "SunAwtFrame",
  "Qt5QWindowIcon",
  "WinDbgFrameClass",
  "Zeta Debugger",
  "IDA", 
  "X32Dbg",
  "x64dbg",
};

bool IsDebugged()
{
    for (const string& sWndClass : vWindowClasses) {
        const char* pszWndClass = sWndClass.c_str();
        if (NULL != FindWindowA(pszWndClass, NULL)) {
            return true;
        }
    }
    return false;
}

int main() {
    bool isDebuggerDetected = IsDebugged();

    if (isDebuggerDetected) {
        cout << "Debugger detected!\n";
    } 

    return 0;
}
```

### [](#header-3)RaiseException

`RaiseException` ile eğer debugger tespit edilirse istisna fırlatılarak programın kapatılmasını sağlayabiliriz.

```
#include <Windows.h>
#include <iostream>
using namespace std;
bool Check()
{
    __try
    {
        RaiseException(DBG_CONTROL_C, 0, 0, NULL);
        return true;
    }
    __except (DBG_CONTROL_C == GetExceptionCode()
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH)
    {
        return false;
    }
}

int main() {
    bool isDebuggerPresent = Check();

    if (!isDebuggerPresent) {
        printf("Debugger is not present.\n");
    }

}
```

### [](#header-3)GetTickCount

`GetTickCount` kullanarak işlem başlangıcı ve bitişi arasındaki süreyi ölçebilir ve eğer belirtilen süreden büyükse programı sonlandırabiliriz. Pek kullanılan bir yöntem olmasada debugger ile program incelenirken aradaki süre artacağından dolayı bu yöntem kullanılabilir.

```
#include <iostream>
#include <windows.h>

using namespace std;
bool IsDebuggedd(DWORD dwNativeElapsed) // milisaniye
{
    DWORD dwStart = GetTickCount();
    // ... 
    return (GetTickCount() - dwStart) > dwNativeElapsed;
}

int main()
{
    if (IsDebuggedd(1000)) {
        cout << "Debugger Detected!" << endl;
    }
}
```

### [](#header-3)QueryPerformanceCounter

`QueryPerformanceCounter` işlevi `GetTickCount` ile aynı amacı taşıyan bir diğer fonksiyonumuz. 

```
#include <iostream>
#include <windows.h>

using namespace std;

bool IsDebugged(DWORD64 qwNativeElapsed) // milisaniye
{
    LARGE_INTEGER liStart, liEnd;
    QueryPerformanceCounter(&liStart);
    // ... 
    QueryPerformanceCounter(&liEnd);
    return (liEnd.QuadPart - liStart.QuadPart) > qwNativeElapsed;
}

int main()
{
    if (IsDebugged(1000)) {
        cout << "Debugger detected!" << endl;
    }
}
```

### [](#header-2)Data Obfuscation





