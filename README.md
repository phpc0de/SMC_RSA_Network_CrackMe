# SMC_RSA_Network_CrackMe
免责声明
本软件（包括 CodeGen、CrackMe、VerifyServer 及相关源代码和文档，以下简称“本软件”）仅用于计算机安全、逆向工程和软件保护技术的学习与研究。用户在使用本软件时必须遵守所在地法律法规。

严禁将本软件或其任何部分用于任何非法目的，包括但不限于未经授权的软件破解、侵犯他人知识产权、破坏计算机系统安全或干扰网络服务的行为。

作者未提供任何形式的担保，包括但不限于适销性、特定用途适用性和不侵权的担保。对于因使用或无法使用本软件而造成的任何直接、间接、偶然、特殊或继发损害（包括但不限于数据丢失、业务中断或经济损失），作者不承担任何法律责任。

使用者应对自身使用本软件的行为全权负责。如果使用本软件违反用户所在国家或地区的法律法规，用户应立即停止使用并自行承担一切后果。

本软件包含的密码学算法（SHA-256、RSA）仅为教学演示目的而设计，未经过安全审计，不应用于生产环境或实际安全系统。

本解决方案包含三个项目，共同构建一个带有自修改代码（SMC）保护、RSA-1024算法验证、十种反调试暗桩以及网络验证的CrackMe练习程序，同时提供一个配套的网络验证服务端。所有代码均使用纯C++编写，仅依赖Windows API，可在安装Visual Studio 2022的Windows 10/11 x64环境下直接编译运行。

一、项目组成与功能

CodeGen（代码生成器）

提取自身编译后的VerifyImpl函数机器码，使用XOR 0x5A加密，生成smc_data.h头文件。

VerifyImpl函数内部包含完整的SHA-256和RSA-1024验证逻辑（与CrackMe中原有的VerifyRSA相同），用于产生加密的验证核心。

CrackMe（客户端主程序）

反调试检测：包含十种暗桩，通过CollectFlags函数收集标志位。
· PEB.BeingDebugged标志
· PEB.NtGlobalFlag标志
· CheckRemoteDebuggerPresent API
· 时间差检测
· 硬件断点检测（Dr0-Dr3）
· 软件断点扫描（检查IsDebuggerPresent函数入口0xCC）
· 反虚拟机（CPUID检测Hypervisor）
· 反沙箱（检测Sandboxie DLL）
· 父进程检测（黑名单：常见调试器/分析工具）
· 代码段CRC校验（可配置，当前版本已注释）

SMC自解密：运行时通过smc_unlock_verify函数将smc_data.h中的加密数组解密到可执行内存，得到VerifyFunc函数指针。

RSA-1024本地验证：解密后的VerifyFunc内部执行完整的SHA-256哈希和非对称签名验证（公钥硬编码于加密代码中）。

WinHTTP网络验证：本地验证通过后，将用户名、序列号及标志位发送至127.0.0.1:8080服务端进行二次确认。

整体流程：暗桩检测（可选退出） → 解密SMC → 输入用户名和序列号 → 调用SMC中的验证 → 若本地通过且网络返回200则成功。

VerifyServer（网络验证服务端）

监听本地8080端口，接收HTTP POST请求。

解析请求中的name、serial、flags参数。

使用与客户端完全相同的RSA公钥和算法对用户名和序列号进行验证。

若RSA验签通过且flags为0（客户端未触发暗桩），返回200 OK；否则返回403 Forbidden。

支持控制台输入'q'优雅退出，亦可通过关闭窗口触发ConsoleHandler自动清理Socket资源。

编译后为独立的控制台程序，可配合CrackMe使用。

二、编译流程

环境要求

Windows 10/11 x64

Visual Studio 2022（需安装“使用C++的桌面开发”工作负荷）

无需任何第三方库，所有依赖均为Windows SDK自带

解决方案结构
SMC_CrackMe/
├── CodeGen/
│ └── CodeGen.cpp
├── CrackMe/
│ ├── CrackMe.cpp
│ └── smc_data.h（初始可不存在，由CodeGen生成）
└── VerifyServer/
└── VerifyServer.cpp

生成步骤
a. 将整个解决方案文件夹复制到目标计算机。
b. 使用Visual Studio 2022打开解决方案文件（.sln）。
c. 首先生成CodeGen项目：

在解决方案资源管理器中右键“CodeGen” → “生成”。

若生成成功，在输出目录（如x64\Debug或x64\Release）下将产生CodeGen.exe。
d. 运行CodeGen.exe生成smc_data.h：

可直接在文件资源管理器中双击运行CodeGen.exe，或在命令提示符下执行。

程序会在当前工作目录（通常为CodeGen.exe所在目录）生成smc_data.h文件。

将生成的smc_data.h复制到CrackMe项目文件夹（与CrackMe.cpp同目录），覆盖旧文件。
e. 生成CrackMe项目：

右键“CrackMe” → “生成”。

如果设置了预先生成事件（如"$(SolutionDir)CodeGen\x64\Debug\CodeGen.exe"），则会自动执行步骤d，无需手工复制。若无此事件，请按上述手动操作。

生成成功后，在输出目录得到CrackMe.exe。
f. 生成VerifyServer项目：

右键“VerifyServer” → “生成”。

输出VerifyServer.exe，可直接运行。
g. 运行测试：

先启动VerifyServer.exe，看到“VerifyServer listening on 127.0.0.1:8080”提示。

运行CrackMe.exe，输入任意用户名和序列号（可先用简单的测试，如name=test, serial=任意）。

如果一切正常，程序会输出SMC解锁成功、验签失败（因序列号错误）等信息，网络请求会被发送到服务端，服务端控制台将打印请求和结果。

使用预计算的合法序列号（需自行分解RSA公钥模数或使用已知私钥生成）即可看到“Access granted!”。

三、注意事项

暗桩中的代码段CRC校验（第10个暗桩）默认被注释，若需启用，须在编译后运行一次程序获取真实校验和，填入EXPECTED_TEXT_CHECKSUM常量并重新编译。

CodeGen.cpp中的VerifyImpl函数必须包含完整的RSA验证逻辑，以确保生成的smc_data.h包含完整的加密算法。若修改了RSA代码，需重新生成smc_data.h。

服务端和客户端的RSA公钥必须完全一致，否则网络验证将失败。

若在调试器下运行CrackMe，暗桩可能触发导致退出，可临时修改main函数忽略暗桩（如注释掉return语句）以便调试其他功能。

整个项目在Release配置下编译可获得无调试信息的最终版本，更适合作为逆向分析样本使用；Debug配置可用于开发调试。

此项目集成了软件保护领域的多种技术，可作为逆向工程、安全研究和C++编程的学习材料。
