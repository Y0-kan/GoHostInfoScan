# GoHostInfoScan
红队小工具 | 利用DCERPC协议，无需认证获取Windows机器主机信息和多网卡信息
## 简介
分析和部分代码参考了倾旋师傅的[文章](https://payloads.online/archivers/2020-07-16/1/)
[HostInfoScan](https://github.com/Y0-kan/HostInfoScan)的Go版本，便于交叉编译与移植。

**本工具主要用于探测内网中Windows机器的操作系统信息、域名、主机名以及多网信息，可以辅助红队快速定位多网卡主机，以及判断机器是否在域内。**

**优点：
无需认证，只要目标的135端口开放即可获得信息**


## 效果
域内机器：
![image](images/20230420143607.jpg)

工作组机器：
![image](images/20230420143625.jpg)

## 使用
```
Usage of GoHostInfoScan64.exe:
  -i string
        IP address of the host you want to scan,for example: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.0/24
  -l string
        inputfile, for example: ip.txt，One ip in a row
  -o string
        Outputfile (default "result.txt")
  -t int
        Thread nums (default 5)
```


## 免责声明
本工具仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您务必审慎阅读、充分理解各条款内容。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。
