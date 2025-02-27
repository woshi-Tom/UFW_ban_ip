# 优化UFW防火墙规则



## 一、本脚本适用范围



**原理**：

>1. **备份当前UFW规则**：将现有的UFW规则保存到`ufw.policy`文件中。
>2. **提取IP信息**：从`apnic.net`获取并解析属于中国的公网IP地址，计算出相应的`IP/CIDR`值。
>3. **拼接允许访问的规则**：基于现有开放端口列表，生成允许特定来源IP访问的规则。
>4. **更新UFW规则**：将新生成的规则加入到UFW中。



**适用范围**：

- 所有使用UFW防火墙的Linux发行版（主要针对Debian系列）



## 二、文件目录结构

以下是脚本运行过程中会用到的文件及其用途：

```bash
├── apnic_delegated_stats.txt	# 存储IP归属地信息
├── banIP_V1.0.0.sh					# 主要的Bash脚本
├── china_ips.txt 				# 存储中国IP段信息的临时文件
├── restricted_ports.txt		# 存储UFW允许规则中的端口列表
└── ufw.policy					# 备份的UFW规则文件
```

仓库内可能没有`china_ips.txt `文件，不用担心会影响脚本运行，该文件是脚本运行产生的临时文件。



## 三、运行示例

运行脚本方式比较简单，如下（不懂的可以百度一下）


###  1、后台运行

```
nohup sh banIP_V1.0.0.sh &
```

### 2、非后台运行

```
chmod 755 ban_ip.sh
./banIP_V1.0.0.sh
```

### 3、中止或退出

 - 后台运行

```
kill -9 $(pgrep banIP_V1.0.0.sh)
```

 - 非后台运行`CTRL + c`发送中断信号即可



## 四、注意事项

- 脚本包含了一个重置函数，可以一键恢复原始的UFW规则，请在必要时谨慎使用。
- 当前策略只允许来自中国的IP地址访问，其他所有IP地址都将被丢弃(`drop`)。
- 使用此脚本前，请确保您的机器配置适合这种设置，并考虑到可能因误配置导致无法远程访问的风险。
- 此项目遵循开源许可协议，您可以在此基础上自由开发和修改。

如有任何疑问或建议，请随时联系。
