# Jenkins_Credentials_Crack

单条 Jenkins 凭据解密脚本（优化版）。用于在具备 master.key 与 hudson.util.Secret 的前提下，解密 Jenkins 配置或插件产生的单个加密密文。

- 支持传入密文字符串（可包含或不包含花括号）或密文文件路径
- 自动识别新/旧两种密文格式（payload_version）
- 新格式：AES-CBC + PKCS7；旧格式：AES-ECB + MAGIC 分隔
- 详细日志与更健壮的错误提示（-v/--verbose 开启调试）


## 环境要求
- Python 3.7+
- 依赖：pycryptodome

安装依赖：
```
pip install -r requirements.txt
# 或
pip install pycryptodome
```


## 相关文件位置（常见）
- $JENKINS_HOME/secrets/master.key
- $JENKINS_HOME/secrets/hudson.util.Secret
- 密文来源：如 credentials.xml/插件 XML 中的 {Base64...} 片段


## 使用方法
脚本：jenkins_credential.py

基本语法：
```
python3 jenkins_credential.py <master.key> <hudson.util.Secret> <密文或密文文件路径>
```

支持两种“第三个参数”形式：
- 直接传入 Base64 密文（可带或不带花括号）
- 传入一个文件路径（文件内容为密文字符串）

开启调试信息：
```
python3 jenkins_credential.py <master.key> <hudson.util.Secret> <密文或文件> -v
```


## 示例
- 直接传入花括号包裹的密文：
```
python3 jenkins_credential.py secrets/master.key secrets/hudson.util.Secret "{AQAAAB...}"
```

- 直接传入不带花括号的密文：
```
python3 jenkins_credential.py secrets/master.key secrets/hudson.util.Secret "AQAAAB..."
```

- 从文件读取密文：
```
python3 jenkins_credential.py secrets/master.key secrets/hudson.util.Secret credential.txt
```

输出：脚本会将解密后的明文密码直接打印到标准输出。


## 常见问题与排错
- ImportError: No module named Crypto
  - 未安装依赖，执行：`pip install pycryptodome`

- Invalid base64 credential / Empty payload after base64 decode
  - 第三个参数不是合法的 Base64 字符串，或文件内容为空；请确认粘贴时未包含多余空白、未被换行破坏。可保留或去除花括号再试。

- Decryption failed: Magic bytes not found in decrypted data（旧格式报错）
  - 提供的密文可能不是旧格式，或 master.key/hudson.util.Secret 与该密文不匹配。

- Windows 下 `python3` 命令不可用
  - 可尝试将命令中的 `python3` 替换为 `python`。


## 安全提示
- 请在合法合规、授权范围内使用本工具。
- master.key/hudson.util.Secret 与敏感密文均属于高敏感数据，请妥善存放，不要上传到公共仓库。


## 鸣谢
- https://github.com/tweksteen/jenkins-decrypt
- https://github.com/bstapes/jenkins-decrypt

本项目在上述思路基础上进行工程化优化与健壮性增强，仅用于安全研究与取证自救。
