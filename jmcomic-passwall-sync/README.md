# Passwall 自动更新禁漫国内域名至直连域名列表
## 项目概述

这是一个自动化配置路由器PassWall规则的Python脚本，主要功能包括：
- 自动登录路由器管理界面
- 获取当前PassWall规则列表
- 从指定网站抓取域名列表
- 将域名添加到直连规则列表
- 使用Redis缓存域名列表避免重复更新

## 功能说明

1. **路由器登录认证**
   - 使用Playwright模拟浏览器登录路由器
   - 自动提取并验证LuCI认证token
   - 获取并管理会话Cookie

2. **规则管理**
   - 获取当前所有规则列表（直连/代理/阻断等）
   - 解析规则页面HTML内容
   - 构建并提交更新后的规则表单

3. **域名抓取**
   - 从指定网站抓取域名列表
   - 支持CSS选择器定位目标元素
   - 自动过滤无效域名

4. **缓存管理**
   - 使用Redis存储已处理的域名列表
   - 比对更新避免重复操作
   - 支持连接异常处理

## 使用说明

### 安装依赖
```bash
pip install playwright requests beautifulsoup4 redis
playwright install chromium
```

### 配置文件
在脚本中修改以下配置常量：

```python
# 路由器配置
ROUTER_CONFIG = {
    "url": "http://192.168.1.254/",     # 路由器管理地址
    "username": "root",                 # 管理员账号
    "password": "password",             # 管理员密码
    "passwall_url": "http://192.168.1.254/cgi-bin/luci/admin/services/passwall/rule_list",  # PassWall规则页面
    "timeout": 10,                      # 请求超时时间(秒)
}

# 域名来源配置
DOMAIN_SOURCE = {
    "url": "https://jmcomicgo.xyz/",    # 目标网站URL
    "css_selector": "china",            # 域名所在的CSS选择器
}

# Redis配置
REDIS_CONFIG = {
    "host": "192.168.1.170",            # Redis服务器地址
    "port": 6379,                       # Redis端口
    "db": 0,                            # 数据库编号
    "password": "cloudcranesss",        # Redis密码
    "socket_timeout": 5                 # 连接超时时间
}
REDIS_KEY = "passwall:direct_hosts"     # 存储键名
```

### 运行脚本
```bash
python update_jmcomic_domain.py
```

## 执行流程

1. 从目标网站抓取域名列表
2. 连接Redis获取已缓存域名
3. 比对域名差异，确定是否需要更新
4. 登录路由器管理界面
5. 获取当前所有规则列表
6. 将新域名添加到直连规则列表
7. 提交更新后的规则列表
8. 将新域名列表缓存到Redis

## 日志说明

脚本使用标准logging模块记录运行日志，包含以下级别：
- **DEBUG**: 详细调试信息（域名抓取、token提取等）
- **INFO**: 关键操作记录（登录成功、规则更新等）
- **WARNING**: 非关键异常（空域名列表等）
- **ERROR**: 操作失败信息（登录失败、请求异常等）

日志格式：`时间 - 级别 - 消息`

## 注意事项

1. 首次运行需要安装Chromium浏览器
2. 确保运行环境能访问路由器管理界面
3. 路由器页面结构变化可能导致脚本失效
4. 目标网站结构变化需调整CSS选择器
5. Redis非必需，但推荐使用以提高效率
6. 生产环境建议设置`headless=True`

## 错误处理

脚本包含完善的错误处理机制：
- 路由器登录失败自动终止
- 网络请求异常重试机制
- Token提取多重验证
- Redis连接异常降级处理
- 所有操作均有异常捕获和日志记录

## 自定义扩展

可根据需要修改以下部分：
1. 调整`DOMAIN_SOURCE`配置抓取不同网站的域名
2. 修改`_parse_rule_list`方法适配不同规则页面结构
3. 扩展`_build_form_data`支持更多规则类型
4. 添加定时任务实现自动化运行

## 许可证

本项目采用 MIT 许可证
