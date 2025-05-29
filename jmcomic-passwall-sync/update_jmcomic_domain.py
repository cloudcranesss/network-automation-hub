"""
路由器规则自动化配置脚本

功能：
1. 自动登录路由器管理界面
2. 获取PassWall规则列表
3. 从指定网站抓取域名列表
4. 将域名添加到直连规则列表
"""
import json
import re
import logging
from typing import Dict, List

import redis
from bs4 import BeautifulSoup
import requests

# 配置常量
ROUTER_CONFIG = {
    "url": "http://192.168.1.254/",
    "username": "root",
    "password": "password",
    "passwall_url": "http://192.168.1.254/cgi-bin/luci/admin/services/passwall/rule_list",
    "timeout": 10,
}

DOMAIN_SOURCE = {
    "url": "https://jmcomicgo.xyz/",
    "css_selector": "china",
}

# 配置常量
REDIS_CONFIG = {
    "host": "192.168.1.170",
    "port": 6379,
    "db": 0,
    "password": "cloudcranesss",
    "socket_timeout": 5
}
REDIS_KEY = "passwall:direct_hosts"  # 单独定义存储键名

# 日志配置
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.DEBUG
)
logger = logging.getLogger(__name__)


class RouterController:
    """路由器操作控制器"""

    def __init__(self):
        self.cookie = None
        self.token = None

    def login(self) -> None:
        """登录路由器并获取会话凭证"""
        login_url = f"{ROUTER_CONFIG['url']}cgi-bin/luci/"
        logger.debug(f"登录URL: {login_url}")

        # 创建新的会话对象
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        })

        # 第一步：发送登录POST请求（禁止重定向）
        login_data = {
            "luci_username": ROUTER_CONFIG["username"],
            "luci_password": ROUTER_CONFIG["password"]
        }
        login_response = self.session.post(
            login_url,
            data=login_data,
            allow_redirects=False,  # 禁止自动重定向
            timeout=ROUTER_CONFIG["timeout"]
        )
        login_response.raise_for_status()

        # 检查是否重定向（302状态码）
        if login_response.status_code != 302:
            raise RuntimeError(f"登录后未重定向，状态码: {login_response.status_code}")

        # 从POST响应头获取Set-Cookie
        set_cookie = login_response.headers.get('Set-Cookie')
        if not set_cookie:
            raise RuntimeError("登录响应中未找到Set-Cookie头")

        # 第二步：手动跟随重定向（GET请求）
        redirect_url = login_response.headers.get('Location')
        if not redirect_url:
            raise RuntimeError("重定向响应中缺少Location头")

        # 确保重定向URL完整
        if not redirect_url.startswith('http'):
            base_url = ROUTER_CONFIG['url'].rstrip('/')
            redirect_url = f"{base_url}{redirect_url}"

        # 设置Cookie头并发送GET请求
        headers = {"Cookie": set_cookie}
        home_response = self.session.get(
            redirect_url,
            headers=headers,
            allow_redirects=True,  # 允许跟随重定向链
            timeout=ROUTER_CONFIG["timeout"]
        )
        home_response.raise_for_status()

        # 保存最终有效的Cookie
        self.cookie = set_cookie
        logger.debug(f"最终Cookie: {self.cookie}")

        # 从最终响应中提取token
        token = self._extract_token(home_response.text)
        if not token:
            raise RuntimeError("无法从重定向页面提取认证token")

        self.token = token
        logger.info(f"成功获取Token: ...{token[-6:]}")

    def _extract_token(self, html: str) -> str:
        """多种方式尝试提取token"""
        # 方式1: 查找name="token"的input
        soup = BeautifulSoup(html, 'html.parser')
        token_input = soup.find('input', {'name': 'token'})
        if token_input and token_input.get('value'):
            return token_input['value']

        # 方式2: 在JavaScript中查找
        token_patterns = [
            r'token:\s*["\']([a-f0-9]{32})["\']',  # token: 'xxx'
            r'"token"\s*:\s*["\']([a-f0-9]{32})["\']',  # "token": "xxx"
            r'name="token"\s+value="([a-f0-9]{32})"'  # <input name="token" value="xxx">
        ]

        for pattern in token_patterns:
            match = re.search(pattern, html)
            if match:
                return match.group(1)

        return ""

    def _fallback_token_search(self, html: str) -> str:
        """备用token搜索方案"""
        # 尝试从常见位置提取
        soup = BeautifulSoup(html, 'html.parser')
        for script in soup.find_all('script'):
            if 'token' in script.text:
                match = re.search(r'([a-f0-9]{32})', script.text)
                if match:
                    return match.group(1)

        # 最终尝试：从cookie中提取
        if 'sysauth' in self.session.cookies:
            return self.session.cookies['sysauth'][:32]

        return ""

    def _extract_and_validate_token(self, script_content: str) -> str:
        """带多重验证的Token提取方法"""
        # 第一阶段：正则匹配
        token_pattern = re.compile(
            r'LuCI\({\s*.*?"token":\s*"([a-fA-F0-9]{32})"',
            re.DOTALL  # 允许跨行匹配
        )
        match = token_pattern.search(script_content)
        if not match:
            raise ValueError("未在脚本内容中发现符合格式的Token")

        raw_token = match.group(1)

        # 第二阶段：格式验证
        if len(raw_token) != 32:
            raise ValueError(f"Token长度异常，期望32位，实际得到{len(raw_token)}位")

        if not re.fullmatch(r'^[a-f0-9]{32}$', raw_token.lower()):
            raise ValueError("Token包含非法字符，应为十六进制字符")

        # 第三阶段：有效性验证（示例）
        if raw_token == '0' * 32:
            raise ValueError("检测到无效的默认Token")

        return raw_token.lower()  # 统一返回小写格式

    def get_rule_list(self) -> Dict[str, List[str]]:
        """获取当前所有规则列表"""
        try:
            response = requests.get(
                ROUTER_CONFIG["passwall_url"],
                headers=self._request_headers(),
                timeout=ROUTER_CONFIG["timeout"]
            )
            response.raise_for_status()
            return self._parse_rule_list(response.text)
        except requests.RequestException as e:
            logger.error(f"获取规则列表失败: {str(e)}")
            raise

    def update_rule_list(self, new_rules: Dict[str, List[str]]) -> None:
        """更新规则列表到路由器"""
        try:
            if not new_rules:
                logger.warning("传入的规则列表为空，跳过更新操作")
                return
            form_data = self._build_form_data(new_rules)
            domain_count = len(new_rules.get("direct_host", []))
            logger.info(f"准备更新直连规则，包含{domain_count}个域名")
            response = requests.post(
                ROUTER_CONFIG["passwall_url"],
                headers=self._request_headers(),
                data=form_data,
                timeout=ROUTER_CONFIG["timeout"]
            )
            response.raise_for_status()
            logger.info("规则更新成功")
        except requests.RequestException as e:
            logger.error(f"规则更新失败: {str(e)}")
            raise

    def _request_headers(self) -> Dict[str, str]:
        """生成请求头"""
        return {
            "Cookie": self.cookie,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": ROUTER_CONFIG["passwall_url"]
        }

    @staticmethod
    def _parse_rule_list(html: str) -> Dict[str, List[str]]:
        """解析规则页面HTML"""

        def parse_field(key: str) -> List[str]:
            textarea = soup.find('textarea', {'id': lambda x: x and key in x})
            if not textarea:
                return []
            return [
                line.strip()
                for line in textarea.get_text().split('\n')
                if line.strip() and not line.startswith('#')
            ]

        soup = BeautifulSoup(html, 'html.parser')
        return {
            "direct_host": parse_field("direct_host"),
            "direct_ip": parse_field("direct_ip"),
            "proxy_host": parse_field("proxy_host"),
            "proxy_ip": parse_field("proxy_ip"),
            "block_host": parse_field("block_host"),
            "block_ip": parse_field("block_ip"),
            "lanlist_ipv4": parse_field("lanlist_ipv4"),
            "lanlist_ipv6": parse_field("lanlist_ipv6"),
            "hosts": parse_field("hosts"),
        }

    def _build_form_data(self, rules: Dict[str, List[str]]) -> Dict[str, str]:
        """构建提交表单数据"""
        return {
            **{f"cbid.passwall.cfg0846c0.{k}": "\n".join(v) for k, v in rules.items()},
            "geoview.lookup": "",
            "cbi.submit": "1",
            "geoview.extract": "",
            "token": self.token
        }


def fetch_domains() -> List[str]:
    """从目标网站抓取域名列表"""
    try:
        response = requests.get(
            DOMAIN_SOURCE["url"],
            timeout=ROUTER_CONFIG["timeout"]
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        # <div class="china"><span>18comic-creed.vip</span></div>
        # 抓取域名
        domains = []
        for div in soup.find_all('div', class_=DOMAIN_SOURCE["css_selector"]):
            span = div.find('span')
            if span:
                domains.append(span.text)
                logger.debug(f"抓取域名：{span.text}")

        return domains
    except requests.RequestException as e:
        logger.error(f"域名获取失败: {str(e)}")
        return []


def main():
    """主执行流程"""
    redis_conn = None  # 确保变量在作用域内
    try:
        # 获取待添加域名
        new_domains = fetch_domains()
        if not new_domains:
            logger.warning("未获取到需要添加的域名")
            return

        # 连接Redis进行域名比对
        try:
            redis_conn = redis.Redis(**REDIS_CONFIG)
            redis_conn.ping()  # 测试连接
            cached_data = redis_conn.get(REDIS_KEY)
            cached_domains = json.loads(cached_data) if cached_data else []
            logger.debug(f"从Redis获取到{len(cached_domains)}条缓存域名")
        except Exception as e:
            logger.error(f"Redis连接异常: {str(e)}，继续执行强制更新")
            cached_domains = []

        # 集合比对域名差异
        new_set = set(new_domains)
        cached_set = set(cached_domains)
        if new_set == cached_set:
            logger.info("域名列表与缓存完全一致，跳过规则更新")
            return

        # 初始化路由器控制器
        router = RouterController()
        router.login()

        # 获取现有规则并更新
        current_rules = router.get_rule_list()
        current_rules["direct_host"].extend(new_domains)
        current_rules["direct_host"] = list(set(current_rules["direct_host"]))

        # 提交更新到路由器
        router.update_rule_list(current_rules)

        # 更新Redis缓存
        if redis_conn:  # 确保连接可用
            try:
                redis_conn.set(REDIS_KEY, json.dumps(new_domains))
                logger.info(f"成功缓存{len(new_domains)}条域名到Redis")
            except Exception as e:
                logger.error(f"域名列表缓存失败: {str(e)}")
        else:
            logger.warning("Redis连接不可用，跳过缓存更新")

    except Exception as e:
        logger.error(f"执行过程中发生错误: {str(e)}")


if __name__ == "__main__":
    main()
    # roter = RouterController()
    # roter.login()
