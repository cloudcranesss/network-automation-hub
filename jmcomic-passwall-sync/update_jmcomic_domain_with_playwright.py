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
from playwright.sync_api import sync_playwright
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
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=False)
                context = browser.new_context(viewport={"width": 1920, "height": 1080})
                page = context.new_page()

                # 页面导航
                page.goto(ROUTER_CONFIG["url"], timeout=ROUTER_CONFIG["timeout"] * 1000)

                # 登录操作
                page.fill("#cbi-input-user", ROUTER_CONFIG["username"])
                page.fill("#cbi-input-password", ROUTER_CONFIG["password"])
                page.click("input[value='登录']")

                # 等待登录完成
                page.wait_for_load_state("networkidle", timeout=ROUTER_CONFIG["timeout"] * 1000)

                # 获取认证信息
                self._get_auth_tokens(page)
                browser.close()

                logger.info("路由器登录成功")

        except Exception as e:
            logger.error(f"登录失败: {str(e)}")
            raise

    def _get_auth_tokens(self, page) -> None:
        """从页面中提取认证令牌（含增强型错误处理）"""
        try:
            # 优先提取并验证Token
            script_element = page.query_selector("xpath=//script[contains(., 'LuCI')]")
            if not script_element:
                raise ValueError("页面中未找到包含LuCI的脚本标签")

            script_content = script_element.inner_text()
            logger.debug(f"原始脚本内容: {script_content[:200]}...")  # 记录部分内容用于调试

            # 使用独立函数提取Token
            self.token = self._extract_and_validate_token(script_content)
            logger.info(f"Token提取成功（前4位后4位）：{self.token[:4]}****{self.token[-4:]}")

            # 获取并处理Cookies
            cookies = page.context.cookies()
            if not cookies:
                raise RuntimeError("获取到的Cookies为空")

            self.cookie = ";".join(
                f"{c['name']}={c['value']}"
                for c in sorted(cookies, key=lambda x: x['name'])  # 排序保证一致性
                if c['value']  # 过滤空值
            )
            logger.debug(f"生成Cookie字符串长度：{len(self.cookie)}")

        except Exception as e:
            logger.error("认证信息提取失败，详细原因：", exc_info=True)
            raise RuntimeError(f"无法完成认证流程: {str(e)}") from e

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
