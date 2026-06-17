"""
test_tag_rules.py —— pytest 测试：关键词规则引擎
覆盖：各标签的正向命中、负向不命中、多标签同时命中、空字段稳健性
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import pytest
from backend.app.rules.tag_rules import match_rules, TagResult, RuleMatchResult


# ── 工具函数 ──────────────────────────────────────────────────

def tag_names(result: RuleMatchResult) -> set:
    """从结果中提取标签名集合"""
    return {t.tag_name for t in result.tags}


# ══════════════════════════════════════════════════════════════
# 正向测试：各标签应被命中
# ══════════════════════════════════════════════════════════════

class TestTagRulesPositive:

    def test_dev_env_by_domain(self):
        """dev. 前缀域名应命中 dev_env"""
        res = match_rules(1, domain="dev.example.com")
        assert "dev_env" in tag_names(res)

    def test_test_env_by_domain(self):
        """staging. 前缀域名应命中 test_env"""
        res = match_rules(2, domain="staging.example.com")
        assert "test_env" in tag_names(res)

    def test_admin_panel_by_domain(self):
        """admin. 前缀域名应命中 admin_panel"""
        res = match_rules(3, domain="admin.example.com")
        assert "admin_panel" in tag_names(res)

    def test_admin_panel_by_title(self):
        """标题含「管理后台」应命中 admin_panel"""
        res = match_rules(4, title="企业管理后台 - 登录")
        assert "admin_panel" in tag_names(res)

    def test_login_page_by_title(self):
        """标题含 login 应命中 login_page"""
        res = match_rules(5, title="User Login")
        assert "login_page" in tag_names(res)

    def test_api_docs_exposed_swagger(self):
        """标题含 swagger ui 应命中 api_docs_exposed"""
        res = match_rules(6, title="Swagger UI")
        assert "api_docs_exposed" in tag_names(res)

    def test_database_exposed_by_port(self):
        """3306 端口应命中 database_exposed"""
        res = match_rules(7, port=3306)
        assert "database_exposed" in tag_names(res)

    def test_database_exposed_by_title(self):
        """标题含 phpmyadmin 应命中 database_exposed"""
        res = match_rules(8, title="phpMyAdmin - 数据库管理")
        assert "database_exposed" in tag_names(res)

    def test_high_risk_port_ssh(self):
        """22 端口应命中 high_risk_port"""
        res = match_rules(9, port=22)
        assert "high_risk_port" in tag_names(res)

    def test_high_risk_port_rdp(self):
        """3389 端口应命中 high_risk_port"""
        res = match_rules(10, port=3389)
        assert "high_risk_port" in tag_names(res)

    def test_directory_listing(self):
        """标题含 Index of / 应命中 directory_listing"""
        res = match_rules(11, title="Index of /var/www/html")
        assert "directory_listing" in tag_names(res)

    def test_middleware_exposed_jenkins(self):
        """标题含 Jenkins 应命中 middleware_exposed"""
        res = match_rules(12, title="Jenkins - Build History")
        assert "middleware_exposed" in tag_names(res)

    def test_middleware_exposed_server(self):
        """Server 头含 Tomcat 应命中 middleware_exposed"""
        res = match_rules(13, server="Apache Tomcat/9.0.65")
        assert "middleware_exposed" in tag_names(res)

    def test_backup_related(self):
        """domain 含 backup 应命中 backup_related"""
        res = match_rules(14, domain="backup.example.com")
        assert "backup_related" in tag_names(res)

    def test_default_page(self):
        """标题为 Welcome to nginx 应命中 default_page"""
        res = match_rules(15, title="Welcome to nginx!")
        assert "default_page" in tag_names(res)


# ══════════════════════════════════════════════════════════════
# 负向测试：正常资产不应误命中
# ══════════════════════════════════════════════════════════════

class TestTagRulesNegative:

    def test_normal_domain_no_false_positive(self):
        """普通 www 域名不应命中任何高风险标签"""
        res = match_rules(20, domain="www.example.com",
                          title="首页 - 企业官网", server="nginx")
        dangerous = tag_names(res) & {"high_risk_port", "database_exposed", "directory_listing"}
        assert len(dangerous) == 0

    def test_port_80_not_high_risk(self):
        """80 端口不应命中 high_risk_port"""
        res = match_rules(21, port=80)
        assert "high_risk_port" not in tag_names(res)

    def test_port_443_not_database(self):
        """443 端口不应命中 database_exposed"""
        res = match_rules(22, port=443)
        assert "database_exposed" not in tag_names(res)

    def test_empty_fields_no_crash(self):
        """所有字段为 None 时不应崩溃"""
        res = match_rules(23)
        assert isinstance(res, RuleMatchResult)
        assert res.matched_count == 0

    def test_empty_string_fields(self):
        """空字符串字段不应崩溃"""
        res = match_rules(24, domain="", title="", server="")
        assert isinstance(res, RuleMatchResult)


# ══════════════════════════════════════════════════════════════
# 多标签同时命中
# ══════════════════════════════════════════════════════════════

class TestTagRulesMultiple:

    def test_multiple_tags_simultaneously(self):
        """admin 域名 + SSH 端口应同时命中 admin_panel 和 high_risk_port"""
        res = match_rules(30,
                          domain="admin.example.com",
                          port=22,
                          title="管理后台 - 请登录")
        names = tag_names(res)
        assert "admin_panel"    in names
        assert "high_risk_port" in names
        assert "login_page"     in names

    def test_matched_rule_description_not_empty(self):
        """命中规则时 matched_rule 字段应有描述"""
        res = match_rules(31, domain="admin.example.com")
        admin_tag = next((t for t in res.tags if t.tag_name == "admin_panel"), None)
        assert admin_tag is not None
        assert len(admin_tag.matched_rule) > 0

    def test_return_type(self):
        """返回类型必须是 RuleMatchResult"""
        res = match_rules(32, domain="test.example.com")
        assert isinstance(res, RuleMatchResult)
        assert isinstance(res.tags, list)
        for tag in res.tags:
            assert isinstance(tag, TagResult)
