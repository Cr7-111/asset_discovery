"""
test_risk_engine.py —— pytest 测试：风险评分引擎
覆盖：各评分项、等级划分、分数上限、空字段处理
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import pytest
from backend.app.rules.risk_engine import calc_risk_score, score_to_level


# ── 工具函数 ──────────────────────────────────────────────────

def make_asset(tags=None, status_code=None, port=80, server=""):
    """构造标准化的资产输入 dict"""
    tag_list = [{"tag_name": t} for t in (tags or [])]
    return {
        "asset_id":    1,
        "tags":        tag_list,
        "status_code": status_code,
        "port":        port,
        "server":      server,
    }


# ══════════════════════════════════════════════════════════════
# 等级划分测试
# ══════════════════════════════════════════════════════════════

class TestScoreToLevel:

    def test_low_boundary(self):
        assert score_to_level(0)  == "low"
        assert score_to_level(29) == "low"

    def test_medium_boundary(self):
        assert score_to_level(30) == "medium"
        assert score_to_level(59) == "medium"

    def test_high_boundary(self):
        assert score_to_level(60) == "high"
        assert score_to_level(79) == "high"

    def test_critical_boundary(self):
        assert score_to_level(80)  == "critical"
        assert score_to_level(100) == "critical"


# ══════════════════════════════════════════════════════════════
# 各评分项测试
# ══════════════════════════════════════════════════════════════

class TestScoreItems:

    def test_database_exposed_adds_25(self):
        """database_exposed 标签应贡献 25 分"""
        asset = make_asset(tags=["database_exposed"])
        res = calc_risk_score(asset)
        assert res["risk_score"] == 25
        assert res["risk_level"] == "low"   # 25 < 30

    def test_admin_panel_adds_20(self):
        """admin_panel 标签应贡献 20 分"""
        asset = make_asset(tags=["admin_panel"])
        res = calc_risk_score(asset)
        assert res["risk_score"] == 20

    def test_high_risk_port_adds_20(self):
        """high_risk_port 标签应贡献 20 分"""
        asset = make_asset(tags=["high_risk_port"])
        res = calc_risk_score(asset)
        assert res["risk_score"] == 20

    def test_dev_env_adds_15(self):
        """dev_env 标签应贡献 15 分"""
        asset = make_asset(tags=["dev_env"])
        res = calc_risk_score(asset)
        assert res["risk_score"] == 15

    def test_test_env_adds_15(self):
        """test_env 标签应贡献 15 分"""
        asset = make_asset(tags=["test_env"])
        res = calc_risk_score(asset)
        assert res["risk_score"] == 15

    def test_api_docs_exposed_adds_15(self):
        """api_docs_exposed 标签应贡献 15 分"""
        asset = make_asset(tags=["api_docs_exposed"])
        res = calc_risk_score(asset)
        assert res["risk_score"] == 15

    def test_server_exposure_adds_10(self):
        """Server 头含版本号应贡献 10 分"""
        asset = make_asset(server="nginx/1.18.0")
        res = calc_risk_score(asset)
        # 命中 middleware_server 规则
        keys = [d["key"] for d in res["score_detail"]]
        assert "middleware_server" in keys

    def test_login_page_adds_5(self):
        """login_page 标签应贡献 5 分"""
        asset = make_asset(tags=["login_page"])
        res = calc_risk_score(asset)
        assert res["risk_score"] == 5

    def test_status_200_adds_5(self):
        """status_code=200 应贡献 5 分"""
        asset = make_asset(status_code=200)
        res = calc_risk_score(asset)
        assert res["risk_score"] == 5

    def test_status_non_200_no_score(self):
        """status_code≠200 不应贡献分数"""
        asset = make_asset(status_code=404)
        res = calc_risk_score(asset)
        assert res["risk_score"] == 0


# ══════════════════════════════════════════════════════════════
# 综合评分测试
# ══════════════════════════════════════════════════════════════

class TestScoreCombined:

    def test_critical_scenario(self):
        """高风险场景：数据库暴露+管理后台+高危端口 → critical"""
        asset = make_asset(
            tags=["database_exposed", "admin_panel", "high_risk_port"],
            status_code=200,
            server="Tomcat/9.0",
        )
        res = calc_risk_score(asset)
        # 25+20+20+5+10=80
        assert res["risk_score"] >= 80
        assert res["risk_level"] == "critical"

    def test_score_capped_at_100(self):
        """所有规则命中时分数不应超过 100"""
        asset = make_asset(
            tags=["database_exposed","admin_panel","high_risk_port",
                  "dev_env","test_env","api_docs_exposed","login_page"],
            status_code=200,
            server="nginx/1.18.0",
        )
        res = calc_risk_score(asset)
        assert res["risk_score"] <= 100

    def test_empty_asset_zero_score(self):
        """空资产应得 0 分，等级为 low"""
        res = calc_risk_score({})
        assert res["risk_score"] == 0
        assert res["risk_level"] == "low"

    def test_score_detail_and_suggestions_align(self):
        """score_detail 条数应与 suggestions 条数相同"""
        asset = make_asset(tags=["admin_panel", "login_page"], status_code=200)
        res = calc_risk_score(asset)
        assert len(res["score_detail"]) == len(res["suggestions"])

    def test_score_detail_structure(self):
        """score_detail 每条应包含 key/score/description 字段"""
        asset = make_asset(tags=["admin_panel"])
        res = calc_risk_score(asset)
        for item in res["score_detail"]:
            assert "key"         in item
            assert "score"       in item
            assert "description" in item

    def test_medium_level(self):
        """admin_panel(20) + login_page(5) + status_200(5) = 30 → medium"""
        asset = make_asset(tags=["admin_panel", "login_page"], status_code=200)
        res = calc_risk_score(asset)
        assert res["risk_score"] == 30
        assert res["risk_level"] == "medium"
