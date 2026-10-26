"""管理接口鉴权：设备、规则库、行为基线、大模型研判等管理面共用（X-AG-Admin-Token）。"""

import hmac

from fastapi import HTTPException


def require_admin(settings, token: str | None, area: str = "admin") -> None:
    """本地测试模式且未配置令牌时放行，否则必须与 AG_AGENT_ADMIN_TOKEN 一致（与评测管理面规则相同）。"""
    expected = settings.agent_admin_token
    if settings.local_test and not expected:
        return
    if not expected:
        raise HTTPException(503, f"{area} disabled: set AG_AGENT_ADMIN_TOKEN or AG_LOCAL_TEST=1")
    if not token or not hmac.compare_digest(token.encode(), expected.encode()):
        raise HTTPException(401, "invalid admin token")
