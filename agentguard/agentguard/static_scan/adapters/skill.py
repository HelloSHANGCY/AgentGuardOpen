"""Skill 适配器：SKILL.md 与关联文件建独立资产。

同名 Skill 位于不同目录时不合并；文件名相同也按路径区分。
"""

import posixpath

from .base import BaseAdapter, DiscoveryResult, build_asset


class SkillAdapter(BaseAdapter):
    name = "skill"

    def supports(self, facts) -> bool:
        return bool(facts.index.skill_markdowns())

    def discover(self, facts, context) -> DiscoveryResult:
        result = DiscoveryResult()
        for skill_dir, skill_md in sorted(facts.index.skill_markdowns().items()):
            entry = facts.index.get(skill_md)
            doc = facts.markdown.get(skill_md)
            frontmatter = doc.frontmatter if doc else {}
            skill_name = str(frontmatter.get("name") or posixpath.basename(skill_dir))
            allowed = frontmatter.get("allowed-tools")
            files = [item.path for item in facts.index.files
                     if item.path == skill_md or item.path.startswith(skill_dir + "/")]
            asset = build_asset(
                context, "Skill", f"skill:{skill_dir}", skill_name,
                relative_path=skill_md, content_digest=entry.digest if entry else "",
                discovery_method="skill_md", confidence="high",
                metadata={
                    "dir": skill_dir,
                    "frontmatter": frontmatter,
                    "frontmatter_error": doc.frontmatter_error if doc else "",
                    "allowed_tools": allowed if isinstance(allowed, list) else None,
                    "allowed_tools_declared": "allowed-tools" in frontmatter,
                    "files": sorted(files),
                    "adapter": self.name,
                },
            )
            result.assets.append(asset)
            if entry is not None:
                result.evidence.append(facts.evidence_for(
                    skill_md, line=1, excerpt=entry.path, parser="markdown", pointer="/frontmatter"))
            for gap in ("frontmatter_error",):
                value = asset.metadata.get(gap)
                if value:
                    result.gaps.append(f"skill {skill_dir}: {value}")
        return result
