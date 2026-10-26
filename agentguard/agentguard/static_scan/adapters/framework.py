"""框架与依赖适配器：依赖声明、import 与镜像引用。

声明范围与锁定版本分别保存，不把范围当作实际安装版本。
"""

from ..parsers.deps import framework_for_package
from .base import BaseAdapter, DiscoveryResult, build_asset


class FrameworkAdapter(BaseAdapter):
    name = "framework"

    def supports(self, facts) -> bool:
        return bool(facts.dependencies or facts.py_modules)

    def discover(self, facts, context) -> DiscoveryResult:
        result = DiscoveryResult()
        declared: dict = {}

        for dep in facts.dependencies:
            framework = framework_for_package(dep.name)
            if dep.ecosystem == "docker":
                asset = build_asset(
                    context, "Dependency", f"dep:docker:{dep.name}", dep.name,
                    relative_path=dep.source_path, version=dep.version,
                    discovery_method="dockerfile", confidence="high",
                    metadata={"ecosystem": "docker", "image": dep.image,
                              "pinned": bool(dep.version), "adapter": self.name},
                )
                result.assets.append(asset)
                _add_dep_evidence(facts, result, dep)
                continue
            if framework:
                category, display = framework
                asset = build_asset(
                    context, "Framework", f"framework:{dep.ecosystem}:{dep.name}", display,
                    relative_path=dep.source_path, version=dep.version,
                    discovery_method="dependency", confidence="high",
                    metadata={"package": dep.name, "ecosystem": dep.ecosystem,
                              "category": category, "specifier": dep.specifier,
                              "resolved": dep.resolved, "source_kind": dep.source_kind,
                              "adapter": self.name},
                )
                declared[f"{dep.ecosystem}:{dep.name}"] = asset
            else:
                asset = build_asset(
                    context, "Dependency", f"dep:{dep.ecosystem}:{dep.name}", dep.name,
                    relative_path=dep.source_path, version=dep.version,
                    discovery_method=dep.source_kind or "dependency",
                    confidence="high" if dep.resolved else "medium",
                    metadata={"ecosystem": dep.ecosystem, "specifier": dep.specifier,
                              "resolved": dep.resolved, "source_kind": dep.source_kind,
                              "adapter": self.name},
                )
            result.assets.append(asset)
            _add_dep_evidence(facts, result, dep)

        # import 证据：声明之外的框架引用只标 medium，且不猜测版本。
        for path, module in facts.py_modules.items():
            if module.parse_error:
                continue
            for import_ref in module.imports:
                root = (import_ref.module or import_ref.name).split(".")[0]
                framework = framework_for_package(root)
                if not framework:
                    continue
                category, display = framework
                key = f"pypi:{root}"
                if key in declared:
                    continue
                logical = f"framework:pypi:{root}"
                asset = build_asset(
                    context, "Framework", logical, display, relative_path=path,
                    discovery_method="import", confidence="medium",
                    metadata={"package": root, "ecosystem": "pypi", "category": category,
                              "adapter": self.name},
                )
                result.assets.append(asset)
                declared[key] = asset
                result.evidence.append(facts.evidence_for(
                    path, line=import_ref.lineno, excerpt=f"import {import_ref.module or import_ref.name}",
                    parser="ast"))
        return result


def _add_dep_evidence(facts, result: DiscoveryResult, dep) -> None:
    if dep.source_path:
        result.evidence.append(facts.evidence_for(
            dep.source_path, line=dep.line,
            excerpt=dep.image or f"{dep.name}{dep.specifier}",
            parser="dependency"))
