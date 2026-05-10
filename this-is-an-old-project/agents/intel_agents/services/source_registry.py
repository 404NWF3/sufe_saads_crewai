from __future__ import annotations

from typing import Any, Literal, cast

from backend.db.typing import SqlContext
from backend.db.unit_of_work import UnitOfWork

from ..schemas.source import RegisteredSourceDTO


class SourceRegistryService:
    """Registry and DB alignment service for first-wave WP1-1 sources."""

    @staticmethod
    def default_sources() -> list[RegisteredSourceDTO]:
        return [
            RegisteredSourceDTO(
                source_name="nvd",
                source_type="structured",
                base_uri="https://services.nvd.nist.gov/rest/json/cves/2.0",
                adapter_name="nvd",
                default_qps=0.15,
                default_max_results=20,
                default_time_window_days=30,
                auth_env_var="NVD_API_KEY",
                auth_type="header_api_key",
                pagination_style="offset",
                page_size_param="resultsPerPage",
                result_path="vulnerabilities",
            ),
            RegisteredSourceDTO(
                source_name="github_advisories",
                source_type="code",
                base_uri="https://api.github.com/graphql",
                adapter_name="github_advisories",
                default_qps=1.0,
                default_max_results=20,
                default_time_window_days=30,
                auth_env_var="GITHUB_TOKEN",
                auth_type="header_bearer",
                pagination_style="cursor",
                result_path="data.securityAdvisories.nodes",
            ),
            RegisteredSourceDTO(
                source_name="arxiv",
                source_type="paper",
                base_uri="https://export.arxiv.org/api/query",
                adapter_name="arxiv",
                default_qps=0.33,
                default_max_results=15,
                default_time_window_days=30,
                pagination_style="offset",
                page_size_param="max_results",
            ),
            RegisteredSourceDTO(
                source_name="reddit",
                source_type="community",
                base_uri="https://www.reddit.com",
                adapter_name="reddit",
                default_qps=0.1,
                default_max_results=10,
                default_time_window_days=7,
                pagination_style="feed",
                default_params={"subreddit": "netsec"},
            ),
            RegisteredSourceDTO(
                source_name="hackernews",
                source_type="community",
                base_uri="https://hn.algolia.com/api/v1/search",
                adapter_name="hackernews",
                default_qps=1.5,
                default_max_results=10,
                default_time_window_days=7,
                pagination_style="offset",
            ),
            RegisteredSourceDTO(
                source_name="cisa_kev",
                source_type="advisory",
                base_uri=(
                    "https://www.cisa.gov/sites/default/files/feeds/"
                    "known_exploited_vulnerabilities.json"
                ),
                adapter_name="cisa_kev",
                default_qps=0.2,
                default_max_results=50,
                default_time_window_days=90,
                pagination_style="none",
            ),
            RegisteredSourceDTO(
                source_name="mitre_attack",
                source_type="structured",
                base_uri=(
                    "https://raw.githubusercontent.com/mitre/cti/master/"
                    "enterprise-attack/enterprise-attack.json"
                ),
                adapter_name="mitre_attack",
                default_qps=0.1,
                default_max_results=30,
                default_time_window_days=90,
                pagination_style="none",
            ),
            RegisteredSourceDTO(
                source_name="github_discussions",
                source_type="code",
                base_uri="https://api.github.com/graphql",
                adapter_name="github_discussions",
                default_qps=1.0,
                default_max_results=20,
                default_time_window_days=30,
                auth_env_var="GITHUB_TOKEN",
                auth_type="header_bearer",
                pagination_style="cursor",
                enabled=True,
            ),
            RegisteredSourceDTO(
                source_name="vendor_advisories",
                source_type="advisory",
                base_uri="https://krebsonsecurity.com/feed/",
                adapter_name="vendor_advisories",
                default_qps=0.2,
                default_max_results=20,
                default_time_window_days=30,
                pagination_style="feed",
                enabled=True,
            ),
            RegisteredSourceDTO(
                source_name="huggingface",
                source_type="paper",
                base_uri="https://huggingface.co/api/models",
                adapter_name="huggingface",
                default_qps=0.5,
                default_max_results=20,
                default_time_window_days=30,
                auth_env_var="HF_TOKEN",
                auth_type="header_bearer",
                pagination_style="offset",
                enabled=True,
            ),
        ]

    def build_registry(
        self, overrides: list[dict[str, Any]] | None = None
    ) -> list[RegisteredSourceDTO]:
        registry = {item.source_name: item for item in self.default_sources()}
        for override in overrides or []:
            dto = RegisteredSourceDTO.model_validate(override)
            registry[dto.source_name] = dto
        return [registry[name] for name in sorted(registry)]

    def get_enabled_sources(
        self, overrides: list[dict[str, Any]] | None = None
    ) -> list[RegisteredSourceDTO]:
        return [item for item in self.build_registry(overrides) if item.enabled]

    def load_aligned_registry(
        self,
        *,
        prefer_db: bool,
        trace_id: str | None = None,
        overrides: list[dict[str, Any]] | None = None,
    ) -> tuple[list[RegisteredSourceDTO], dict[str, Any]]:
        code_registry = self.build_registry(overrides)
        db_sources = []
        report = {
            "prefer_db": prefer_db,
            "db_available": False,
            "code_only_sources": [],
            "db_only_sources": [],
            "aligned_sources": [],
        }
        if not prefer_db:
            report["aligned_sources"] = [
                item.source_name for item in code_registry if item.enabled
            ]
            return [item for item in code_registry if item.enabled], report

        try:
            with UnitOfWork(
                context=SqlContext(
                    trace_id=trace_id, agent_name="source_registry_alignment"
                ),
                read_only=True,
            ) as uow:
                db_sources = uow.sources.list_enabled_sources()
        except Exception:
            report["aligned_sources"] = [
                item.source_name for item in code_registry if item.enabled
            ]
            return [item for item in code_registry if item.enabled], report

        report["db_available"] = True
        code_map = {item.source_name: item for item in code_registry}
        db_names = {item.source_name for item in db_sources}
        code_names = set(code_map)
        report["code_only_sources"] = sorted(code_names - db_names)
        report["db_only_sources"] = sorted(db_names - code_names)

        aligned: list[RegisteredSourceDTO] = []
        for db_source in db_sources:
            base = code_map.get(db_source.source_name)
            if base is None:
                aligned.append(
                    RegisteredSourceDTO(
                        source_name=db_source.source_name,
                        source_type=_app_source_type_for_db_type(db_source.source_type),
                        base_uri=db_source.base_uri,
                        adapter_name=db_source.source_name,
                        enabled=db_source.enabled,
                        default_qps=float(db_source.default_qps),
                    )
                )
                continue
            aligned.append(
                base.model_copy(
                    update={
                        "base_uri": db_source.base_uri or base.base_uri,
                        "source_type": _app_source_type_for_db_type(
                            db_source.source_type
                        ),
                        "enabled": db_source.enabled,
                        "default_qps": float(db_source.default_qps),
                    }
                )
            )
        report["aligned_sources"] = [
            item.source_name for item in aligned if item.enabled
        ]
        return [item for item in aligned if item.enabled], report

    def bootstrap_sources_to_db(self, *, trace_id: str | None = None) -> dict[str, Any]:
        type_map = {
            "structured": ("cve_repo", 5),
            "code": ("github", 4),
            "paper": ("paper", 4),
            "community": ("forum", 3),
            "advisory": ("api", 4),
        }
        report = {"upserted": [], "failed": []}
        try:
            with UnitOfWork(
                context=SqlContext(
                    trace_id=trace_id, agent_name="source_registry_bootstrap"
                )
            ) as uow:
                for item in self.default_sources():
                    db_type, trust_level = type_map[item.source_type]
                    try:
                        created = uow.sources.upsert_source(
                            source_name=item.source_name,
                            source_type=db_type,
                            base_uri=item.base_uri,
                            trust_level=trust_level,
                            default_qps=float(item.default_qps),
                            enabled=item.enabled,
                        )
                        report["upserted"].append(created.source_name)
                    except Exception as exc:
                        report["failed"].append(
                            {"source_name": item.source_name, "error": str(exc)}
                        )
        except Exception as exc:
            report["failed"].append({"source_name": "__bootstrap__", "error": str(exc)})
        return report


def _app_source_type_for_db_type(
    db_type: str,
) -> Literal["structured", "code", "paper", "community", "advisory"]:
    mapping = {
        "cve_repo": "structured",
        "github": "code",
        "paper": "paper",
        "forum": "community",
        "api": "advisory",
        "darkweb": "advisory",
    }
    return cast(
        Literal["structured", "code", "paper", "community", "advisory"],
        mapping.get(db_type, "structured"),
    )
