from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..schemas.source import SourceHealthRowDTO


class SourceHealthService:
    def build_dashboard(
        self,
        source_execution_stats: list[dict[str, Any]],
        *,
        drift_threshold: float,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in source_execution_stats:
            grouped[row["source_name"]].append(row)

        dashboard: list[dict[str, Any]] = []
        drift_alerts: list[dict[str, Any]] = []
        for source_name, rows in grouped.items():
            total = len(rows)
            success_count = sum(1 for row in rows if row.get("success", False))
            degraded_count = sum(
                1 for row in rows if row.get("degraded_from_live", False)
            )
            total_items = sum(int(row.get("item_count", 0)) for row in rows)
            avg_latency = sum(float(row.get("latency_ms", 0.0)) for row in rows) / max(
                total, 1
            )
            drift_reason = None
            drift_detected = False
            if total and (total_items / total) <= drift_threshold:
                drift_detected = True
                drift_reason = "low_result_yield"
            elif any(row.get("error_type") for row in rows):
                drift_detected = True
                drift_reason = "elevated_error_rate"

            dashboard.append(
                SourceHealthRowDTO(
                    source_name=source_name,
                    success_rate=round(success_count / max(total, 1), 3),
                    degraded_rate=round(degraded_count / max(total, 1), 3),
                    avg_latency_ms=round(avg_latency, 3),
                    total_queries=total,
                    total_items=total_items,
                    drift_detected=drift_detected,
                    drift_reason=drift_reason,
                ).model_dump(mode="python")
            )
            if drift_detected:
                drift_alerts.append(
                    {
                        "source_name": source_name,
                        "drift_reason": drift_reason,
                        "observed_queries": total,
                        "observed_items": total_items,
                    }
                )
        dashboard.sort(key=lambda row: row["source_name"])
        drift_alerts.sort(key=lambda row: row["source_name"])
        return dashboard, drift_alerts
