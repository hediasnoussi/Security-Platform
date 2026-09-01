"""FastAPI application exposing the security analysis backend."""

from __future__ import annotations

from dataclasses import dataclass
import os
from threading import RLock
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from backend.alert_source import AlertBatch, AlertSource, DemoAlertSource, WazuhAlertSource
from backend.classifier import ClassificationResult, classify_alert
from backend.correlation import CorrelationGroup, DeduplicatedEvent, correlate_events, deduplicate_alerts
from backend.incidents import Incident, IncidentStore
from backend.models import NormalizedAlert
from backend.parser import parse_alerts
from backend.recommendations import Recommendation, generate_recommendations
from backend.risk_score import RiskAssessment, assess_event_risk


DEFAULT_MAX_ALERTS = 1000
DEFAULT_REFRESH_BATCH_SIZE = 200


@dataclass(frozen=True)
class AlertAnalysis:
    """In-memory analysis context for one normalized alert."""

    alert: NormalizedAlert
    event: DeduplicatedEvent
    classification: ClassificationResult
    risk_assessment: RiskAssessment
    recommendations: tuple[Recommendation, ...]
    incident: Incident


class RecommendationResponse(BaseModel):
    title: str
    priority: str
    description: str
    rationale: str
    actions: list[str]
    category: str


class AlertSummaryResponse(BaseModel):
    alert_id: str | None
    timestamp: str | None
    rule_id: str | None
    rule_level: int | None
    rule_description: str | None
    category: str
    subcategory: str
    risk_score: int
    risk_level: str
    agent_id: str | None
    agent_name: str | None
    source_user: str | None
    destination_user: str | None
    command: str | None
    event_id: str
    incident_id: str


class AlertDetailResponse(AlertSummaryResponse):
    rule_groups: list[str]
    location: str | None
    full_log: str | None
    extra_data: dict[str, Any]
    recommendations: list[RecommendationResponse]


class IncidentResponse(BaseModel):
    incident_id: str
    title: str
    description: str
    status: str
    severity: str
    risk_score: int
    category: str
    subcategory: str
    agent_id: str | None
    agent_name: str | None
    source_user: str | None
    destination_user: str | None
    first_seen: str | None
    last_seen: str | None
    event_ids: list[str]
    correlation_id: str | None
    recommendations: list[RecommendationResponse]
    created_at: str | None
    updated_at: str | None
    categories: list[str]
    source_alert_ids: list[str]


class StatisticsResponse(BaseModel):
    total_incidents: int
    critical: int
    high: int
    medium: int
    low: int


class HealthResponse(BaseModel):
    status: str = Field(default="ok")


class ErrorResponse(BaseModel):
    error: str
    detail: str
    errors: list[dict[str, Any]] | None = None


class SecurityAnalysisService:
    """Service layer orchestrating repository data and business modules."""

    def __init__(
        self,
        alert_source: AlertSource | None = None,
        incident_store: IncidentStore | None = None,
        max_alerts: int | None = None,
        refresh_batch_size: int | None = None,
    ) -> None:
        self._alert_source = alert_source or build_alert_source_from_environment()
        self._incident_store = incident_store or IncidentStore()
        self._max_alerts = _positive_int(
            max_alerts,
            "SECURITY_PLATFORM_MAX_ALERTS",
            DEFAULT_MAX_ALERTS,
        )
        self._refresh_batch_size = _positive_int(
            refresh_batch_size,
            "SECURITY_PLATFORM_REFRESH_BATCH_SIZE",
            DEFAULT_REFRESH_BATCH_SIZE,
        )
        self._refresh_lock = RLock()
        self._raw_alert_batch = AlertBatch(alerts=())
        self._source_offset = 0
        self._alerts: tuple[NormalizedAlert, ...] = ()
        self._events = tuple(deduplicate_alerts(self._alerts))
        self._groups = tuple(correlate_events(self._events))
        self._alert_analysis: tuple[AlertAnalysis, ...] = ()
        self._alert_analysis_by_id: dict[str, AlertAnalysis] = {}
        self._load_initial_alerts()

    def refresh(self) -> bool:
        """Read one bounded batch of new source alerts and rebuild if it changed."""

        with self._refresh_lock:
            batch = self._alert_source.get_alerts(
                offset=self._source_offset,
                limit=self._refresh_batch_size,
            )
            self._raw_alert_batch = batch
            self._source_offset = batch.next_offset
            return self._merge_batch(batch)

    def list_alerts(self) -> list[AlertAnalysis]:
        with self._refresh_lock:
            return list(self._alert_analysis)

    def get_alert(self, alert_id: str) -> AlertAnalysis:
        with self._refresh_lock:
            analysis = self._alert_analysis_by_id.get(alert_id)
            if analysis is None:
                raise KeyError(f"Alert not found: {alert_id}")
            return analysis

    def list_incidents(self) -> list[Incident]:
        with self._refresh_lock:
            return self._incident_store.list_incidents()

    def get_incident(self, incident_id: str) -> Incident:
        with self._refresh_lock:
            incident = self._incident_store.get(incident_id)
            if incident is None:
                raise KeyError(f"Incident not found: {incident_id}")
            return incident

    def get_statistics(self) -> StatisticsResponse:
        incidents = self.list_incidents()
        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
        }
        for incident in incidents:
            if incident.severity in counts:
                counts[incident.severity] += 1

        return StatisticsResponse(
            total_incidents=len(incidents),
            critical=counts["Critical"],
            high=counts["High"],
            medium=counts["Medium"],
            low=counts["Low"],
        )

    def _build_alert_analysis(self) -> tuple[AlertAnalysis, ...]:
        event_by_alert_id = self._event_by_alert_id()
        incident_by_event_id = self._incident_by_event_id()
        alert_analysis: list[AlertAnalysis] = []

        for alert in self._alerts:
            event = event_by_alert_id.get(alert.alert_id)
            if event is None:
                continue
            classification = classify_alert(event.representative_alert)
            risk_assessment = assess_event_risk(event)
            recommendations = tuple(
                generate_recommendations(
                    event,
                    classification=classification,
                    risk_assessment=risk_assessment,
                )
            )
            alert_analysis.append(
                AlertAnalysis(
                    alert=alert,
                    event=event,
                    classification=classification,
                    risk_assessment=risk_assessment,
                    recommendations=recommendations,
                    incident=incident_by_event_id[event.event_id],
                )
            )

        return tuple(alert_analysis)

    def _load_initial_alerts(self) -> None:
        """Scan the source once while retaining only the configured alert window."""

        with self._refresh_lock:
            while True:
                previous_offset = self._source_offset
                batch = self._alert_source.get_alerts(
                    offset=self._source_offset,
                    limit=self._refresh_batch_size,
                )
                self._raw_alert_batch = batch
                self._source_offset = batch.next_offset
                self._merge_batch(batch, rebuild=False)
                if self._source_offset <= previous_offset:
                    break

            self._rebuild_analysis()

    def _merge_batch(self, batch: AlertBatch, *, rebuild: bool = True) -> bool:
        incoming_alerts = tuple(parse_alerts(batch.alerts))
        merged_alerts = _merge_alert_window(
            self._alerts,
            incoming_alerts,
            self._max_alerts,
        )
        if merged_alerts == self._alerts:
            return False

        self._alerts = merged_alerts
        if rebuild:
            self._rebuild_analysis()
        return True

    def _rebuild_analysis(self) -> None:
        self._events = tuple(deduplicate_alerts(self._alerts))
        self._groups = tuple(correlate_events(self._events))
        self._incident_store.retain_active_context(
            {event.event_id for event in self._events},
            {
                alert.alert_id
                for alert in self._alerts
                if alert.alert_id is not None
            },
        )
        self._alert_analysis = self._build_alert_analysis()
        self._alert_analysis_by_id = {
            analysis.alert.alert_id: analysis
            for analysis in self._alert_analysis
            if analysis.alert.alert_id is not None
        }

    def _event_by_alert_id(self) -> dict[str, DeduplicatedEvent]:
        event_mapping: dict[str, DeduplicatedEvent] = {}
        for event in self._events:
            for alert in event.alerts or (event.representative_alert,):
                if alert.alert_id is not None:
                    event_mapping[alert.alert_id] = event
        return event_mapping

    def _incident_by_event_id(self) -> dict[str, Incident]:
        grouped_event_ids: set[str] = set()
        incident_mapping: dict[str, Incident] = {}

        for group in self._groups:
            incident = self._incident_store.get_or_create_incident(group)
            for event in group.events:
                grouped_event_ids.add(event.event_id)
                incident_mapping[event.event_id] = incident

        for event in self._events:
            if event.event_id in grouped_event_ids:
                continue
            incident_mapping[event.event_id] = self._incident_store.get_or_create_incident(event)

        return incident_mapping


def build_alert_source_from_environment() -> AlertSource:
    """Build the configured alert source without coupling the API to Wazuh paths."""

    mode = (
        os.getenv("SECURITY_PLATFORM_ALERT_SOURCE")
        or os.getenv("ALERT_SOURCE_MODE")
        or "DEMO"
    ).strip().upper()

    if mode == "DEMO":
        return DemoAlertSource()

    if mode == "WAZUH":
        alerts_path = (
            os.getenv("SECURITY_PLATFORM_WAZUH_ALERTS_PATH")
            or os.getenv("WAZUH_ALERTS_PATH")
        )
        if not alerts_path:
            raise ValueError(
                "WAZUH alert source mode requires SECURITY_PLATFORM_WAZUH_ALERTS_PATH "
                "or WAZUH_ALERTS_PATH."
            )
        return WazuhAlertSource(path=alerts_path)

    raise ValueError(f"Unsupported alert source mode: {mode}")


def _positive_int(value: int | None, environment_name: str, default: int) -> int:
    if value is not None:
        return value if value > 0 else default

    raw_value = os.getenv(environment_name)
    if raw_value is None:
        return default

    try:
        parsed_value = int(raw_value)
    except ValueError:
        return default
    return parsed_value if parsed_value > 0 else default


def _merge_alert_window(
    current_alerts: tuple[NormalizedAlert, ...],
    incoming_alerts: tuple[NormalizedAlert, ...],
    maximum_alerts: int,
) -> tuple[NormalizedAlert, ...]:
    """Keep the newest bounded alerts and avoid re-adding ids after rotation."""

    seen_alert_ids: set[str] = set()
    unique_reversed_alerts: list[NormalizedAlert] = []
    for alert in reversed((*current_alerts, *incoming_alerts)):
        if alert.alert_id is not None:
            if alert.alert_id in seen_alert_ids:
                continue
            seen_alert_ids.add(alert.alert_id)
        unique_reversed_alerts.append(alert)

    unique_alerts = list(reversed(unique_reversed_alerts))
    return tuple(unique_alerts[-maximum_alerts:])


def create_app(service: SecurityAnalysisService | None = None) -> FastAPI:
    """Create the FastAPI application with a pluggable analysis service."""

    app = FastAPI(title="Security Platform API", version="0.1.0")
    app.state.analysis_service = service or SecurityAnalysisService()

    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        _: Request,
        exc: HTTPException,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": _error_code(exc.status_code),
                "detail": str(exc.detail),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        _: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "error": "bad_request",
                "detail": "Invalid request.",
                "errors": exc.errors(),
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(
        _: Request,
        __: Exception,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_server_error",
                "detail": "Internal server error.",
            },
        )

    @app.get(
        "/health",
        response_model=HealthResponse,
        responses={500: {"model": ErrorResponse}},
    )
    def health() -> HealthResponse:
        return HealthResponse()

    @app.get(
        "/alerts",
        response_model=list[AlertSummaryResponse],
        responses={500: {"model": ErrorResponse}},
    )
    def list_alerts(
        analysis_service: SecurityAnalysisService = Depends(get_analysis_service),
    ) -> list[AlertSummaryResponse]:
        analysis_service.refresh()
        return [_alert_summary_response(item) for item in analysis_service.list_alerts()]

    @app.get(
        "/alerts/{alert_id}",
        response_model=AlertDetailResponse,
        responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    )
    def get_alert(
        alert_id: str,
        analysis_service: SecurityAnalysisService = Depends(get_analysis_service),
    ) -> AlertDetailResponse:
        analysis_service.refresh()
        try:
            analysis = analysis_service.get_alert(alert_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return _alert_detail_response(analysis)

    @app.get(
        "/incidents",
        response_model=list[IncidentResponse],
        responses={500: {"model": ErrorResponse}},
    )
    def list_incidents(
        analysis_service: SecurityAnalysisService = Depends(get_analysis_service),
    ) -> list[IncidentResponse]:
        analysis_service.refresh()
        return [_incident_response(incident) for incident in analysis_service.list_incidents()]

    @app.get(
        "/incidents/{incident_id}",
        response_model=IncidentResponse,
        responses={404: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    )
    def get_incident(
        incident_id: str,
        analysis_service: SecurityAnalysisService = Depends(get_analysis_service),
    ) -> IncidentResponse:
        analysis_service.refresh()
        try:
            incident = analysis_service.get_incident(incident_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return _incident_response(incident)

    @app.get(
        "/statistics",
        response_model=StatisticsResponse,
        responses={500: {"model": ErrorResponse}},
    )
    def get_statistics(
        analysis_service: SecurityAnalysisService = Depends(get_analysis_service),
    ) -> StatisticsResponse:
        analysis_service.refresh()
        return analysis_service.get_statistics()

    return app


def get_analysis_service(request: Request) -> SecurityAnalysisService:
    """FastAPI dependency exposing the current service instance."""

    return request.app.state.analysis_service


def _alert_summary_response(analysis: AlertAnalysis) -> AlertSummaryResponse:
    return AlertSummaryResponse(
        alert_id=analysis.alert.alert_id,
        timestamp=analysis.alert.timestamp,
        rule_id=analysis.alert.rule_id,
        rule_level=analysis.alert.rule_level,
        rule_description=analysis.alert.rule_description,
        category=analysis.classification.category,
        subcategory=analysis.classification.subcategory,
        risk_score=analysis.risk_assessment.score,
        risk_level=analysis.risk_assessment.level,
        agent_id=analysis.alert.agent_id,
        agent_name=analysis.alert.agent_name,
        source_user=analysis.alert.source_user,
        destination_user=analysis.alert.destination_user,
        command=analysis.alert.command,
        event_id=analysis.event.event_id,
        incident_id=analysis.incident.incident_id,
    )


def _alert_detail_response(analysis: AlertAnalysis) -> AlertDetailResponse:
    return AlertDetailResponse(
        **_alert_summary_response(analysis).model_dump(),
        rule_groups=list(analysis.alert.rule_groups),
        location=analysis.alert.location,
        full_log=analysis.alert.full_log,
        extra_data=analysis.alert.extra_data,
        recommendations=[
            _recommendation_response(recommendation)
            for recommendation in analysis.recommendations
        ],
    )


def _incident_response(incident: Incident) -> IncidentResponse:
    return IncidentResponse(
        incident_id=incident.incident_id,
        title=incident.title,
        description=incident.description,
        status=incident.status,
        severity=incident.severity,
        risk_score=incident.risk_score,
        category=incident.category,
        subcategory=incident.subcategory,
        agent_id=incident.agent_id,
        agent_name=incident.agent_name,
        source_user=incident.source_user,
        destination_user=incident.destination_user,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        event_ids=list(incident.event_ids),
        correlation_id=incident.correlation_id,
        recommendations=[
            _recommendation_response(recommendation)
            for recommendation in incident.recommendations
        ],
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        categories=list(incident.categories),
        source_alert_ids=list(incident.source_alert_ids),
    )


def _recommendation_response(
    recommendation: Recommendation,
) -> RecommendationResponse:
    return RecommendationResponse(
        title=recommendation.title,
        priority=recommendation.priority,
        description=recommendation.description,
        rationale=recommendation.rationale,
        actions=list(recommendation.actions),
        category=recommendation.category,
    )


def _error_code(status_code: int) -> str:
    return {
        400: "bad_request",
        404: "not_found",
        500: "internal_server_error",
    }.get(status_code, "http_error")


app = create_app()
