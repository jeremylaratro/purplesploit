"""
SIEM Integrations for PurpleSploit

Sends security events to SIEM platforms (Splunk, Elastic, generic webhooks).
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from abc import abstractmethod
import json
import logging

from .base import (
    BaseIntegration,
    IntegrationConfig,
    IntegrationStatus,
    NotificationPayload,
    NotificationPriority,
    WebhookMixin,
)

logger = logging.getLogger(__name__)

# Optional requests import
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class SIEMConfig(IntegrationConfig):
    """Base SIEM configuration."""
    webhook_url: str = ""
    source_type: str = "purplesploit"
    index: str = "security"
    verify_ssl: bool = True
    custom_headers: Dict[str, str] = field(default_factory=dict)


class SIEMWebhook(BaseIntegration, WebhookMixin):
    """
    Generic SIEM webhook integration.

    Sends JSON-formatted security events to any webhook endpoint.
    Compatible with most SIEM platforms that accept HTTP input.
    """

    def __init__(self, config: Optional[SIEMConfig] = None):
        if config is None:
            config = SIEMConfig(name="siem_webhook")
        super().__init__(config)
        self.siem_config: SIEMConfig = config

    def connect(self) -> bool:
        """Verify webhook endpoint."""
        if not REQUESTS_AVAILABLE:
            self._error_message = "requests library not installed"
            self.status = IntegrationStatus.ERROR
            return False

        if not self.siem_config.webhook_url:
            self._error_message = "No webhook_url configured"
            self.status = IntegrationStatus.ERROR
            return False

        self.status = IntegrationStatus.CONNECTED
        return True

    def disconnect(self) -> bool:
        """Disconnect from SIEM."""
        self.status = IntegrationStatus.DISCONNECTED
        return True

    def test_connection(self) -> Dict[str, Any]:
        """Test SIEM connection with a test event."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            test_event = {
                "event_type": "test",
                "source": "purplesploit",
                "message": "Connection test",
                "timestamp": datetime.utcnow().isoformat(),
            }

            response = requests.post(
                self.siem_config.webhook_url,
                headers=self._get_headers(),
                json=test_event,
                timeout=self.config.timeout,
                verify=self.siem_config.verify_ssl,
            )

            if response.status_code in (200, 201, 202, 204):
                return {"success": True, "status_code": response.status_code}
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "PurpleSploit/1.0",
        }
        headers.update(self.siem_config.custom_headers)
        return headers

    def send_notification(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Send event to SIEM webhook."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        if not self._check_rate_limit():
            return {"success": False, "error": "Rate limited"}

        try:
            event = self._build_event(payload)

            response = requests.post(
                self.siem_config.webhook_url,
                headers=self._get_headers(),
                json=event,
                timeout=self.config.timeout,
                verify=self.siem_config.verify_ssl,
            )

            self._record_request()

            if response.status_code in (200, 201, 202, 204):
                return {"success": True, "status_code": response.status_code}
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)

    def _build_event(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Build SIEM event from notification payload."""
        return {
            "event_type": "security_finding",
            "source": payload.source,
            "sourcetype": self.siem_config.source_type,
            "timestamp": payload.timestamp.isoformat(),
            "title": payload.title,
            "message": payload.message,
            "severity": payload.severity,
            "priority": payload.priority.value,
            "target": payload.target,
            "finding_id": payload.finding_id,
            "cvss_score": payload.cvss_score,
            "tags": payload.tags,
            "extra_data": payload.extra_data,
        }

    def send_finding(
        self,
        title: str,
        description: str,
        severity: str,
        target: str,
        finding_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        tags: Optional[List[str]] = None,
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Send a finding to the SIEM.

        Args:
            title: Finding title
            description: Finding description
            severity: Severity level
            target: Affected target
            finding_id: Optional finding ID
            cvss_score: Optional CVSS score
            tags: Optional tags
            extra_data: Additional data to include

        Returns:
            Result dict with success status
        """
        payload = NotificationPayload(
            title=title,
            message=description,
            severity=severity,
            target=target,
            finding_id=finding_id,
            cvss_score=cvss_score,
            tags=tags or [],
            extra_data=extra_data or {},
        )

        return self.send_notification(payload)

    def send_scan_event(
        self,
        event_type: str,
        scan_name: str,
        target: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Send a scan lifecycle event to the SIEM.

        Args:
            event_type: Event type (scan_started, scan_completed, scan_failed)
            scan_name: Name of the scan/module
            target: Target being scanned
            status: Scan status
            details: Additional details

        Returns:
            Result dict with success status
        """
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            event = {
                "event_type": event_type,
                "source": "purplesploit",
                "sourcetype": self.siem_config.source_type,
                "timestamp": datetime.utcnow().isoformat(),
                "scan_name": scan_name,
                "target": target,
                "status": status,
                "details": details or {},
            }

            response = requests.post(
                self.siem_config.webhook_url,
                headers=self._get_headers(),
                json=event,
                timeout=self.config.timeout,
                verify=self.siem_config.verify_ssl,
            )

            if response.status_code in (200, 201, 202, 204):
                return {"success": True}
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}",
                }

        except Exception as e:
            return self._handle_error(e)


@dataclass
class SplunkConfig(SIEMConfig):
    """Splunk-specific configuration."""
    hec_token: str = ""
    hec_url: str = ""  # e.g., https://splunk:8088/services/collector


class SplunkIntegration(SIEMWebhook):
    """
    Splunk HTTP Event Collector (HEC) integration.

    Sends events to Splunk via the HEC endpoint with proper formatting.
    """

    def __init__(self, config: Optional[SplunkConfig] = None):
        if config is None:
            config = SplunkConfig(name="splunk")
        super().__init__(config)
        self.splunk_config: SplunkConfig = config

    def _get_headers(self) -> Dict[str, str]:
        """Get Splunk HEC headers."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Splunk {self.splunk_config.hec_token}",
        }
        headers.update(self.splunk_config.custom_headers)
        return headers

    @property
    def _endpoint(self) -> str:
        """Get HEC endpoint URL."""
        return self.splunk_config.hec_url or self.splunk_config.webhook_url

    def connect(self) -> bool:
        """Verify Splunk HEC connection."""
        if not REQUESTS_AVAILABLE:
            self._error_message = "requests library not installed"
            self.status = IntegrationStatus.ERROR
            return False

        if not self._endpoint:
            self._error_message = "No hec_url configured"
            self.status = IntegrationStatus.ERROR
            return False

        if not self.splunk_config.hec_token:
            self._error_message = "No hec_token configured"
            self.status = IntegrationStatus.ERROR
            return False

        result = self.test_connection()
        if result.get("success"):
            self.status = IntegrationStatus.CONNECTED
            return True
        return False

    def test_connection(self) -> Dict[str, Any]:
        """Test Splunk HEC connection."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            # Splunk HEC health check endpoint
            health_url = self._endpoint.replace("/collector", "/collector/health")

            response = requests.get(
                health_url,
                headers=self._get_headers(),
                timeout=self.config.timeout,
                verify=self.splunk_config.verify_ssl,
            )

            if response.status_code == 200:
                return {"success": True, "status": "healthy"}
            else:
                # Try sending a test event instead
                return self._send_test_event()

        except Exception as e:
            return self._handle_error(e)

    def _send_test_event(self) -> Dict[str, Any]:
        """Send a test event to verify HEC."""
        try:
            event = {
                "event": {
                    "event_type": "test",
                    "source": "purplesploit",
                    "message": "HEC connection test",
                },
                "sourcetype": self.splunk_config.source_type,
                "index": self.splunk_config.index,
            }

            response = requests.post(
                self._endpoint,
                headers=self._get_headers(),
                json=event,
                timeout=self.config.timeout,
                verify=self.splunk_config.verify_ssl,
            )

            if response.status_code == 200:
                return {"success": True, "status": "test_event_sent"}
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def send_notification(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Send event to Splunk HEC."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        if not self._check_rate_limit():
            return {"success": False, "error": "Rate limited"}

        try:
            # Build Splunk HEC event format
            splunk_event = {
                "event": self._build_event(payload),
                "sourcetype": self.splunk_config.source_type,
                "index": self.splunk_config.index,
                "time": payload.timestamp.timestamp(),
            }

            response = requests.post(
                self._endpoint,
                headers=self._get_headers(),
                json=splunk_event,
                timeout=self.config.timeout,
                verify=self.splunk_config.verify_ssl,
            )

            self._record_request()

            if response.status_code == 200:
                return {"success": True}
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)

    def send_batch(self, events: List[NotificationPayload]) -> Dict[str, Any]:
        """
        Send multiple events in a batch.

        Args:
            events: List of notification payloads

        Returns:
            Result dict with success count
        """
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            # Build batch payload (newline-delimited JSON)
            batch_data = ""
            for payload in events:
                splunk_event = {
                    "event": self._build_event(payload),
                    "sourcetype": self.splunk_config.source_type,
                    "index": self.splunk_config.index,
                    "time": payload.timestamp.timestamp(),
                }
                batch_data += json.dumps(splunk_event) + "\n"

            response = requests.post(
                self._endpoint,
                headers=self._get_headers(),
                data=batch_data,
                timeout=self.config.timeout * 2,
                verify=self.splunk_config.verify_ssl,
            )

            if response.status_code == 200:
                return {"success": True, "events_sent": len(events)}
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)


@dataclass
class ElasticConfig(SIEMConfig):
    """Elasticsearch-specific configuration."""
    cloud_id: Optional[str] = None
    api_key_id: Optional[str] = None
    api_key_secret: Optional[str] = None
    index_pattern: str = "purplesploit-findings"


class ElasticIntegration(SIEMWebhook):
    """
    Elasticsearch integration.

    Sends events to Elasticsearch via REST API or Cloud.
    """

    def __init__(self, config: Optional[ElasticConfig] = None):
        if config is None:
            config = ElasticConfig(name="elasticsearch")
        super().__init__(config)
        self.elastic_config: ElasticConfig = config

    def _get_headers(self) -> Dict[str, str]:
        """Get Elasticsearch headers."""
        headers = {
            "Content-Type": "application/json",
        }

        if self.elastic_config.api_key_id and self.elastic_config.api_key_secret:
            import base64
            credentials = f"{self.elastic_config.api_key_id}:{self.elastic_config.api_key_secret}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"ApiKey {encoded}"
        elif self.elastic_config.api_key:
            headers["Authorization"] = f"ApiKey {self.elastic_config.api_key}"

        headers.update(self.elastic_config.custom_headers)
        return headers

    @property
    def _base_url(self) -> str:
        """Get Elasticsearch base URL."""
        return self.elastic_config.webhook_url.rstrip("/")

    def connect(self) -> bool:
        """Verify Elasticsearch connection."""
        if not REQUESTS_AVAILABLE:
            self._error_message = "requests library not installed"
            self.status = IntegrationStatus.ERROR
            return False

        if not self._base_url:
            self._error_message = "No webhook_url (Elasticsearch URL) configured"
            self.status = IntegrationStatus.ERROR
            return False

        result = self.test_connection()
        if result.get("success"):
            self.status = IntegrationStatus.CONNECTED
            return True
        return False

    def test_connection(self) -> Dict[str, Any]:
        """Test Elasticsearch connection."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            response = requests.get(
                self._base_url,
                headers=self._get_headers(),
                timeout=self.config.timeout,
                verify=self.elastic_config.verify_ssl,
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "cluster_name": data.get("cluster_name"),
                    "version": data.get("version", {}).get("number"),
                }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)

    def send_notification(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Send event to Elasticsearch."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        if not self._check_rate_limit():
            return {"success": False, "error": "Rate limited"}

        try:
            doc = self._build_event(payload)
            doc["@timestamp"] = payload.timestamp.isoformat()

            # Generate index name with date
            index_name = f"{self.elastic_config.index_pattern}-{datetime.utcnow().strftime('%Y.%m.%d')}"

            response = requests.post(
                f"{self._base_url}/{index_name}/_doc",
                headers=self._get_headers(),
                json=doc,
                timeout=self.config.timeout,
                verify=self.elastic_config.verify_ssl,
            )

            self._record_request()

            if response.status_code in (200, 201):
                data = response.json()
                return {
                    "success": True,
                    "index": data.get("_index"),
                    "id": data.get("_id"),
                }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)

    def send_bulk(self, events: List[NotificationPayload]) -> Dict[str, Any]:
        """
        Send multiple events using bulk API.

        Args:
            events: List of notification payloads

        Returns:
            Result dict with success count
        """
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            index_name = f"{self.elastic_config.index_pattern}-{datetime.utcnow().strftime('%Y.%m.%d')}"

            # Build bulk request body (NDJSON format)
            bulk_data = ""
            for payload in events:
                # Action line
                bulk_data += json.dumps({"index": {"_index": index_name}}) + "\n"
                # Document line
                doc = self._build_event(payload)
                doc["@timestamp"] = payload.timestamp.isoformat()
                bulk_data += json.dumps(doc) + "\n"

            response = requests.post(
                f"{self._base_url}/_bulk",
                headers={**self._get_headers(), "Content-Type": "application/x-ndjson"},
                data=bulk_data,
                timeout=self.config.timeout * 2,
                verify=self.elastic_config.verify_ssl,
            )

            if response.status_code == 200:
                data = response.json()
                errors = data.get("errors", False)
                return {
                    "success": not errors,
                    "events_sent": len(events),
                    "errors": errors,
                }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)

    def search_findings(
        self,
        query: Optional[str] = None,
        severity: Optional[str] = None,
        target: Optional[str] = None,
        from_date: Optional[datetime] = None,
        size: int = 100,
    ) -> Dict[str, Any]:
        """
        Search for findings in Elasticsearch.

        Args:
            query: Search query string
            severity: Filter by severity
            target: Filter by target
            from_date: Filter from this date
            size: Maximum results

        Returns:
            Result dict with matching findings
        """
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            # Build query
            must_clauses = []
            if query:
                must_clauses.append({"query_string": {"query": query}})
            if severity:
                must_clauses.append({"term": {"severity": severity.lower()}})
            if target:
                must_clauses.append({"term": {"target.keyword": target}})
            if from_date:
                must_clauses.append({
                    "range": {"@timestamp": {"gte": from_date.isoformat()}}
                })

            search_body = {
                "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
                "size": size,
                "sort": [{"@timestamp": {"order": "desc"}}],
            }

            response = requests.post(
                f"{self._base_url}/{self.elastic_config.index_pattern}-*/_search",
                headers=self._get_headers(),
                json=search_body,
                timeout=self.config.timeout,
                verify=self.elastic_config.verify_ssl,
            )

            if response.status_code == 200:
                data = response.json()
                hits = data.get("hits", {})
                findings = [hit.get("_source") for hit in hits.get("hits", [])]
                return {
                    "success": True,
                    "total": hits.get("total", {}).get("value", 0),
                    "findings": findings,
                }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)
