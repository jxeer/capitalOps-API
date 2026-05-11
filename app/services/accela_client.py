"""
Accela Civic Platform API client.

Provides a thin wrapper around the Accela API for querying permit and
entitlement records from Hillsborough and Pinellas counties.

Authentication:
    Uses OAuth2 client credentials flow. Tokens are cached and refreshed
    automatically when expired.

Usage:
    client = AccelaClient("hillsboroughcountyfl")
    records = client.search_records(parcel_number="12345")
    workflow = client.get_workflow(record_id="ABC123")
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any

import requests

logger = logging.getLogger(__name__)


class AccelaTokenManager:
    """
    Manages OAuth2 access tokens for the Accela API.

    Tokens are cached with their expiry time. The next request will
    automatically fetch a new token when the current one expires.
    """

    def __init__(self, agency: str):
        self.agency = agency
        self._token: Optional[str] = None
        self._expires_at: Optional[datetime] = None

    def get_token(self, client_id: str, client_secret: str, base_url: str) -> Optional[str]:
        """
        Fetch an OAuth2 access token using client credentials.

        Returns cached token if still valid, otherwise fetches a new one.

        Args:
            client_id: Accela API client ID
            client_secret: Accela API client secret
            base_url: Accela API base URL (e.g., https://apis.accela.com)

        Returns:
            Access token string, or None if fetch failed
        """
        now = datetime.utcnow()

        if self._token and self._expires_at and now < self._expires_at:
            return self._token

        token_url = f"{base_url}/oauth2/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "records inspections workflow"
        }

        try:
            response = requests.post(
                token_url,
                data=data,
                timeout=10,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if response.status_code != 200:
                logger.warning(
                    "Accela token fetch failed for agency %s: %s %s",
                    self.agency, response.status_code, response.text
                )
                return None

            json_data = response.json()
            self._token = json_data.get("access_token")
            expires_in = json_data.get("expires_in", 3600)

            self._expires_at = now + timedelta(seconds=int(expires_in) - 60)

            return self._token

        except requests.exceptions.RequestException as e:
            logger.error("Accela token request exception for agency %s: %s", self.agency, e)
            return None


class AccelaClient:
    """
    Client for the Accela Civic Platform API.

    Provides methods for searching records and fetching workflow/inspection data.
    Use one client instance per county agency.
    """

    def __init__(self, agency: str):
        """
        Initialize an Accela API client for a specific county agency.

        Args:
            agency: Agency identifier (e.g., "hillsboroughcountyfl", "pinellascountyfl")
        """
        self.agency = agency
        self.base_url = os.environ.get("ACCELA_BASE_URL", "https://apis.accela.com")
        self.client_id = os.environ.get("ACCELA_CLIENT_ID")
        self.client_secret = os.environ.get("ACCELA_CLIENT_SECRET")
        self.token_manager = AccelaTokenManager(agency)
        self._session = requests.Session()

    def _request(self, method: str, path: str, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Make an authenticated request to the Accela API.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: API endpoint path (e.g., /v4/records)
            **kwargs: Additional arguments to pass to requests

        Returns:
            Parsed JSON response, or None on failure
        """
        if not self.client_id or not self.client_secret:
            logger.warning("Accela credentials not configured for agency %s", self.agency)
            return None

        token = self.token_manager.get_token(self.client_id, self.client_secret, self.base_url)
        if not token:
            logger.warning("Failed to get Accela token for agency %s", self.agency)
            return None

        url = f"{self.base_url}{path}"
        kwargs.setdefault("timeout", 10)
        kwargs.setdefault("headers", {})
        kwargs["headers"]["Authorization"] = f"Bearer {token}"

        try:
            response = self._session.request(method, url, **kwargs)

            if response.status_code >= 400:
                logger.warning(
                    "Accela API error for agency %s %s %s: %s %s",
                    self.agency, method, path, response.status_code, response.text[:200]
                )
                return None

            return response.json() if response.content else {}

        except requests.exceptions.Timeout:
            logger.warning("Accela request timeout for agency %s %s %s", self.agency, method, path)
            return None
        except requests.exceptions.RequestException as e:
            logger.error("Accela request exception for agency %s %s %s: %s", self.agency, method, path, e)
            return None

    def search_records(
        self,
        parcel_number: Optional[str] = None,
        address: Optional[str] = None,
        record_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Search for permit/entitlement records.

        Args:
            parcel_number: Filter by parcel number
            address: Filter by street address
            record_type: Filter by record type (e.g., "Building", "Planning")
            status: Filter by record status
            limit: Maximum number of records to return

        Returns:
            List of record objects, or empty list on failure
        """
        params = {"limit": limit}

        if parcel_number:
            params["filters"] = f"parcel_number={parcel_number}"
        if address:
            params["filters"] = f"address={address}"
        if record_type:
            params["recordType"] = record_type
        if status:
            params["status"] = status

        result = self._request("GET", f"/v4/{self.agency}/records", params=params)

        if result is None:
            return []

        records = result.get("result", []) or result.get("records", [])
        return records if isinstance(records, list) else []

    def get_workflow(self, record_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the current workflow/task status for a record.

        Args:
            record_id: The record ID to fetch workflow for

        Returns:
            Workflow object with tasks and current status, or None on failure
        """
        return self._request("GET", f"/v4/{self.agency}/records/{record_id}/workflow")

    def get_inspections(self, record_id: str) -> List[Dict[str, Any]]:
        """
        Get the inspection history for a record.

        Args:
            record_id: The record ID to fetch inspections for

        Returns:
            List of inspection objects, or empty list on failure
        """
        result = self._request("GET", f"/v4/{self.agency}/records/{record_id}/inspections")

        if result is None:
            return []

        inspections = result.get("result", []) or result.get("inspections", [])
        return inspections if isinstance(inspections, list) else []

    def get_record(self, record_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a single record by ID.

        Args:
            record_id: The record ID to fetch

        Returns:
            Record object, or None on failure
        """
        return self._request("GET", f"/v4/{self.agency}/records/{record_id}")