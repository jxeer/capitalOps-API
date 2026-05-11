"""
ArcGIS REST API client for querying zoning hearings and rezoning data.

Provides methods to query county ArcGIS FeatureServer endpoints for
upcoming zoning hearings and rezoning applications.

Usage:
    features = query_hearings(
        base_url="https://maps.hcfl.gov/arcgis/rest/services/Planning/ZoningHearings/FeatureServer/0",
        parcel_number="12345"
    )
"""

import logging
import os
from typing import List, Dict, Any, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_PARCEL_FIELD = os.environ.get("ARCGIS_PARCEL_FIELD", "PARCEL_NUM")


def query_hearings(
    base_url: str,
    parcel_number: str,
    parcel_field: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Query an ArcGIS FeatureServer for hearings associated with a parcel.

    Args:
        base_url: The full base URL of the FeatureServer layer
                  (e.g., https://maps.hcfl.gov/arcgis/rest/services/.../FeatureServer/0)
        parcel_number: The parcel number to filter by
        parcel_field: The field name in the feature class for parcel numbers
                      (default: PARCEL_NUM from ARCGIS_PARCEL_FIELD env var)

    Returns:
        List of feature objects from the ArcGIS query, or empty list on failure
    """
    if not base_url or not parcel_number:
        return []

    field = parcel_field or DEFAULT_PARCEL_FIELD

    query_url = f"{base_url}/query"
    params = {
        "where": f"{field}='{parcel_number}'",
        "outFields": "*",
        "f": "json",
        "returnGeometry": "false"
    }

    try:
        response = requests.get(query_url, params=params, timeout=10)

        if response.status_code != 200:
            logger.warning(
                "ArcGIS query failed for URL %s: %s %s",
                base_url, response.status_code, response.text[:200]
            )
            return []

        json_data = response.json()

        if "error" in json_data:
            logger.warning(
                "ArcGIS returned error for parcel %s: %s",
                parcel_number, json_data.get("error", {})
            )
            return []

        features = json_data.get("features", [])
        return features if isinstance(features, list) else []

    except requests.exceptions.Timeout:
        logger.warning("ArcGIS request timeout for parcel %s, URL %s", parcel_number, base_url)
        return []
    except requests.exceptions.RequestException as e:
        logger.error("ArcGIS request exception for parcel %s: %s", parcel_number, e)
        return []
    except Exception as e:
        logger.error("ArcGIS parse error for parcel %s: %s", parcel_number, e)
        return []


def get_upcoming_hearings(base_url: str, days_ahead: int = 90) -> List[Dict[str, Any]]:
    """
    Query for all upcoming hearings within a date range.

    Args:
        base_url: The full base URL of the FeatureServer layer
        days_ahead: Number of days to look ahead for hearings

    Returns:
        List of feature objects for hearings within the date range, or empty list
    """
    if not base_url:
        return []

    from datetime import datetime, timedelta

    future_date = (datetime.now() + timedelta(days=days_ahead)).strftime("%Y-%m-%d")
    today = datetime.now().strftime("%Y-%m-%d")

    query_url = f"{base_url}/query"
    params = {
        "where": f"HEARING_DATE>='{today}' AND HEARING_DATE<='{future_date}'",
        "outFields": "*",
        "f": "json",
        "returnGeometry": "false",
        "orderbyFields": "HEARING_DATE ASC"
    }

    try:
        response = requests.get(query_url, params=params, timeout=10)

        if response.status_code != 200:
            logger.warning(
                "ArcGIS upcoming hearings query failed for URL %s: %s",
                base_url, response.status_code
            )
            return []

        json_data = response.json()

        if "error" in json_data:
            return []

        features = json_data.get("features", [])
        return features if isinstance(features, list) else []

    except Exception as e:
        logger.error("ArcGIS upcoming hearings error: %s", e)
        return []