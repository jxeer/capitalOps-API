"""
Entitlement status polling service.

Monitors permit and entitlement status from Accela and ArcGIS data sources,
writes changes to EntitlementRecord/PermitEvent models, and triggers
notifications via create_notification().

The poller runs as a BackgroundScheduler job, not inside the Flask request cycle.
It is initialized in app/__init__.py and only starts when FLASK_ENV is not 'testing'.

Environment Variables (all required for polling to run):
    POLLER_INTERVAL_MINUTES: Minutes between poll cycles (default: 30)
    ACCELA_BASE_URL: Accela API base URL
    ACCELA_CLIENT_ID: Accela OAuth client ID
    ACCELA_CLIENT_SECRET: Accela OAuth client secret
    ACCELA_HILLSBOROUGH_AGENCY: Agency ID for Hillsborough County
    ACCELA_PINELLAS_AGENCY: Agency ID for Pinellas County
    HILLSBOROUGH_ARCGIS_HEARINGS_URL: ArcGIS FeatureServer URL for Hillsborough hearings
    PINELLAS_ARCGIS_HEARINGS_URL: ArcGIS FeatureServer URL for Pinellas hearings
    ARCGIS_PARCEL_FIELD: Field name for parcel number in ArcGIS queries
"""

import logging
import os
from datetime import datetime
from typing import Optional, Dict, Any, List, Set

from app import db
from app.models import EntitlementRecord, PermitEvent, Project
from app.notifications import create_notification

logger = logging.getLogger(__name__)

COUNTY_AGENCIES = {
    "hillsborough": {
        "accela_agency": os.environ.get("ACCELA_HILLSBOROUGH_AGENCY", "hillsboroughcountyfl"),
        "arcgis_url": os.environ.get("HILLSBOROUGH_ARCGIS_HEARINGS_URL"),
    },
    "pinellas": {
        "accela_agency": os.environ.get("ACCELA_PINELLAS_AGENCY", "pinellascountyfl"),
        "arcgis_url": os.environ.get("PINELLAS_ARCGIS_HEARINGS_URL"),
    },
}


def determine_county(agency: str) -> Optional[str]:
    """
    Determine the county from the agency field of an EntitlementRecord.

    Args:
        agency: The agency string from EntitlementRecord (e.g., "Hillsborough County", "Pinellas County")

    Returns:
        "hillsborough", "pinellas", or None if not recognized
    """
    agency_lower = agency.lower() if agency else ""
    if "hillsborough" in agency_lower:
        return "hillsborough"
    if "pinellas" in agency_lower:
        return "pinellas"
    return None


def get_accela_client(county: str):
    """
    Get an AccelaClient for a specific county.

    Args:
        county: "hillsborough" or "pinellas"

    Returns:
        AccelaClient instance, or None if credentials not configured
    """
    from app.services.accela_client import AccelaClient

    agency_id = COUNTY_AGENCIES.get(county, {}).get("accela_agency")
    if not agency_id:
        return None

    client_id = os.environ.get("ACCELA_CLIENT_ID")
    client_secret = os.environ.get("ACCELA_CLIENT_SECRET")

    if not client_id or not client_secret:
        logger.warning("Accela credentials not configured for %s", county)
        return None

    return AccelaClient(agency_id)


def poll_all_entitlements():
    """
    Main polling function — runs on each scheduler tick.

    Loads all EntitlementRecords that have a source_url or are from known counties,
    then queries Accela and ArcGIS for each to detect changes.

    Changes are written to EntitlementRecord and PermitEvent tables.
    Notifications are created for the project PM on any new events.

    This function is designed to be resilient — one bad record should not
    abort the entire cycle. Exceptions are caught and logged per record.
    """
    logger.info("=== Starting entitlement poll cycle ===")

    try:
        records = EntitlementRecord.query.filter(
            db.or_(
                EntitlementRecord.source_url.isnot(None),
                EntitlementRecord.agency.ilike("%hillsborough%"),
                EntitlementRecord.agency.ilike("%pinellas%")
            )
        ).all()
    except Exception as e:
        logger.error("Failed to load EntitlementRecords: %s", e)
        return

    logger.info("Polling %d entitlement records", len(records))

    processed_count = 0
    error_count = 0

    for record in records:
        try:
            process_entitlement_record(record)
            processed_count += 1
        except Exception as e:
            error_count += 1
            logger.error(
                "Error processing entitlement record %s (id=%d): %s",
                record.application_number or record.parcel_number,
                record.id,
                e,
                exc_info=True
            )

    logger.info(
        "=== Poll cycle complete: processed=%d, errors=%d ===",
        processed_count, error_count
    )


def process_entitlement_record(record: EntitlementRecord):
    """
    Process a single EntitlementRecord — query external sources, detect changes.

    Args:
        record: The EntitlementRecord to process
    """
    county = determine_county(record.agency)
    if not county:
        logger.debug("Skipping record %d — county not recognized: %s", record.id, record.agency)
        return

    county_config = COUNTY_AGENCIES.get(county, {})
    changes_made = False

    new_events: List[PermitEvent] = []

    accela_client = get_accela_client(county)

    if accela_client:
        accela_changes, accela_events = process_accela(record, accela_client)
        if accela_changes:
            changes_made = True
        new_events.extend(accela_events)

    arcgis_url = county_config.get("arcgis_url")
    if arcgis_url:
        arcgis_changes, arcgis_events = process_arcgis(record, arcgis_url)
        if arcgis_changes:
            changes_made = True
        new_events.extend(arcgis_events)

    if new_events:
        for event in new_events:
            db.session.add(event)

        db.session.commit()

        for event in new_events:
            notify_pm_on_event(record, event)


def process_accela(
    record: EntitlementRecord,
    client
) -> tuple[bool, List[PermitEvent]]:
    """
    Query Accela API for workflow/inspection changes on a record.

    Args:
        record: EntitlementRecord to process
        client: AccelaClient instance

    Returns:
        Tuple of (changes_made: bool, events: list[PermitEvent])
    """
    from app.services.accela_client import AccelaClient

    events: List[PermitEvent] = []
    changes_made = False

    search_results = client.search_records(parcel_number=record.parcel_number)

    matching_record = None
    for result in search_results:
        rec_parcel = result.get("parcel_number") or result.get("parcels", [{}])[0].get("parcelNumber", "")
        if rec_parcel == record.parcel_number:
            matching_record = result
            break

    if not matching_record:
        return False, []

    record_id = matching_record.get("id") or matching_record.get("recordId")
    if not record_id:
        return False, []

    workflow = client.get_workflow(record_id)
    if workflow:
        tasks = workflow.get("tasks", []) or workflow.get("workflowTasks", [])
        if tasks:
            current_task = tasks[0] if tasks else {}
            current_status = current_task.get("name") or current_task.get("status")

            if current_status and current_status.lower() != record.status.lower():
                event = PermitEvent(
                    entitlement_record_id=record.id,
                    event_type="status_change",
                    previous_value=record.status,
                    new_value=current_status,
                    detected_at=datetime.utcnow(),
                    source="scraper"
                )
                events.append(event)

                record.status = current_status
                changes_made = True

                logger.info(
                    "Status change for record %d: %s -> %s",
                    record.id, record.status, current_status
                )

    existing_inspection_ids = {
        (e.event_type, e.new_value, e.detected_at.isoformat() if e.detected_at else None)
        for e in PermitEvent.query.filter_by(entitlement_record_id=record.id, source="scraper").all()
        if e.event_type == "inspection"
    }

    inspections = client.get_inspections(record_id)
    for insp in inspections:
        insp_id = insp.get("id") or insp.get("inspectionId")
        insp_type = insp.get("type") or insp.get("inspectionType", "Unknown")
        insp_date = insp.get("date") or insp.get("inspectionDate")
        insp_result = insp.get("result") or insp.get("inspectionResult", "")

        insp_key = (f"inspection_{insp_type}", insp_result, insp_date)
        if insp_key not in existing_inspection_ids and insp_result:
            event = PermitEvent(
                entitlement_record_id=record.id,
                event_type="inspection",
                previous_value=None,
                new_value=f"{insp_type}: {insp_result}",
                detected_at=datetime.fromisoformat(insp_date) if insp_date and "T" in str(insp_date) else datetime.utcnow(),
                source="scraper"
            )
            events.append(event)
            existing_inspection_ids.add(insp_key)
            changes_made = True

    return changes_made, events


def process_arcgis(
    record: EntitlementRecord,
    arcgis_url: str
) -> tuple[bool, List[PermitEvent]]:
    """
    Query ArcGIS hearings layer for hearing schedule updates.

    Args:
        record: EntitlementRecord to process
        arcgis_url: ArcGIS FeatureServer URL for hearings layer

    Returns:
        Tuple of (changes_made: bool, events: list[PermitEvent])
    """
    from app.services.arcgis_client import query_hearings

    events: List[PermitEvent] = []
    changes_made = False

    if not arcgis_url:
        return False, []

    features = query_hearings(arcgis_url, record.parcel_number)
    if not features:
        return False, []

    for feature in features:
        attributes = feature.get("attributes", {})

        hearing_date_str = (
            attributes.get("HEARING_DATE") or
            attributes.get("HearingDate") or
            attributes.get("SCHEDULED_DATE")
        )

        if not hearing_date_str:
            continue

        try:
            if isinstance(hearing_date_str, (int, float)):
                from datetime import datetime
                hearing_date = datetime.fromtimestamp(hearing_date_str / 1000).date()
            else:
                hearing_date = datetime.fromisoformat(str(hearing_date_str).replace("Z", "")).date()
        except Exception:
            logger.warning("Failed to parse hearing date for record %d: %s", record.id, hearing_date_str)
            continue

        if record.hearing_date != hearing_date:
            event = PermitEvent(
                entitlement_record_id=record.id,
                event_type="hearing_scheduled",
                previous_value=str(record.hearing_date) if record.hearing_date else None,
                new_value=str(hearing_date),
                detected_at=datetime.utcnow(),
                source="scraper"
            )
            events.append(event)

            record.hearing_date = hearing_date
            changes_made = True

            logger.info(
                "Hearing date update for record %d: %s -> %s",
                record.id, record.hearing_date, hearing_date
            )

    return changes_made, events


def notify_pm_on_event(record: EntitlementRecord, event: PermitEvent):
    """
    Send a notification to the Project Manager when an entitlement event occurs.

    Args:
        record: The EntitlementRecord that had an event
        event: The PermitEvent that was created
    """
    if not record.project_id:
        return

    project = Project.query.get(record.project_id)
    if not project or not project.pm_assigned:
        return

    from app.models import User
    pm_user = User.query.filter_by(full_name=project.pm_assigned).first()

    if not pm_user:
        logger.debug(
            "PM not found for project %d (pm_assigned=%s)",
            project.id, project.pm_assigned
        )
        return

    try:
        create_notification(
            user_id=pm_user.id,
            notification_type="entitlement_update",
            title=f"{record.agency} — {event.event_type} on parcel {record.parcel_number}",
            body=f"Event: {event.event_type} | Previous: {event.previous_value or 'N/A'} | New: {event.new_value or 'N/A'}",
            related_entity_type="entitlement_record",
            related_entity_id=record.id
        )
        logger.info(
            "Notification sent to PM %s for record %d event",
            pm_user.username, record.id
        )
    except Exception as e:
        logger.error(
            "Failed to send notification for record %d: %s",
            record.id, e
        )


def get_poller_status() -> Dict[str, Any]:
    """
    Get the current status of the entitlement poller.

    Returns:
        Dict with poller state information
    """
    from app.services.entitlement_poller import poll_all_entitlements
    return {
        "poll_function": "poll_all_entitlements",
        "env_vars_needed": [
            "POLLER_INTERVAL_MINUTES",
            "ACCELA_CLIENT_ID",
            "ACCELA_CLIENT_SECRET",
            "ACCELA_HILLSBOROUGH_AGENCY",
            "ACCELA_PINELLAS_AGENCY",
            "HILLSBOROUGH_ARCGIS_HEARINGS_URL",
            "PINELLAS_ARCGIS_HEARINGS_URL",
        ]
    }