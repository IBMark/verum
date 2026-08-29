"""Event publishing - swallowed errors next to handlers that keep evidence."""

import logging

logger = logging.getLogger(__name__)


def publish_best_effort(broker, event):
    try:
        broker.publish(event)
    except Exception:
        pass


def cleanup(path):
    try:
        path.unlink()
    except:
        pass


def publish_logged(broker, event):
    try:
        broker.publish(event)
    except ConnectionError:
        logger.warning("event dropped: broker unreachable")


def publish_reraised(broker, event):
    try:
        broker.publish(event)
    except Exception:
        logger.exception("publish failed")
        raise


def skip_missing(path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass
