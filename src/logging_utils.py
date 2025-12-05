"""Global structured logger for the auto_ops_agent."""
import logging

logger = logging.getLogger("auto_ops_agent")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('{"time":"%(asctime)s","level":"%(levelname)s","message":"%(message)s","extra":%(extra)s}')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
