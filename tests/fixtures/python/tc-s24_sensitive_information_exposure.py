import logging

logger = logging.getLogger("api")

def handle_request(req):
    try:
        process_db(req)
        return "Success"
    except Exception as e:
        logger.error("DB error: %s", e)
        return "An internal server error occurred"
