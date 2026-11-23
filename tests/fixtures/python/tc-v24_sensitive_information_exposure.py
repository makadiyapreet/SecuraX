import traceback

def handle_request(req):
    try:
        process_db(req)
    except Exception as e:
        return f"Database error details: {traceback.format_exc()}"
