"""Compatibility wrapper for the new backend entrypoint."""

from backend.run import app, create_app, initialize_application, logger


if __name__ == "__main__":
    initialize_application(app)
    logger.info("Service started via compatibility wrapper, listening on 0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
