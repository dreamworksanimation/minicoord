# Copyright 2023-2024 DreamWorks Animation LLC
# SPDX-License-Identifier: Apache-2.0

import threading
import atexit
import logging

logger = logging.getLogger("run")

from coord_service import CoordService

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('tornado').setLevel(logging.WARNING)

PORT = 8888
logger.info("Starting coordinator service on port {}".format(PORT))
service = CoordService(PORT)
co = service.coord

t = threading.Thread(target=service.run)
t.daemon = True
t.start()

def shutdown():
    logger.info("Shutting down coordinator service")
    co.shutdown_all()

atexit.register(shutdown)
