# Copyright 2023-2024 DreamWorks Animation LLC
# SPDX-License-Identifier: Apache-2.0

# An implementation of the Coordinator REST interface
#
# The coordinator logic in implemented in class Coord (coord.py),
# this class translates HTTP requests to methods in that class.
# Note that "host" in the API means the same thing as "computation"
# 

from tornado.ioloop import IOLoop, PeriodicCallback
import tornado.web

import json
import logging

from coord import Coord
from utils import short_id

logger = logging.getLogger("coord_service")

class CoordService(tornado.web.Application):

     def __init__(self, port):
        
        self.port = port
        self.coord = Coord()

        handlers = [
            # GET /status : return coordinator status
            (r"/status",StatusHandler,dict(coord=self.coord)),
            # POST /nodes : register a new node
            (r"/coordinator/1/nodes",NodesHandler,dict(coord=self.coord)),
            # DELETE /nodes/<id> : unregister a node
            (r"/coordinator/1/nodes/([a-fA-F\-0-9]+)",NodesHandler,dict(coord=self.coord)),
            # POST /sessions : create a new session
            (r"/coordinator/1/sessions",SessionsHandler,dict(coord=self.coord)),
            # DELETE /sessions/<id> : terminate a session
            (r"/coordinator/1/sessions/([a-fA-F\-0-9]+)",SessionsHandler,dict(coord=self.coord)),
            # PUT /sessions/<sess_id>/hosts/<host_id> : notification that a host(computation) is ready
            # PUT /sessions/<sess_id>/computations/<host_id> : same (newer syntax)
            # DELETE /sessions/<sess_id>/hosts/<host_id> : notification that a host(computation) exited
            # DELETE /sessions/<sess_id>/hosts/<host_id> : same (newer syntax)
            (r"/coordinator/1/sessions/([a-fA-F\-0-9]+)/hosts/([a-fA-F\-0-9]+)",HostsHandler,dict(coord=self.coord)),
            (r"/coordinator/1/sessions/([a-fA-F\-0-9]+)/computations/([a-fA-F\-0-9]+)",HostsHandler,dict(coord=self.coord)),
            # POST /sessions/<id>/event : record session event
            (r"/coordinator/1/sessions/([a-fA-F\-0-9]+)/event",EventHandler,dict(coord=self.coord)),
        ]

        super(CoordService, self).__init__(
              handlers = handlers)

     def run(self):
        self.listen(self.port)
        self.ioLoop = IOLoop.current()
        self.ioLoop.start()

     def stop(self):
          self.ioLoop.stop()

class BaseHandler(tornado.web.RequestHandler):

    def initialize(self,coord):
         self.coord = coord


class StatusHandler(BaseHandler):

    def get(self):
        """ Respond with coordinator status"""
        response = self.coord.status()
        self.write(response)

        
class NodesHandler(BaseHandler):

    def post(self):
        """ Register a new node with coordinator"""
        req = self.request.body
        # we get a trailing null for some reason
        req = req.rstrip('\x00')
        req = json.loads(req)
        self.coord.register_node_request(req)
        self.set_status(201) # CREATED

    def delete(self,node_id):
        """ Unregister a node with coordinator"""
        self.coord.unregister_node_request(node_id)
        self.set_status(204) # NO CONTENT
              
class SessionsHandler(BaseHandler):

    def delete(self,sess_id):
        """Terminate a session"""
        reason = "Unknown"
        if 'X-Session-Delete-Reason' in self.request.headers:
            reason = self.request.headers['X-Session-Delete-Reason']
        self.coord.terminate_session_request(sess_id,reason)
        self.set_status(204) # NO CONTENT

    def post(self):
        """Create a session"""
        req = self.request.body
        # we get a trailing null for some reason
        req = req.rstrip('\x00')
        req = json.loads(req)
        resp = self.coord.create_session_request(req)
        if resp:
            self.write(resp)
            # self.set_status(201) : client is broken and doesn't like this...
        else:
            self.set_status(503) # service unavailable
              
class HostsHandler(BaseHandler):

    def put(self,sess_id,host_id):
        # node is notifying us that a host (i.e. computation)
        # is ready
        self.coord.session(sess_id).computation_ready_signal(host_id)

    def delete(self,sess_id,host_id):
        # node is notifying us that a host (i.e. computation)
        # exited
        if self.coord.session_exists(sess_id):
            reason = "Unknown"
            if 'X-Host-Delete-Reason' in self.request.headers:
                reason = self.request.headers['X-Host-Delete-Reason']
            self.coord.session(sess_id).computation_exit_signal(host_id,reason)
        else:
            # we can get computation exit notifications after the session deleted has been requested.
            # this is deliberate, to allow coord to track session shutdown but in this
            # implementation we don't care...
            logger.info("Delete request for computation in deleted session {}".format(short_id(sess_id)))

class EventHandler(BaseHandler):
    def post(self,sess_id):
        """Record a session event (used for logging)"""
        req = self.request.body
        # we get a trailing null for some reason
        req = req.rstrip('\x00')
        req = json.loads(req)
        if self.coord.session_exists(sess_id):
            self.coord.session(sess_id).event_request(req)
        else:
            # we can get event notifications after the session delete has been requested.
            # this is deliberate, to allow coord to track session shutdown but in this
            # implementation we don't care...
            logger.info("Event {} for deleted session {}".format(req,short_id(sess_id)))
        self.set_status(201) # created

