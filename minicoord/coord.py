# Copyright 2023-2024 DreamWorks Animation LLC
# SPDX-License-Identifier: Apache-2.0

# This class contains the main Coordinator logic. It manages a list of Nodes and a list of Sessions
# Each of these has its own unique UUID, but for convenience can also be accessed by index.
#
# - Nodes are added to the list when a Node service starts up on some machine and contacts the REST
# API to register itself. On shutdown, the Node service will call back to deregister.
#
# - Sessions are created when a client requests that a new Session be started.

import logging

from utils import short_id
from session import Session
from node import Node

logger = logging.getLogger("coord")

class Coord(object):

    def __init__(self):
        self.sessions = {}
        self.nodes = {}
                        
    def status(self):
        """Return status of coordinator as a dict"""
        return { 'sessions': len(self.sessions),
                 'nodes': len(self.nodes) }

    def shutdown_all(self):
        """shutdown everything prior to exit"""
        logger.info("Shutting down")
        for s in self.sessions.values():
            if s and not s.is_released:
                s.shutdown("Coordinator shutdown")
        self.sessions.clear()
        for n in self.nodes.values():
            if n: n.shutdown("Coordinator shutdown")
        self.nodes.clear()
    
    # sessions

    def session(self,sessionid):
        return self.sessions[sessionid]

    def session_exists(self,sessionid):
        return sessionid in self.sessions
        
    def create_session_request(self,session_data):
        """ handle a request to create a new session"""
        session = Session(self)
        self.sessions[session.id] = session
        session.set_definition(session_data['sessionDef'])
        if session.allocate():
            return session.launch()
        return None

    def terminate_session_request(self,sess_id,reason):
        """ called when a request is made to terminate a session"""
        session = self.sessions[sess_id]
        session.terminate_request(reason)
        del self.sessions[sess_id]

    # nodes

    def node(self,node_id):
        return self.nodes[node_id]
    
    def add_test_node(self,cores,memory):
        node = Node.make_test_node(self,cores,memory)
        self.nodes[node.id] = node
        logger.info("Added test node {} with {} cores, {} Mb memory".format(short_id(node.id),node.hostname))

    def register_node_request(self,node_data):
        """ called when a new Node registers via the REST API"""
        node = Node(self,node_data)
        self.nodes[node.id] = node
        logger.info("Registered new node {} on {} : {} cores".format(short_id(node.id),node.hostname,node.resources.total.cores))

    def unregister_node_request(self,node_id):
        """ called when a node unregisters via the REST API"""
        node = self.nodes[node_id]
        logger.info("Unregistering node {}".format(short_id(node.id)))
        del self.nodes[node_id]

    # tools

    def list(self):
        print("\nNodes({}):".format(len(self.nodes)))
        for n in self.nodes.values():
            print(str(n))
        print("\nSessions({}):".format(len(self.sessions)))
        for s in self.sessions.values():
            print(str(s))
        print("")




