# Copyright 2023-2024 DreamWorks Animation LLC
# SPDX-License-Identifier: Apache-2.0

import requests
import socket
import logging

from utils import short_id
import allocate

logger = logging.getLogger("node")

# Represents a Node service running on some machine

class Node(object):

    def __init__(self,coord,node_data):
        self.coord = coord
        self.node_data = node_data
        cores = node_data['resources']['cores']
        memory = node_data['resources']['memoryMB']
        self.resources = allocate.NodeResources(cores,memory)
        self.is_test_node = False


    testNodeCount = 0
    @staticmethod
    def make_test_node(coord,cores,memory):
        Node.testNodeCount += 1
        test_data = { 'id': "test_{}".format(Node.testNodeCount),
                      'hostname': "testnode",
                      'http_port': 0,
                      'port': 0,
                      'resources': { 'cores': cores,
                                     'memory': memory}}
        node = Node(coord,test_data)
        node.is_test_node = True
        return node

    @property
    def id(self):
        return self.node_data['id']

    @property
    def hostname(self):
        return self.node_data['hostname']

    @property
    def host_ip(self):
        return self.node_data['ipAddress']

    @property
    def http_port(self):
        return self.node_data['httpPort']

    @property
    def port(self):
        return self.node_data["port"]

    def __str__(self):
        return "Node {} on {} (ip {})".format(self.id,self.hostname,self.host_ip)

    # make config for main section
    # add 'computations' and 'sessionId' to 'config'
    def make_config(self):
        return { 'tcp':self.port,
                 'port':self.http_port,
                 'ip':socket.gethostbyname(self.hostname),
                 'nodeId':self.id,
                 'config': { 'computations': {}}
                 }

    # make config for routing section
    # add 'entry: true/false' 
    def make_routing_config(self):
        return { 'tcp':self.port,
                 'port':self.http_port,
                 'ip': self.host_ip,
                 'host':self.hostname
                 }

    # sends a POST /sessions request to the node
    def launch(self,sess_id,data):
        if not self.is_test_node:
            url = "http://{}:{}/sessions".format(self.hostname,self.http_port)
            r = requests.post(url,json=data)
            r.raise_for_status()
        logger.info("Launching session {} on node {}".format(short_id(sess_id),short_id(self.id)))

    def update(self,sess_id,data):
        if not self.is_test_node:
            url = "http://{}:{}/sessions/{}/status".format(self.hostname,self.http_port,sess_id)
            r = requests.put(url,json=data)
            r.raise_for_status()
        status = data.get("status", "unknown")
        logger.info("Updating session {} on node {} : status {}".format(short_id(sess_id),short_id(self.id),status))
        
    def delete_session(self,sess_id,reason):
        if not self.is_test_node:
            url = "http://{}:{}/sessions/{}".format(self.hostname,self.http_port,sess_id)
            r = requests.delete(url,headers={"X-Session-Delete-Reason":reason})
            #r.raise_for_status()
        logger.info("Deleting session {} on node {} reason: {}".format(short_id(sess_id),short_id(self.id),reason))
        
    def shutdown(self,reason):
        if not self.is_test_node:
            url = "http://{}:{}/status".format(self.hostname,self.http_port)
            body = {'status':'shutdown',
                    'shutdownByApp':'coordinator',
                    'shutdownByUser':'NA',
                    'shutdownReason':reason}
            r = requests.put(url,json=body)
            #r.raise_for_status()
        logger.info("Shutting down node {} reason: {}".format(short_id(self.id),reason))
    

