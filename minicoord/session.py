# Copyright 2023-2024 DreamWorks Animation LLC
# SPDX-License-Identifier: Apache-2.0

import uuid
import logging
import copy

logger = logging.getLogger("session")

from utils import short_id
import allocate

class Computation(object):
    """ Represents a single computation in a session. Computations are listed in the
        session definition, but may appear inside arrays"""

    def __init__(self,session,basename,config,array_index=None):
        self.session = session
        self.basename = basename
        self.array_index = array_index
        if array_index is None:
            self.name = basename
        else:
            self.name = "{}_i{}".format(basename,array_index)
        self.config = config
        self.id = str(uuid.uuid4())
        self.node_id = None
        self.is_client = (basename == '(client)')
        if not self.is_client:
            resource_req = config.get('requirements',{}).get('resources')
            if resource_req is None:
                memory = None
                cores = 1
            else:
                memory = resource_req.get('memoryMB')
                if 'cores' in resource_req:
                    cores = resource_req['cores']
                else:
                    cores = (resource_req.get('minCores',1),
                            resource_req.get('maxCores','*'))
            self.required_resources = allocate.RequiredResources(cores,memory)
            self.hostname_pin = config.get('requirements',{}).get('hostname_pin')
        self.assigned_resources = None
        self.exit_kills_session = False

    def is_allocated(self):
        return self.node_id is not None

    def evaluate_variables(self):
        """ substitute actual values for the variables $arrayIndex and $arrayNumber that
            can appear in definitions"""
        newconfig = self.config.copy()
        for (k,v) in self.config.iteritems():
            if not isinstance(v,basestring):
                continue
            if v == "$arrayIndex":
                newconfig[k] = self.array_index
            elif v == "$arrayNumber":
                newconfig[k] = self.session.array_len(self.basename)
            elif v.startswith("$arrayNumber."):
                arrayName = v[len("$arrayNumber."):]
                newconfig[k] = self.session.array_len(arrayName)
        self.config = newconfig
        
    def __str__(self):
        return "Computation {} id {} on {}".format(self.name,self.id,self.node_id)

    # make config for routing section
    def make_routing_config(self):
        return { 'compId':self.id,
                 'hostId':self.id,
                 'nodeId':self.node_id }

def normalize_message_list(messages):
    # translate shortened (lazy...) forms of message lists to an actual list
    # return a list unchanged, unless it is ['*'] => []
    # oddly, 'accept: []' means 'accept everything'
    if isinstance(messages,list):
        if len(messages) == 1 and messages[0] == '*':
            return []
        return messages
    # "*" => []
    elif messages == '*':
        return []
    # "MessageName" => ["MessageName"]
    else:
        return [messages]

def normalize_messages_entry(entry):
    # translate shortened message entries to a normal form
    if isinstance(entry,dict):
        return {k: normalize_message_list(v) for (k,v) in entry.items()}
    return {'accept':normalize_message_list(entry)}

class Session(object):

    def __init__(self,coord):
        self.coord = coord
        self.id = str(uuid.uuid4())
        self.computations = {}
        self.contexts = {}
        self.comps_by_id = {}
        self.arrays = {}
        self.message_filter = {}
        self.is_released = False
        self.entry_id = None
        self.ready_count = 0
        
    def __str__(self):
        return "Session {} ({} computations)".format(self.id,len(self.computations))

    def computation(self,comp_id):
        return self.comps_by_id[comp_id]

    def array_len(self,basename):
        return len(self.arrays[basename])
    
    def set_definition(self,definition):

        logger.info("Starting session {}".format(short_id(self.id)))

        self.computations = {}
        for (name,config) in definition['computations'].iteritems():
            if 'arrayExpand' in config:
                self.add_array(name,config,config['arrayExpand'])
            else:
                self.add_computation(name,config)

        self.contexts = definition.get('contexts',{})

        # evaluate array variables and build 'reversed' source,target 
        # message filter using the target,source data in the comp configs
        self.message_filter = {}
        for c in self.computations.values():
            c.evaluate_variables()
            target = c.name
            if 'messages' in c.config:
                for (source,names) in c.config['messages'].iteritems():
                    names = normalize_messages_entry(names)
                    if source in self.arrays:
                        for s in self.arrays[source]:
                            entry = self.message_filter.setdefault(s,{})
                            entry[target] = names
                    else:
                        entry = self.message_filter.setdefault(source,{})
                        entry[target] = names

    def add_array(self,basename,config,count):
        names = []
        for i in range(count):
            c = self.add_computation(basename,config,i)
            names.append(c.name)
        self.arrays[basename] = names
        
    def add_computation(self,basename,config,array_index=None):
        c = Computation(self,basename,config,array_index)
        self.computations[c.name] = c
        self.comps_by_id[c.id] = c
        return c

    def allocate(self):
        return allocate.allocate_session(self)

    def release(self,reason):
        allocate.release_session(self,reason)
        self.is_released = True

    def get_nodes(self):
        nodes = set()
        for c in self.computations.values():
            if c.node_id:
                nodes.add(self.coord.node(c.node_id))
        return nodes
        
    def launch(self):
        (ncs,r) = self.generate_node_configs()
        for (nid,nc) in ncs.iteritems():
            nd = { nid: nc,
                   "routing": r }
            node = self.coord.node(nid)
            node.launch(self.id,nd)
        self.readyCount = 0

        entry_node = self.coord.node(self.entry_id)
        return {'sessionId':self.id,
                'hostname': entry_node.hostname,
                'ip': entry_node.host_ip,
                'port': entry_node.port}

    def go(self):
        # all computations are ready : start the session
        # send final topology to all nodes
        (ncs,r) = self.generate_node_configs()
        for (nid,nc) in ncs.iteritems():
            nd = { "status":"run",
                   "routing": r }
            node = self.coord.node(nid)
            node.update(self.id,nd)
        # send "engineReady" to entry node
        entry_node = self.coord.node(self.entry_id)
        nd = { "status":"engineReady"}
        entry_node.update(self.id,nd)
            

    def generate_node_configs(self):
        node_configs = {}
        nodes = {}
        comps = {}
        self.entry_id = None
        for c in self.computations.values():
            if c.is_client:
                continue
            if c.id == None or c.node_id == None:
                logger.warning("Computation {} has no assignment, omitting".format(c.name))
                continue
            comps[c.name] = c.make_routing_config()
            if c.node_id in node_configs:
                node_config = node_configs[c.node_id]
            else:
                node = self.coord.node(c.node_id)
                node_config = node.make_config()
                node_config['config']['sessionId'] = self.id
                node_config['config']['contexts'] = self.contexts
                node_configs[c.node_id] = node_config
                nodes[node.id] = node.make_routing_config()

            assigned_config = copy.deepcopy(c.config)
            assigned_config.setdefault('requirements',{}).setdefault('resources',{})['cores'] = c.assigned_resources.cores
            assigned_config['requirements']['resources']['memoryMB'] = c.assigned_resources.memory
            node_config['config']['computations'][c.name] = assigned_config
            entry = c.config.get('entry')
            if entry == True or entry == "yes" or self.entry_id is None:
                self.entry_id = c.node_id
           
                
        nodes[self.entry_id]['entry'] = True
        routing = { 'messageFilter': self.message_filter,
                    self.id: {
                        "nodes": nodes,
                        "computations": comps,
                        "engine":"empty",
                        "clientData": {
                            "session":"empty",
                            "clientInfo":{
                                "nodeName":None,
                                "osVersion":None,
                                "platformModel":None,
                                "platformName":None,
                                "osName":None
                                }
                            }
                        }
                    }
        return (node_configs,routing)
   
    def shutdown(self,reason):
        logger.info("Shutting down session {} reason: {}".format(short_id(self.id),reason))
        self.release(reason)

    def event_request(self,event):
        """ We are being informed of an event : not used by this implementation"""
        logger.info("Session {} event received: {}".format(short_id(self.id),event))
        
    def terminate_request(self,reason):
        """ Handle a request to terminate this session"""
        logger.info("Terminating session {} reason {}".format(short_id(self.id),reason))
        self.release(reason)

    def computation_ready_signal(self,comp_id):
        """notification from node that a computation is ready"""
        c = self.comps_by_id[comp_id]
        logger.info("Computation {} id {} is ready".format(c.name, short_id(c.id)))
        self.ready_count += 1
        # if all computations are ready, start the session
        if self.ready_count == len(self.computations)-1: # not (client)
            self.go()

    def computation_exit_signal(self,comp_id,reason):
        """notification from node that a computation exited"""
        c = self.comps_by_id[comp_id]
        logger.info("Computation {} id {} exited reason : {}".format(c.name, short_id(c.id), reason))
        if c.exit_kills_session:
            logger.info("Killing session in response")
            self.delete(reason)
        else:
            logger.info("Continuing")

