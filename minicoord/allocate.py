# Copyright 2023-2024 DreamWorks Animation LLC
# SPDX-License-Identifier: Apache-2.0

import copy
import logging

from utils import short_id

DEFAULT_COMPUTATION_MEMORY = 16384

logger = logging.getLogger("allocate")

class Resources(object):
    def __init__(self,cores=0,memory=0):
        self.cores = cores
        self.memory = memory

class NodeResources(object):
    """Total and free resources on a node"""

    def __init__(self,cores,memory):
        self.total = Resources(cores,memory)
        self.free = Resources(cores,memory)
        self.per_session = {}

    def satisfies(self,comp_resources):
        if comp_resources.minCores() > self.free.cores:
            return False
        return comp_resources.memory <= self.free.memory

    def assign(self,comp):
        cores = comp.required_resources.maxCores(self.free.cores)
        self.free.cores -= cores
        self.free.memory -= comp.required_resources.memory
        sess_res = self.per_session.setdefault(comp.session.id,Resources())
        sess_res.cores += cores
        sess_res.memory += comp.required_resources.memory
        return Resources(cores,comp.required_resources.memory)

    def release_session(self,session):
        r = self.per_session.pop(session.id)
        self.free.cores += r.cores
        self.free.memory += r.memory

class RequiredResources(object):
    """Resource requirements of a computation
        cores may be a fixed number or a pair
        (n,m) means between n and m inclusive
        (n,'*') means at least n"""

    def __init__(self,cores,memory):
        self.cores = cores # may be a number or a pair
        self.memory = memory or DEFAULT_COMPUTATION_MEMORY

    def is_variable(self):
        if not isinstance(self.cores,tuple):
            return False
        return self.cores[0] != self.cores[1]

    def minCores(self):
        if not isinstance(self.cores,tuple):
            return self.cores
        return self.cores[0]

    def maxCores(self,max_avail):
        if not isinstance(self.cores,tuple):
            return self.cores
        if self.cores[1] == '*':
            return max_avail
        else:
            return self.cores[1]


class Allocation(object):
    """An in-progress allocations"""

    def __init__(self,session):
        self.nodes = {}  # node_id => NodeResources
        self.hostnames = {} # node_id => hostname
        for node in session.coord.nodes.values():
            self.nodes[node.id] = copy.copy(node.resources)
            self.hostnames[node.id] = node.hostname
        self.comps = {}  # comp_id => (node_id,Resources)

    def apply(self,session):
        for node in session.coord.nodes.values():
            node.resources = self.nodes[node.id]
        for (comp_id,(node_id,resources)) in self.comps.items():
            session.computation(comp_id).node_id = node_id
            session.computation(comp_id).assigned_resources = resources

    def allocate(self,c):
        for (n,r) in self.nodes.items():
            if r.satisfies(c.required_resources):
                if c.hostname_pin and c.hostname_pin != self.hostnames[n]:
                    logger.info("Not allocating node {} to computation {} because of hostname pin ({} != {})".format(short_id(n),c.name,self.hostnames[n],c.hostname_pin))
                    continue
                resources = r.assign(c)
                self.comps[c.id] = (n,resources)
                logger.info("Allocated node {} ({} cores, {} Mb) to computation {} id {}".format(short_id(n),resources.cores, resources.memory, c.name,short_id(c.id)))
                return True
        logger.warning("Failed to allocate a node to computation {} id {}".format(c.name,short_id(c.id)))
        return False


def allocate_session(session):

    alloc = Allocation(session)

    # in the first pass, we allocate computations with
    # a fixed cores requirement
    for c in session.computations.values():
        if c.is_allocated() or c.is_client: continue
        if c.required_resources.is_variable(): continue
        if not alloc.allocate(c):
            return False # allocation failed

    # the second pass allocates computations with
    # variable requirements
    for c in session.computations.values():
        if c.is_allocated() or c.is_client: continue
        if not c.required_resources.is_variable(): continue
        if not alloc.allocate(c):
            return False # allocation failed

    # apply the allocation to the actual nodes and computations
    alloc.apply(session)
    return True

def release_session(session,reason):
    for node in session.get_nodes():
        node.delete_session(session.id,reason)
        node.resources.release_session(session)
