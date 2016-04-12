# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron.agent import firewall
from neutron.i18n import _LW, _LI
from oslo_log import log as logging

from vmware_dvs.common import config
from vmware_dvs.utils import security_group_utils as sg_util
from vmware_dvs.utils import dvs_util

LOG = logging.getLogger(__name__)

CONF = config.CONF


class DVSFirewallDriver(firewall.FirewallDriver):
    """DVS Firewall Driver.
    """
    def __init__(self):
        self.networking_map = dvs_util.create_network_map_from_config(
            CONF.ML2_VMWARE)
        self.dvs_ports = {}
        self._defer_apply = False
        # Map for known ports and dvs it is connected to.
        self.dvs_port_map = {}

    def prepare_port_filter(self, ports):
        self._process_port_filter(ports)

    def apply_port_filter(self, ports):
        self._process_port_filter(ports)

    def update_port_filter(self, ports):
        self._process_port_filter(ports)

    def _process_port_filter(self, ports):
        LOG.info(_LI("Set security group rules for ports %s"),
                 [p['id'] for p in ports])
        for port in ports:
            self.dvs_ports[port['device']] = port
        self._apply_sg_rules_for_port(ports)

    @dvs_util.wrap_retry
    def remove_port_filter(self, ports):
        LOG.info(_LI("Clean up security group rules on deleted ports"))
        for p_id in ports:
            port = self.dvs_ports.get(p_id)
            if port is not None:
                dvs = self._get_dvs_for_port_id(port)
                if dvs:
                    dvs.release_port(port)
                self.dvs_ports.pop(port['device'], None)
                for port_set in self.dvs_port_map.values():
                    port_set.discard(port['id'])

    @property
    def ports(self):
        return self.dvs_ports

    @dvs_util.wrap_retry
    def _apply_sg_rules_for_port(self, ports):
        self._update_dvs_port_map(ports)
        for dvs, port_id_list in self.dvs_port_map.iteritems():
            port_list = [p for p in ports if p['id'] in port_id_list]
            sg_util.update_port_rules(dvs, port_list)

    def update_security_group_rules(self, sg_id, sg_rules):
        pass

    def update_security_group_members(self, sg_id, sg_members):
        pass

    def security_group_updated(self, action_type, sec_group_ids,
                               device_id=None):
        pass

    def _update_dvs_port_map(self, ports):
        known_ports = (set.union(*self.dvs_port_map.values())
                       if self.dvs_port_map.values() else {})
        unknown_ports_network_dvs_map = {}
        for port in ports:
            port_id = port['id']
            if port_id not in known_ports:
                port_network = port['network_id']
                if port_network in unknown_ports_network_dvs_map:
                    dvs = unknown_ports_network_dvs_map[port_network]
                else:
                    dvs = dvs_util.get_dvs_by_network(
                        self.networking_map.values(), port_network)
                    unknown_ports_network_dvs_map[port_network] = dvs
                if dvs:
                    self._get_dvs_and_put_dvs_in_port_map(dvs, port_id)

    def _get_dvs_for_port_id(self, port):
        self._update_dvs_port_map([port])
        for dvs, port_list in self.dvs_port_map.iteritems():
            if port['id'] in port_list:
                return dvs
        LOG.warning(_LW("Cannot find dvs for port %s"), port['id'])

    def _get_dvs_and_put_dvs_in_port_map(self, dvs, port_id):
        # Check if dvs is known, otherwise add it in port_map with
        # corresponding port_id
        if dvs not in self.dvs_port_map:
            self.dvs_port_map[dvs] = set()
        self.dvs_port_map[dvs].add(port_id)
        return dvs

    def filter_defer_apply_on(self):
        pass

    def filter_defer_apply_off(self):
        pass
