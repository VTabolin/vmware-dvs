# Copyright 2010-2011 OpenStack Foundation
# Copyright 2012-2013 IBM Corp.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from novaclient import client as nova_client

from mech_vmware_dvs import exceptions


NOVA_API_VERSION = '2'


def get_hypervisors_by_host(cfg, host):
    client = _make_nova_client(cfg)

    for hypervisor in client.hypervisors.list():
        if hypervisor.service['host'] != host:
            continue
        break
    else:
        raise exceptions.HypervisorNotFound

    return hypervisor


def _make_nova_client(cfg):
    bypass_url = None
    if cfg.nova_admin_tenant_id:
        bypass_url = '%s/%s' % (cfg.nova_url,
                                cfg.nova_admin_tenant_id)

    novaclient_cls = nova_client.get_client_class(NOVA_API_VERSION)

    return novaclient_cls(
        username=cfg.nova_admin_username,
        api_key=cfg.nova_admin_password,
        tenant_id=cfg.nova_admin_tenant_id,
        auth_url=cfg.nova_admin_auth_url,
        cacert=cfg.nova_ca_certificates_file,
        insecure=cfg.nova_api_insecure,
        bypass_url=bypass_url,
        region_name=cfg.nova_region_name)
