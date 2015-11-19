import sys

from oslo_config import cfg
from oslo_log import log as logging
#import oslo_messaging
from six import moves

from neutron.common import utils
from neutron.common import config as common_config
from neutron.i18n import _LE, _LI, _LW
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.agent.linux import ip_lib
from neutron.agent.common import config as agent_conf
from neutron.common import constants as q_const

LOG = logging.getLogger(__name__)
cfg.CONF.import_group('AGENT', 'vmware_conf')

def create_agent_config_map(config):
    """Create a map of agent config parameters.

    :param config: an instance of cfg.CONF
    :returns: a map of agent configuration parameters
    """
    try:
        bridge_mappings = utils.parse_mappings(config.ML2_VMWARE.network_maps)
    except ValueError as e:
        raise ValueError(_("Parsing network_maps failed: %s.") % e)

    kwargs = dict(
        vsphere_hostname=config.ML2_VMWARE.vsphere_hostname,
        vsphere_login=config.ML2_VMWARE.vsphere_login,
        vsphere_password=config.ML2_VMWARE.vsphere_password,
        bridge_mappings=bridge_mappings,
        polling_interval=config.AGENT.polling_interval,
        minimize_polling=config.AGENT.minimize_polling,
        veth_mtu=config.AGENT.veth_mtu,
        quitting_rpc_timeout=config.AGENT.quitting_rpc_timeout,
    )
    return kwargs

class SimpleAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

#    target = oslo_messaging.Target(version='1.2')

    def __init__(self, vsphere_hostname, vsphere_login, vsphere_password,
                 bridge_mappings, polling_interval,
                 veth_mtu=None,
                 minimize_polling=False,
                 quitting_rpc_timeout=None):
        super(SimpleAgent, self).__init__()
        self.veth_mtu = veth_mtu
        self.available_local_vlans = set(moves.xrange(q_const.MIN_VLAN_TAG,
                                                      q_const.MAX_VLAN_TAG))
        # TODO(ethuleau): Change ARP responder so it's not dependent on the
        #                 ML2 l2 population mechanism driver.
        self.agent_state = {
            'binary': 'neutron-dvs-agent',
            'host': cfg.CONF.host,
            'topic': q_const.L2_AGENT_TOPIC,
            'configurations': {'bridge_mappings': bridge_mappings,
                               'vsphere_hostname': vsphere_hostname,
                               'log_agent_heartbeats':
                               cfg.CONF.AGENT.log_agent_heartbeats},
            'agent_type': 'DVS agent',
            'start_flag': True}
        print self.agent_state

        # Security group agent support
        self.sg_agent = sg_rpc.SecurityGroupAgentRpc(self.context,
                self.sg_plugin_rpc, self.local_vlan_map,
                defer_refresh_firewall=True)

def main():

    cfg.CONF.register_opts(ip_lib.OPTS)
    agent_conf.register_root_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    utils.log_opt_values(LOG)

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.error(_LE('%s Agent terminated!'), e)
        sys.exit(1)

    try:
        agent = SimpleAgent(**agent_config)
    except RuntimeError as e:
        LOG.error(_LE("%s Agent terminated!"), e)
        sys.exit(1)
    print 'Ok'
    '''signal.signal(signal.SIGTERM, agent._handle_sigterm)

    # Start everything.
    LOG.info(_LI("Agent initialized successfully, now running... "))
    agent.daemon_loop()'''
