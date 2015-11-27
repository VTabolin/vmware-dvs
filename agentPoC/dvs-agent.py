import sys
import signal
import time

from oslo_config import cfg
from oslo_log import log as logging
#import oslo_messaging
#from six import moves

from neutron.common import utils
from neutron.common import config as common_config
from neutron.i18n import _LE, _LI, _LW
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.agent.linux import ip_lib
#from neutron.agent.common import config as agent_conf
from neutron.common import constants as q_const
from neutron.common import topics
from neutron.agent import rpc as agent_rpc
from neutron.agent.common import polling
#from neutron.openstack.common import loopingcall
from oslo_service import loopingcall
from neutron import context

LOG = logging.getLogger(__name__)
cfg.CONF.import_group('AGENT', 'neutron.cmd.eventlet.plugins.vmware_conf')

class DVSPluginApi(agent_rpc.PluginApi):
    pass

class DVSAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

#    target = oslo_messaging.Target(version='1.2')

    def __init__(self, vsphere_hostname, vsphere_login, vsphere_password,
                 bridge_mappings, polling_interval,
                 veth_mtu=None,
                 minimize_polling=False,
                 quitting_rpc_timeout=None):
        super(DVSAgent, self).__init__()
        self.veth_mtu = veth_mtu
        #self.available_local_vlans = set(moves.xrange(q_const.MIN_VLAN_TAG,
        #                                              q_const.MAX_VLAN_TAG))
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

        self.setup_rpc()
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

        self.polling_interval = polling_interval
        self.minimize_polling = minimize_polling
        # Security group agent support
        self.sg_agent = sg_rpc.SecurityGroupAgentRpc(self.context,
                self.sg_plugin_rpc, defer_refresh_firewall=True)
        print "SG_agent enabled"
        self.run_daemon_loop = True
        self.iter_num = 0
        self.fullsync = True
        # The initialization is complete; we can start receiving messages
        self.connection.consume_in_threads()

        self.quitting_rpc_timeout = quitting_rpc_timeout

    def _report_state(self):
        # How many devices are likely used by a VM
        #self.agent_state.get('configurations')['devices'] = (
        #    self.int_br_device_count)

        try:
            agent_status = self.state_rpc.report_state(self.context,
                                                       self.agent_state,
                                                       True)
            if agent_status == q_const.AGENT_REVIVED:
                LOG.info(_LI('Agent has just revived. Do a full sync.'))
                self.fullsync = True
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def setup_rpc(self):
        self.agent_id = 'dvs-agent-%s' % cfg.CONF.host
        self.topic = topics.AGENT
        self.plugin_rpc = DVSPluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)

        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.endpoints = [self]
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.PORT, topics.DELETE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers,
                                                     start_listening=False)

    def _handle_sigterm(self, signum, frame):
        LOG.debug("Agent caught SIGTERM, quitting daemon loop.")
        self.run_daemon_loop = False

    def daemon_loop(self):
        with polling.get_polling_manager(
            self.minimize_polling) as pm:
            print self.minimize_polling
            self.rpc_loop(polling_manager=pm)

    def rpc_loop(self, polling_manager=None):
        if not polling_manager:
            polling_manager = polling.get_polling_manager(
                minimize_polling=False)
        while self.run_daemon_loop:
            start = time.time()
            if self.fullsync:
                LOG.info(_LI("Agent out of sync with plugin!"))
                self.fullsync = False
                polling_manager.force_polling()
            if self._agent_has_updates(polling_manager):
                print "has updates"
                LOG.debug("Agent rpc_loop - update")
            self.loop_count_and_wait(start)


    def _agent_has_updates(self, polling_manager):
        print self.sg_agent.firewall_refresh_needed()
        return (self.sg_agent.firewall_refresh_needed())                

    def loop_count_and_wait(self, start_time):
        # sleep till end of polling interval
        elapsed = time.time() - start_time
        LOG.debug("Agent rpc_loop - iteration:%(iter_num)d "
                  "completed. Elapsed:%(elapsed).3f",
                  {'iter_num': self.iter_num,
                   'elapsed': elapsed})
        if elapsed < self.polling_interval:
            time.sleep(self.polling_interval - elapsed)
        else:
            LOG.debug("Loop iteration exceeded interval "
                      "(%(polling_interval)s vs. %(elapsed)s)!",
                      {'polling_interval': self.polling_interval,
                       'elapsed': elapsed})
        self.iter_num = self.iter_num + 1

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


def main():

    cfg.CONF.register_opts(ip_lib.OPTS)
    #agent_conf.register_root_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    utils.log_opt_values(LOG)

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.error(_LE('%s Agent terminated!'), e)
        sys.exit(1)

    try:
        agent = DVSAgent(**agent_config)
    except RuntimeError as e:
        LOG.error(_LE("%s Agent terminated!"), e)
        sys.exit(1)
    print 'Ok'
    signal.signal(signal.SIGTERM, agent._handle_sigterm)

    # Start everything.
    LOG.info(_LI("Agent initialized successfully, now running... "))
    agent.daemon_loop()

if __name__ == "__main__":
    main()
