'''

Created on Sep 24, 2012
Dependencies:
    Unix:
        cat
        gzip
    
@author: luis
'''
from optparse import OptionParser
import subprocess
import shlex

class Command:
    def __init__(self, cmd, name, TIMEOUT = 100):
        self.cmd = cmd
        self.name = name
		self.TIMEOUT = TIMEOUT
		self.lastout = ''
	
	def systemCall(self):
		'''
		non-implemented abstract function for subclassing
		'''
		pass
class UnixCommand(Command):
    def __init__(self, cmd, name):
        Command.__init__(cmd, name)

	
	def systemCall(self):
		'''
		Perform an OS CLI call on the Windows commandline and get the full output
		best used for one shot commands that do not involve interactivity.
		returns both the output and the error in a tuple
		This is intentionally a blocking command, it will not return until the command has ended.
		'''
		proccess = subprocess.Popen(shlex.split(cmd))
		process.wait()
		out, err = process.communicate()
		self.lastout = out
		return out, err
class WindowsCommand(Command):
	def __init__(self, cmd, name):
        Command.__init__(cmd, name)

	
	def systemCall(self):
		'''
		Perform an OS CLI call on the Windows commandline and get the full output
		best used for one shot commands that do not involve interactivity
		'''
		#reserving for windows implementation
		pass
class System:
    '''
    Represents the state of the system in which the program is
    being executed. A wrapper for the platform module
    '''


    def __init__(self):
		#Any of these values upon retrieval failure will be NULL
		self.uname = platform.uname()
		self.system = self.uname[0]
		self.nodeinfo = self.uname[1]
		self.release = self.uname[2]
		self.version = self.uname[3]
		self.CPU_architecture = self.uname[4]
		
        #OS environment variables in a dictionary
		self.env = os.environ
	
	def getPath():
		pass
	
	def getDate():
		pass
	
	def getHostname():
		pass
class SysinfoSnapshot:
    def __init__(self):
		self.factory = SysInfoDataFactory()
	
	def runDiscovery(self):
		pass
class SysinfoSnapshotWin:
    def __init__(self):
        SysinfoSnapshot.__init__()

	def runDiscovery(self):
		pass
class SysinfoSnapshotUnix:
    def __init__(self, flavor):
        SysinfoSnapshot.__init__()
		#Flag for specialized Linux commands, None if failed to obtain
        self.flavor = flavor
    
	def runDiscovery(self):
        self.server_commands = [
                           self.callCommand('arp -an').getOutput(),
                           self.callCommand('biosdecode').getOutput(),
                           self.callCommand('blkid -c /dev/nell | sort').getOutput(),
                           self.callCommand('cat /etc/SuSE-release').getOutput(),
                           self.callCommand('cat /etc/redhat-release','chkconfig --list | sort').getOutput(),
                           self.callCommand('date').getOutput(),
                           self.callCommand('df -h').getOutput(),
                           self.callCommand('dmesg').getOutput(),
                           self.callCommand('dmidecode').getOutput(),
                           self.callMethod('eth-tool-all-interfaces').getOutput(),#implemented as method
                           self.callCommand('fdisk -l').getOutput(),
                           self.callCommand('free').getOutput(),
                           self.callCommand('fw-ini-dump').getOutput(),
                           self.callCommand('hostname').getOutput(),
                           
                           self.callCommand('hwinfo --netcard').getOutput(),
                           self.callCommand('ibstat').getOutput(),
                           self.callCommand('ibstatus').getOutput(),
                           self.callCommand('ibv_devinfo').getOutput(),
                           self.callCommand('ibv_devinfo -v').getOutput(),
                           self.callCommand('ifconfig -a').getOutput(),
                           self.callCommand('ip a s').getOutput(),
                           self.callCommand('ip m s').getOutput(),
                           self.callCommand('ip n s').getOutput(),
                           self.callCommand('iptables -t filter -nvL').getOutput(),
                           self.callCommand('iptables -t mangle -nvL').getOutput(),
                           self.callCommand('iptables -t nat -nvL').getOutput(),
                           self.callCommand('iptables-save -t filter').getOutput(),
                           self.callCommand('iptables-save -t mangle').getOutput(),
                           self.callCommand('iptables-save -t nat').getOutput(),
                           self.callCommand('lslk').getOutput(),
                           self.callCommand('lsmod').getOutput(),
                           self.callCommand('lsof').getOutput(),
                           self.callCommand('lspci').getOutput(),
                           self.callCommand('lspci -tv').getOutput(),
                           self.callCommand('lspci -tvvv').getOutput(),
                           self.callCommand('lspci -xxxx').getOutput(),
                           self.callCommand('mii-tool -vv').getOutput(),
                           self.callCommand('modprobe sq').getOutput(),
                           self.callCommand('mount').getOutput(),
                           self.callCommand('netstat -anp').getOutput(),
                           self.callCommand('netstat -i').getOutput(),
                           self.callCommand('netstat -nlp').getOutput(),
                           self.callCommand('netstat -nr').getOutput(),
                           self.callCommand('numactl --hardware').getOutput(),
                           self.callCommand('ofed_info').getOutput(),
                           
                           self.callCommand('ompi_info').getOutput(),
                           self.callCommand('perfquery').getOutput(),
                           self.callCommand('ps xfalw').getOutput(),
                           self.callCommand('route -n').getOutput(),

                           self.callCommand('sdpnetstat -anp').getOutput(),
                           self.callCommand('sg_map -i -x').getOutput(),
                           self.callCommand('sysctl -a').getOutput(),
                           self.callCommand('ulimit -a').getOutput(),
                           self.callCommand('uname -a').getOutput(),
                           self.callCommand('uptime').getOutput(),
                           self.callCommand('zcat /proc/config.gz').getOutput(),
                           self.callMethod('zz_proc_net_bonding_files').getOutput(), #implement as method
                           self.callMethod('zz_sys_class_net_files').getOutput(), #implement as method
                           ]

        self.fabric_diagnostics = [
                            self.callMethod('Multicast_Information').getOutput(),#implemented as method
                            self.callCommand('ib-find-bad-ports').getOutput(),
                            self.callMethod('ib-find-disabled-ports').getOutput(),
                            self.callCommand('ib-mc-info-show').getOutput(),
                            self.callCommand('ib-topology-viewer').getOutput(),
                            self.callCommand('ib_diagnet').getOutput(),
                            self.callCommand('ib_switches_FW_scan').getOutput(),
                            self.callCommand('ibcheckerrors -nocolor').getOutput(),
                            self.callCommand('ibhosts').getOutput(),
                            self.callCommand('ibnetdiscover').getOutput(),
                            self.callCommand('ibnetdiscover -p').getOutput(),
                            self.callCommand('ibswitches').getOutput(),
                            self.callCommand('sm-status').getOutput(),
                            self.callCommand('sm_master_is').getOutput(),
                            self.callCommand('sminfo').getOutput(),
                            ]

        self.files = [
                            self.getFileText('/etc/hosts').getOutput(),
                            self.getFileText('/etc/hosts.allow').getOutput(),
                            self.getFileText('/etc/hosts.deny').getOutput(),
                            self.getFileText('/etc/issue').getOutput(),
                            self.getFileText('/etc/modprobe.conf').getOutput(),
                            self.getFileText('/etc/modprobe.d/blacklist-compat').getOutput(),
                            self.getFileText('/etc/modprobe.d/blacklist-firewire').getOutput(),
                            self.getFileText('/etc/modprobe.d/blacklist.conf').getOutput(),
                            self.getFileText('/etc/modprobe.d/mlx4_en.conf').getOutput(),
                            self.getFileText('/etc/modprobe.d/modprobe.conf.dist').getOutput(),
                            self.getFileText('/etc/resolv.conf').getOutput(),
                            self.getFileText('/etc/sysconfig/network-scripts/ifcfg-bond0').getOutput(),
                            self.getFileText('/etc/sysconfig/network-scripts/ifcfg-eth0').getOutput(),
                            self.getFileText('/etc/sysconfig/network-scripts/ifcfg-eth1').getOutput(),
                            self.getFileText('/etc/sysconfig/network-scripts/ifcfg-ib0').getOutput(),
                            self.getFileText('/etc/sysconfig/network-scripts/ifcfg-lo').getOutput(),
                            
                            self.getFileText('/proc/buddyinfo').getOutput(),
                            self.getFileText('/proc/cmdline').getOutput(),
                            self.getFileText('/proc/cpuinfo').getOutput(),
                            self.getFileText('/proc/crypto').getOutput(),
                            self.getFileText('/proc/devices').getOutput(),
                            self.getFileText('/proc/deskstats').getOutput(),
                            self.getFileText('/proc/dma').getOutput(),
                            self.getFileText('/proc/execdomains').getOutput(),
                            self.getFileText('/proc/scsi/scsi').getOutput(),
                            self.getFileText('/proc/slabinfo').getOutput(),
                            self.getFileText('/proc/stat').getOutput(),
                            self.getFileText('/proc/swaps').getOutput(),
                            self.getFileText('/proc/uptime').getOutput(),
                            self.getFileText('/proc/vmstat').getOutput(),
                            self.getFileText('/proc/zoneinfo').getOutput(),
                            
                            self.getFileText('/sys/class/infiniband/*/board_id').getOutput(),
                            self.getFileText('/sys/class/infiniband/*/fw_ver').getOutput(),
                            self.getFileText('/sys/class/infiniband/*/hca_type').getOutput(),
                            self.getFileText('/sys/class/infiniband/*/hw_rev').getOutput(),
                            self.getFileText('/sys/class/infiniband/*/node_desc').getOutput(),
                            self.getFileText('/sys/class/infiniband/*/node_guid').getOutput(),
                            self.getFileText('/sys/class/infiniband/*/node_type').getOutput(),
                            self.getFileText('/sys/class/infiniband/*/sys_image_guid').getOutput(),
                            self.getFileText('/sys/class/infiniband/*/uevent').getOutput(),
                            
                            self.getFileText('/var/log/messages').getOutput(),
							]
	
	def getFileText(self, FQFN):
		'''
		returns a "SysInfoData" structure handled as a file type
		'''
		
		out = UnixCommand('cat {filename}'.format(filename = FQFN).systemCall()[0]
		FDStruct = self.factory.generateFileDataStruct(FQFN, out, 'file')
        return FDStruct
    
    def callMethod(self, method):
		'''
		returns a "SysInfoData" structure handled as a method type
        '''
		m = getattr(self, '{meth}'.format(meth = method))
		out = m()
		MStruct = self.factory.getMethodDataStruct(method, out, 'method')
		return MStruct
                                            
    def callCommand(self, command):
		'''
		returns a "SysInfoData" structure handled as a command type
        '''
        out = UnixCommand('{cmd}'.format(cmd = command)).systemCall()[0]
		CStruct = self.factory.generateCommandDataStruct(command, out, 'command')
		return CStruct
                                            
                                           
    def gzip(file, outputfile):
        f = open(file,r)
        result = UnixCommand('gzip {target} {destination}'.format(target = file, destination = outputfile)
		
class SysInfoDataFactory:
	def __init__(self):
		pass
	
	def generateMethodDataStruct(self, name, output, type):
		return MethodData(name, output, type)
	
	def generateFileDataStruct(self, name, output, type):
		return FileData(name, output, type)
	
	def generateCommandDataStruct(self, name, output, type):
		return CommandData(name, output, type)
class SysInfoData:
	def __init__(self, name, output, type):
		self.name = name
		self.output = output
		self.type = type
		
	def getName(self):
		return self.name

	def getOutput(self):
		return self.output
	
	def getType(self):
		return self.type
class MethodData(SysInfoData):
	pass
class CommandData(SysInfoData):
	pass
class FileData(SysInfoData);
	pass
class App:
    '''
        application interface specific stuff, CLI, GUI, etc
    '''
    def __init__(self):
		self.parser = OptionParser()
		self.system = System()
		self.flav = self.system.linux_flavor
		
		self.VERSION=1.58
		self.PATH = self.system.getPath()
		self.HOST = self.system.getHostname()
		self.XDATE = self.system.getDate()
		self.OFILE = '/tmp/sysinfo-snapshot-{VERSION}-{HOST}-{XDATE}.html'.format(VERSION = self.VERSION,
																				HOST = self.HOST,
																				XDATE = self.XDATE)
		
		appstats = {}
		
		if self.system.operating_system in ['Windows', 'Microsoft']:
			sysinfo = SysinfoSnapshotWin()
		
		else: 
			sysinfo = SysinfoSnapshotUnix(self.flav)
		
		sysinfo.run()


class SysHTMLGenerator:
    def __init__(self, hostname, iterablecontent):
    def sectionfooter(self):
        foot = """<small><a href=\"#sec$((sec - 1))\">[&lt;&lt;prev]</a></small> 
                          <small><a href=\"#index\">[back to index]</a></small> 
                          <small><a href=\"#sec$((sec + 1))\">[next>>]</a></small>"""
        return foot
    
    def fileheader(self, hostname):
        head = """<html><head><title>{hostn}'s Diagnostics</title></head><body><pre>""".format(hostn = hostname)
        return head
    
    def styling(self):
        """
        
    
if __name__ == '__main__':
    pass