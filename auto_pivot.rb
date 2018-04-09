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
		OptAddress.new('RHOST',    [true, 'IP address of pivot computer (our side IP)'])
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

	def windows_pivot()
		#
		# Windows commands
		#
		if is_admin?
		
			rra_status = service_info("RemoteAccess")
			
			# iprouting_status = --> Valor inicial del registro IPEnableRouter
			# print_status("Initial values:")
			# print_line("	El servicio RRA se encuentra #{rra_status}")
			# print_line("	El valor de IPEnableRouter es #{iprouting_status}")
			# https://www.offensive-security.com/metasploit-unleashed/api-calls/
			# Lee las interfaces de red
			# print_status(client.net.config.interfaces)
			
			print_status("status: #{service_info("RemoteAccess")[:status].to_s}")
			print_status(service_info("RemoteAccess").to_s)
			# print_status("Enabling IP Router...")
			# print_good(cmd_exec("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /f /v IPEnableRouter /t REG_DWORD /d 1"))
			# print_status("Enabling Routing and Remote Access service...")
			# print_good(cmd_exec("sc config RemoteAccess start= auto"))
			# print_status("Starting Routing and Remote Access service...")
			# print_good(cmd_exec("net start RemoteAccess"))
		else
			print_bad("You have to be administrator to execute this module.")
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
			# create_route()
			#para saber si las rutas son correctas
			print_status("windows: route -p add #{get_net(datastore['NET'])} mask #{get_netmask(datastore['NET'])} METRIC 1")
			print_status("linux: route add -net #{datastore['NET']} gw #{datastore['RHOST']}")
		else
			print_bad("Aborting Module.")
		end
			
  	end
end

# Service_info
		#{:starttype=>2, :display=>"Routing and Remote Access", :startname=>"LocalSystem", :path=>"C:\\WINDOWS\\system32\\svchost.exe -k netsvcs", :logroup=>"", :interactive=>false, :dacl=>"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CR;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)", :status=>4}
