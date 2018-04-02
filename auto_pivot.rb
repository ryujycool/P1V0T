##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'rex'
class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'to add here',
        'Description'   => %q{alguna descripcion},
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
		OptBool.new( 'SYSTEMINFO', [ true, 'True if you want to get system info', 'TRUE' ])
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
		if systeminfo == TRUE
		print_good("OS: #{session.sys.config.sysinfo['OS']}")
		print_good("Computer name: #{'Computer'} ")
		print_good("Current user: #{session.sys.config.getuid}")
		print_line('')
		end
  end
end
