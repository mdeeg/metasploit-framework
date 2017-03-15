##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/post/hardware/automotive/kwp2000'

class MetasploitModule < Msf::Post

  include Msf::Post::Hardware::Automotive::KWP2000

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
  # @param bus [String] service ID
  # @param bus [String] parameter ID (PID)
  #
  # @return [String] engine type
  def read_dtc_codes(bus)
    response = send_kwp2000_request(bus, 0x240, 0x258, TARGET_TRIONIC, READ_DIAGNOSTIC_TROUBLE_CODES_BY_STATUS, [], {"MAXPKTS" => 1})
    if response.size > 0
      response
    else
      return nil
    end
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
  end
end
