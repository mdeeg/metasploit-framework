# -*- coding: binary -*-
module Msf
class Post
module Hardware
module Automotive

module KWP2000onCAN

# KWP2000 on CAN
# based on information of the T7Suite for Saab Trionic 7 ECUs (https://github.com/mattiasclaesson/T7Suite/)

# service ID codes
START_COMMUNICATION = 0x81
STOP_COMMUNICATION = 0x82
ACCESS_TIMING_PARAMETERS = 0x83
TESTER_PRESENT = 0x3E
START_DIAGNOSTIC_SESSION = 0x10
SECURITY_ACCESS = 0x27
ECU_RESET = 0x11
READ_ECU_IDENTIFICATION = 0x1A
READ_DATA_BY_LOCALIDENTIFIER = 0x21
READ_DATA_BY_COMMONIDENTIFIER = 0x22
READ_MEMORY_BY_ADDRESS = 0x23
DYNAMICALLY_DEFINE_LOCAL_IDENTIFIER = 0x2C
WRITE_DATA_BY_LOCAL_IDENTIFIER = 0x2C
WRITE_DATA_BY_COMMON_IDENTIFIER = 0x2E
WRITE_MEMORY_BY_ADDRESS = 0x3D
READ_DIAGNOSTIC_TROUBLE_CODES_BY_STATUS = 0x18
READ_STATUS_OF_DIAGNOSTIC_TROUBLE_CODES = 0x17
READ_FREEZE_FRAME_DATA = 0x12
CLEAR_DIAGNOSTIC_INFORMATION = 0x14
INPUT_OUTPUT_CONTROL_BY_LOCAL_IDENTIFIER = 0x30
INPUT_OUTPUT_CONTROL_BY_COMMON_IDENTIFIER = 0x2F
START_ROUTINE_BY_LOCAL_IDENTIFIER = 0x31
START_ROUTINE_BY_ADDRESS = 0x38
STOP_ROUTINE_BY_LOCAL_IDENTIFIER = 0x32
STOP_ROUTINE_BY_ADDRESS = 0x39
REQUEST_ROUTINE_RESULTS_BY_LOCAL_IDENTIFIER = 0x33
REQUEST_ROUTINE_RESULTS_BY_ADDRESS = 0x3A
REQUEST_DOWNLOAD = 0x34
REQUEST_UPLOAD = 0x35
TRANSFER_DATA = 0x36
REQUEST_TRANSFER_EXIT = 0x37

# TARGET CODES
TARGET_NONE = 0x00
TARGET_EHU = 0x91
TARGET_SID = 0x96
TARGET_ACC = 0x98
TARGET_MIU = 0x9A
TARGET_TWICE = 0x9B
TARGET_TRIONIC = 0xA1

# INIT CODES
INIT_EHU = 0x81
INIT_SID = 0x65
INIT_ACC = 0x98
INIT_MIU = 0x61
INIT_TWICE = 0x45
INIT_TRIONIC = 0x11
INIT_CDC = 0x28

# RESPONSE CODES
GENERAL_REJECT = 0x10
SERVICE_NOT_SUPPORTED = 0x11
SUBFUNCTION_NOT_SUPPORTED = 0x12
BUSY_REPEAT_REQUEST = 0x21
CONDITIONS_NOT_CORRECT_OR_REQUESTS_EQ_ERROR = 0x22
ROUTINE_NOT_COMPLETE_OR_SERVICE_IN_PROGRESS = 0x23
REQUEST_OUT_OF_RANGE = 0x31
SECURITY_ACCESS_DENIED = 0x33
INVALID_KEY = 0x35
EXCEED_NUMBER_OF_ATTEMPTS = 0x36
REQUIRED_TIME_DELAY_NOT_EXPIRED = 0x37
DOWNLOAD_NOT_ACCEPTED = 0x40
IMPROPER_DOWNLOAD_TYPE = 0x41
CANNOT_DOWNLOAD_TO_SPECIFIED_ADDRESS = 0x42
CANNOT_DOWNLOAD_NUMBER_OF_BYTES_REQUESTED = 0x43
UPLOAD_NOT_ACCEPTED = 0x50
IMPROPER_UPLOAD_TYPE = 0x51
CANNOT_UPLOAD_FROM_SPECIFIED_ADDRESS = 0x52
CANNOT_UPLOAD_NUMBER_OF_BYTES_REQUESTED = 0x53
TRANSFER_SUSPENDED = 0x71
TRANSFER_ABORTED = 0x72
ILLEGAL_ADDRESS_IN_BLOCK_TRANSFER = 0x74
ILLEGAL_BYTE_COUNT_IN_BLOCK_TRANSFER = 0x75
ILLEGAL_BLOCK_TRANSFER_TYPE = 0x76
BLOCK_TRANSFER_DATA_CHECKSUM_ERROR = 0x77
REQ_CORRECT_LYRCVD_RSPPENDING = 0x78
INCORRECT_BYTE_COUNT_DURING_BLOCK_TRANSFER = 0x79
SERVICE_NOT_SUPPORTED_INACTIVE_DIAG_SESSION = 0x80
NEGATIVE_RESPONSE = 0x7F
POSITIVE_RESPONSE = 0x100
RESPONSE_TIMEOUT = 0x101


#
# Send KWP2000 request over CAN
#
# @param bus [String] unique CAN bus identifier
# @param srcId [Integer] Integer representation of the Sending CAN ID
# @param dstId [Integer] Integer representation of the receiving CAN ID
# @param target [Integer] Integer representation of the KWP2000 target code 
# @param serviceId [Integer] Integer representation of the KWP2000 service ID
# @param data [Array] KWP message data
# @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
#
# @return [Hash] client.automotive response
def send_kwp2000_request(bus, srcId, dstId, target, serviceId, data, opt={})
  if not client.automotive
    print_error("Not an automotive hwbridge session")
    return {}
  end
  srcId = srcId.to_s(16)
  dstId = dstId.to_s(16)
  bus = client.automotive.active_bus if not bus
  if not bus
    print_line("No active bus, use 'connect' or specify bus via the options")
    return {}
  end

  bytes = data[0..data.length]                    # parameter bytes
  data = Array.new(8, 0)                          # message data (8 bytes)
  rowCount = (bytes.length + 1) / 6               # number of rows

  response_data = Array.new                       # all response dah
  receivedRowCount = 0                            # number of received in responsta
  receivedLen = 0                                 # received lengte
  receivedCount = 0

  # process all messages (rows)
  rowCount.downto(0) do |row|
    # treat first message (row) differently than the others
    if (row.to_i == rowCount)
      data[0] = row.to_i | 0x40                   # row number
      data[1] = target                            # target
      data[2] = bytes.length + 1                  # add service ID to length
      data[3] = serviceId                         # service ID

      # set parameter bytes
      for i in 0..3 do
        if bytes.empty?
          data[4 + i] = 0x00                      # zerohttps://github.com/mattiasclaesson/T7Suitei padding
        else
          data[4 + i] = bytes.shift               # parameter bytes
        end
      end
    else
      data[0] = row.to_i                          # row number
      data[1] = target                            # target

      # set parameter bytes
      for i in 2..7 do
        if not bytes.empty?
          data[i] = bytes.shift                   # parameter bytes
        else
          data[i] = 0x00                          # zero padding
        end
      end
    end

    # send KWP2000 request
    response = client.automotive.cansend_and_wait_for_response(bus, srcId, dstId, data, opt)

    if response.has_key? "Packets" and response["Packets"].size > 0
      data = response["Packets"][0]["DATA"]
    else
      return {}
    end

    # get number of rows in response
    receivedRowCount = data[0].hex & ~0xC0

    # check response
    if data[3].hex == NEGATIVE_RESPONSE
      print_error("Received negative KWP2000 response")
      print_error("#{data}")
      return {}
    elsif (data[3].hex & ~0x40) == serviceId
      # get length of data in response
      receivedLen = data[2].hex - 1               # subtract one for service ID
      receivedCount = 0
      for i in 0..3 do 
        if (receivedLen - receivedCount) > 0
          response_data.push(data[4 + i])
          receivedCount += 1
        end
      end
    else
      print_error("Received malformed response")
      return {}
    end

    # acknowledge received message and receive further response rows, if available
    while (receivedRowCount > 0)
      # send acknowledge message for specific row
      ack_message = [0x40, TARGET_TRIONIC, 0x3F, 0x80 | receivedRowCount, 0x00, 0x00, 0x00, 0x00]
      response = client.automotive.cansend_and_wait_for_response(bus, 266, dstId, ack_message, opt)

      if response.has_key? "Packets" and response["Packets"].size > 0
        data = response["Packets"][0]["DATA"]
      else
        return {}
      end

      # get received row count
      receivedRowCount = data[0].hex & ~0xC0

      # append received data to response data buffer
      data[2..7].each do |b|
        response_data.push(b)
      end
    end
  end

  # return response data buffer
  response_data[0..receivedLen - 1]
end


#
# Send raw KWP2000 request over CAN
#
# @param bus [String] unique CAN bus identifier
# @param srcId [Integer] Integer representation of the Sending CAN ID
# @param dstId [Integer] Integer representation of the receiving CAN ID
# @param data [Array] raw KWP message data
# @param opt [Hash] Additional options to be passed to automotive.send_isotp_and_wait_for_response
#
# @return [Hash] client.automotive response
def send_raw_kwp2000_request(bus, srcId, dstId, data, opt={})
  if not client.automotive
    print_error("Not an automotive hwbridge session")
    return {}
  end
  srcId = srcId.to_s(16)
  dstId = dstId.to_s(16)
  bus = client.automotive.active_bus if not bus
  if not bus
    print_line("No active bus, use 'connect' or specify bus via the options")
    return {}
  end

  client.automotive.cansend_and_wait_for_response(bus, srcId, dstId, data, opt)
end


#
# Start KWP2000 session (only tested on Trionic 7)
#
# @param bus [String] unique CAN bus identifier
#
# @return [Hash] client.automotive response
def start_kwp2000_session(bus)
  print_status("Start KWP2000 session")
  start_session_request = [0x3F, 0x81, 0x00, 0x11, 0x02, 0x40, 0x00, 0x00]
  packets = send_raw_kwp2000_request(bus, 0x220, 0x238, start_session_request, {"MAXPKTS" => 1})
end


end
end
end
end
end
