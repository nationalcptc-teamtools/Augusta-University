## Installation
pip install pymodbus

## Importing Neccessary Modules
from pymodbus.client.sync import ModbusTcpClient
from pymodbus.client.sync import ModbusUdpClient
from pymodbus.payload import BinaryPayloadDecoder, BinaryPayloadBuilder
from pymodbus.constants import Endian

## Modbus TCP Client
# Create a Modbus TCP client
client = ModbusTcpClient('localhost', port=502)

# Connect to the Modbus server
client.connect()

# Read holding registers
result = client.read_holding_registers(address, count, unit=unit)
print(result.registers)

# Write a single register
client.write_register(address, value, unit=unit)

# Disconnect from the Modbus server
client.close()

## Modbus UDP Client
# Create a Modbus UDP client
client = ModbusUdpClient('localhost', port=502)

# Read input registers
result = client.read_input_registers(address, count, unit=unit)
print(result.registers)

# Write multiple registers
builder = BinaryPayloadBuilder(endian=Endian.Big)
builder.add_32bit_float(value)
client.write_registers(address, builder.to_registers(), unit=unit)

## Modbus Payload Decoding
# Example: Decoding a 32-bit float
decoder = BinaryPayloadDecoder.fromRegisters(result.registers, byteorder=Endian.Big)
decoded_value = decoder.decode_32bit_float()
print(decoded_value)
