package backend

// NextSOASerial returns the serial value that ZoneStore implementations use
// when creating a new zone or advancing an existing SOA serial.
func NextSOASerial(currentSerial uint32) uint32 {
	return generateSerial(currentSerial)
}
