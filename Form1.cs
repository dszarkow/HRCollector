using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Management;
using System.Windows.Forms;

// Ref: https://www.silabs.com/documents/login/reference-manuals/Bluetooth_Smart_Software-BLE-1.6-API-RM.pdf

namespace BLEHeartRateCollector
{
    public partial class Form1 : Form
    {
        public Bluegiga.BGLib bglib = new Bluegiga.BGLib();
        public Boolean isAttached = false;
        public Dictionary<string, string> portDict = new Dictionary<string, string>();

        /* ================================================================ */
        /*                BEGIN MAIN EVENT-DRIVEN APP LOGIC                 */
        /* ================================================================ */

        // Define the application's "states"
        public const UInt16 STATE_STANDBY = 0;
        public const UInt16 STATE_SCANNING = 1;
        public const UInt16 STATE_CONNECTING = 2;
        public const UInt16 STATE_FINDING_SERVICES = 3;
        public const UInt16 STATE_FINDING_ATTRIBUTES = 4;
        public const UInt16 STATE_LISTENING_MEASUREMENTS = 5;
        
        // Initialize program variables
        public UInt16 app_state = STATE_STANDBY;        // current/starting application state
        public Byte connection_handle = 0;              // connection handle (will always be 0 if only one connection happens at a time)
        public UInt16 att_handlesearch_start = 0;       // "start" handle holder during search
        public UInt16 att_handlesearch_end = 0;         // "end" handle holder during search
        public UInt16 att_handle_measurement = 0;       // heart rate measurement attribute handle
        public UInt16 att_handle_measurement_ccc = 0;   // heart rate measurement client characteristic configuration handle (to enable notifications)

        //-------------------------------------------------------------------------------------------------------------
        // NOTE: The ATTClientProcedureCompletedEvent is automatically triggered at the end of each event handler.
        //       The ATTClientProcedureCompletedEvent examines the "STATE" along with other data and decides
        //       what command to issue next.  In general each command triggers a corresponding event that
        //       performs some work and then triggers the ATTClientProcedureCompletedEvent.
        //-------------------------------------------------------------------------------------------------------------

        //-------------------------------------------------------------------------------------------------------------
        // For master/scanner devices, the "gap_scan_response" event is a common "entry-like" point
        // that filters ad packets to find devices which advertise the Heart Rate service.
        // Other services can be found as well. See https://www.bluetooth.com/specifications/gatt/services 
        // for a list of Service Assigned Numbers (hexadecimal values are used).
        public void GAPScanResponseEvent(object sender, Bluegiga.BLE.Events.GAP.ScanResponseEventArgs e)
        {
            String log = String.Format("ble_evt_gap_scan_response: rssi={0}, packet_type={1}, sender=[ {2}], address_type={3}, bond={4}, data=[ {5}]" + Environment.NewLine,
                (SByte)e.rssi,
                e.packet_type,
                ByteArrayToHexString(e.sender),
                e.address_type,
                e.bond,
                ByteArrayToHexString(e.data)
                );
            Console.Write(log);
            ThreadSafeDelegate(delegate { txtLog.AppendText(log); });

            // Pull all advertised service info from ad packet
            List<Byte[]> ad_services = findAllAdvertisedServices(e.data);
            
            // Check for 0x180D (the official Heart Rate service UUID),
            // using an "extension" method.
            if (ad_services.Any(a => a.SequenceEqual(new Byte[] { 0x18, 0x0D }))) {

                // A device with the Heart Rate service has been found, so 
                // connect to that device, triggering the ConnectionStatus event.

                // See Ref. p. 101, for info. about the Connect Direct command.
                // Parameters are:
                // Byte[] address, Byte addr_type, UInt16 conn_interval_min, UInt16 conn_interval_max, UInt16 timeout, UInt16 latency
                Byte[] cmd = bglib.BLECommandGAPConnectDirect(e.sender, e.address_type, 0x20, 0x30, 0x100, 0); 

                // DEBUG: display bytes written
                ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("=> TX ({0}) [ {1}]", cmd.Length, ByteArrayToHexString(cmd)) + Environment.NewLine); });

                // Send the command, which then triggers the ConnectionStatus event.
                bglib.SendCommand(serialAPI, cmd); 

                // Update the state to "connecting"
                app_state = STATE_CONNECTING;
            }

            // No callback function was specified. A callback function may be used.
            // Only the ConnectionStatus event handler is used in this application.
        }

        //-------------------------------------------------------------------------------------------------------------
        // This code was previously inline as part of the function GAPScanResponseEvent().
        // As it performs a specific task, I've made it a separate function.
        public List<byte[]> findAllAdvertisedServices(byte[] e_data)
        {
            List<byte[]> ad_services = new List<Byte[]>();

            Byte[] this_field = { };
            int bytes_left = 0;
            int field_offset = 0;
            for (int i = 0; i < e_data.Length; i++)
            {
                if (bytes_left == 0)
                {
                    bytes_left = e_data[i];
                    this_field = new Byte[e_data[i]];
                    field_offset = i + 1;
                }
                else
                {
                    this_field[i - field_offset] = e_data[i];
                    bytes_left--;
                    if (bytes_left == 0)
                    {
                        if (this_field[0] == 0x02 || this_field[0] == 0x03)
                        {
                            // partial or complete list of 16-bit UUIDs
                            ad_services.Add(this_field.Skip(1).Take(2).Reverse().ToArray());
                        }
                        else if (this_field[0] == 0x04 || this_field[0] == 0x05)
                        {
                            // partial or complete list of 32-bit UUIDs
                            ad_services.Add(this_field.Skip(1).Take(4).Reverse().ToArray());
                        }
                        else if (this_field[0] == 0x06 || this_field[0] == 0x07)
                        {
                            // partial or complete list of 128-bit UUIDs
                            ad_services.Add(this_field.Skip(1).Take(16).Reverse().ToArray());
                        }
                    }
                }
            }

            return ad_services;
        }

        //-------------------------------------------------------------------------------------------------------------
        // Event handler for the ConnectionStatus event.
        // The "Connection_Status" event occurs when a new connection is established.
        public void ConnectionStatusEvent(object sender, Bluegiga.BLE.Events.Connection.StatusEventArgs e)
        {
            String log = String.Format("ble_evt_connection_status: connection={0}, flags={1}, address=[ {2}], address_type={3}, conn_interval={4}, timeout={5}, latency={6}, bonding={7}" + Environment.NewLine,
                e.connection,
                e.flags,
                ByteArrayToHexString(e.address),
                e.address_type,
                e.conn_interval,
                e.timeout,
                e.latency,
                e.bonding
                );
            Console.Write(log);
            ThreadSafeDelegate(delegate { txtLog.AppendText(log); });

            // Check the flags to see if a connection was completed.
            // Ref: p. 41 for links, see p. 96 for flag values
            if ((e.flags & 0x05) == 0x05)
            {
                // Connected, now perform service discovery.
                // Save the connection_handle value.
                connection_handle = e.connection;
                ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("Connected to {0}", ByteArrayToHexString(e.address)) + Environment.NewLine); });

                // Create the ATTClientReadByGroup command.
                // "service" UUID is 0x2800 (little-endian for UUID uint8array). 
                // Ref: https://www.bluetooth.com/specifications/gatt/declarations
                // Get a "list" of all services provided.
                Byte[] cmd = bglib.BLECommandATTClientReadByGroupType(
                    e.connection, 0x0001, 0xFFFF, new Byte[] { 0x00, 0x28 }); 

                // DEBUG: display bytes written
                ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("=> TX ({0}) [ {1}]", cmd.Length, ByteArrayToHexString(cmd)) + Environment.NewLine); });

                // Send the command, triggering the ATTClientGroupFoundEvent and
                // the ProcedureCompleted event. Ref. p. 53.
                bglib.SendCommand(serialAPI, cmd);
                
                // Update the application state.
                app_state = STATE_FINDING_SERVICES;
            }
        }

        //-------------------------------------------------------------------------------------------------------------
        // Event handler for the ATTClientGroupFoundEvent.
        // Here, a service "group" has been found, and that group must be texted to determine if it is
        // the specific service group we are interested in.
        public void ATTClientGroupFoundEvent(object sender, Bluegiga.BLE.Events.ATTClient.GroupFoundEventArgs e)
        {
            String log = String.Format("ble_evt_attclient_group_found: connection={0}, start={1}, end={2}, uuid=[ {3}]" + Environment.NewLine,
                e.connection,
                e.start,
                e.end,
                ByteArrayToHexString(e.uuid)
                );
            Console.Write(log);
            ThreadSafeDelegate(delegate { txtLog.AppendText(log); });

            // Since we were searching for "service" attribute groups (UUID=0x2800), we must have found
            // a "service" attribute groups (UUID=0x2800).
            // Check the returned e.uuid list for the Heart Rate Measurement service.
            // Ref: https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.service.heart_rate.xml
            // This uses an "extension" method defined in System.Linq.IEnumerable.
            if (e.uuid.SequenceEqual(new Byte[] { 0x0D, 0x18 }))  // Little-endian
            {
                // Fount the Heart Rate service, so save the attribute group start and end "indices'.
                ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("Found attribute group for service w/UUID=0x180D: start={0}, end=%d", e.start, e.end) + Environment.NewLine); });
                att_handlesearch_start = e.start; // Start of attribute group
                att_handlesearch_end = e.end;     // End of attribute group
            }
        }

        //-------------------------------------------------------------------------------------------------------------
        // Event handler for the ATTClientFindInformationFound Event.
        // Here, a characteristics "group" has been found, and that group must be texted to determine if it is
        // the specific characteristics group we are interested in.
        public void ATTClientFindInformationFoundEvent(object sender, Bluegiga.BLE.Events.ATTClient.FindInformationFoundEventArgs e)
        {
            String log = String.Format("ble_evt_attclient_find_information_found: connection={0}, chrhandle={1}, uuid=[ {2}]" + Environment.NewLine,
                e.connection,
                e.chrhandle,
                ByteArrayToHexString(e.uuid)
                );
            Console.Write(log);
            ThreadSafeDelegate(delegate { txtLog.AppendText(log); });

            // Check for the specific heart rate measurement characteristic (UUID=0x2A37).
            // Ref: https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.characteristic.heart_rate_measurement.xml
            // using the extension method SequenceEqual
            if (e.uuid.SequenceEqual(new Byte[] { 0x37, 0x2A }))
            {
                // Fount the desired charatceristic, so now record the characteristic's handle
                ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("Found attribute w/UUID=0x2A37: handle={0}", e.chrhandle) + Environment.NewLine); });
                att_handle_measurement = e.chrhandle;
            }
            // Previously found the desired characteristic, so now
            // check for subsequent client characteristic configuration (UUID=0x2902).
            // Ref: https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.descriptor.gatt.client_characteristic_configuration.xml
            else if (e.uuid.SequenceEqual(new Byte[]  { 0x02, 0x29 }) && att_handle_measurement > 0)
            {
                // Previously found the desired characteristic, 
                // so now record the client characteristic configuration handle.
                ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("Found attribute w/UUID=0x2902: handle={0}", e.chrhandle) + Environment.NewLine); });

                att_handle_measurement_ccc = e.chrhandle;
            }
        }

        //-------------------------------------------------------------------------------------------------------------
        // Event handler for the ATTClientProcedureCompleted event.
        // This function responds to the current asata and any input data.
        public void ATTClientProcedureCompletedEvent(object sender, Bluegiga.BLE.Events.ATTClient.ProcedureCompletedEventArgs e)
        {
            String log = String.Format("ble_evt_attclient_procedure_completed: connection={0}, result={1}, chrhandle={2}" + Environment.NewLine,
                e.connection,
                e.result,
                e.chrhandle
                );
            Console.Write(log);
            ThreadSafeDelegate(delegate { txtLog.AppendText(log); });

            // Check if we just finished searching for services.
            if (app_state == STATE_FINDING_SERVICES)
            {
                // Did we find the service we were looking for?
                if (att_handlesearch_end > 0)
                {
                    //print "Found 'Heart Rate' service with UUID 0x180D"

                    // Yes, we found the Heart Rate service, so now search for the attributes of that service, 
                    // triggering the ATTClientFindInformationFound event.
                    
                    // Create the command.
                    Byte[] cmd = bglib.BLECommandATTClientFindInformation(e.connection, att_handlesearch_start, att_handlesearch_end);
                    // DEBUG: display bytes written
                    ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("=> TX ({0}) [ {1}]", cmd.Length, ByteArrayToHexString(cmd)) + Environment.NewLine); });

                    // Send the command
                    bglib.SendCommand(serialAPI, cmd);

                    // Update the current state.
                    app_state = STATE_FINDING_ATTRIBUTES;
                }
                else
                {
                    ThreadSafeDelegate(delegate { txtLog.AppendText("Could not find 'Heart Rate' service with UUID 0x180D" + Environment.NewLine); });
                }
            }
            // check if we just finished searching for attributes within the Heart Rate service
            else if (app_state == STATE_FINDING_ATTRIBUTES)
            {
                if (att_handle_measurement_ccc > 0)
                {
                    //print "Found 'Heart Rate' measurement attribute with UUID 0x2A37"

                    // Yes, we found the measurement + client characteristic configuration values,
                    // so enable notifications. This is done by writing 0x0001 to the client characteristic configuration attribute.
                    // Notifications trigger the  ATTClientAttributeValueEvent.

                    // Create the command.
                    Byte[] cmd = bglib.BLECommandATTClientAttributeWrite(e.connection, att_handle_measurement_ccc, new Byte[] { 0x01, 0x00 });
                    // DEBUG: display bytes written
                    ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("=> TX ({0}) [ {1}]", cmd.Length, ByteArrayToHexString(cmd)) + Environment.NewLine); });

                    // Send the command.
                    bglib.SendCommand(serialAPI, cmd);

                    // Update the current application state.
                    app_state = STATE_LISTENING_MEASUREMENTS;
                }
                else
                {
                    ThreadSafeDelegate(delegate { txtLog.AppendText("Could not find 'Heart Rate' measurement attribute with UUID 0x2A37" + Environment.NewLine); });
                }
            }
        }

        //-------------------------------------------------------------------------------------------------------------
        // Event handler for the ATTClientAttributeValue event, 
        // triggered when a new attribute value is sent to this application.
        public void ATTClientAttributeValueEvent(object sender, Bluegiga.BLE.Events.ATTClient.AttributeValueEventArgs e)
        {
            String log = String.Format("ble_evt_attclient_attribute_value: connection={0}, atthandle={1}, type={2}, value=[ {3}]" + Environment.NewLine,
                e.connection,
                e.atthandle,
                e.type,
                ByteArrayToHexString(e.value)
                );
            Console.Write(log);
            ThreadSafeDelegate(delegate { txtLog.AppendText(log); });

            // Check for a new value from the connected peripheral's heart rate measurement attribute.
            if (e.connection == connection_handle && e.atthandle == att_handle_measurement)
            {
                // The first byte of heart rate record contains a set of flags.
                byte flags = e.value[0];

                //---------------------------------------------------------------------------------
                // Code to get the RR intervalues
                // Ref: https://stackoverflow.com/questions/17422218/bluetooth-low-energy-how-to-parse-r-r-interval-value

                ushort offset = 1;

                int hrValue = 0;

                bool HRC2 = (flags & 1) == 1;
                if (HRC2) //this means the BPM is un uint16
                {
                    short hr = BitConverter.ToInt16(e.value, offset);
                    offset += 2;

                    hrValue = hr;
                }
                else //BPM is uint8
                {
                    byte hr = e.value[offset];
                    offset += 1;

                    hrValue = hr;
                }

                //see if EE is available
                //if so, pull 2 bytes
                bool ee = (flags & (1 << 3)) != 0;
                if (ee)
                    offset += 2;

                //see if RR is present
                //if so, the number of RR values is total bytes left / 2 (size of uint16)
                bool rr = (flags & (1 << 4)) != 0;
                int countRR = 0;
                List<double> rrIntervalList = new List<double>();

                if (rr)
                {
                    countRR = (e.value.Length - offset) / 2;
                    for (int i = 0; i < countRR; i++)
                    {
                        //each existence of these values means an R-Wave was already detected
                        //the ushort means the time (1/1024 seconds) since last r-wave
                        ushort value = BitConverter.ToUInt16(e.value, offset);

                        double intervalLengthInSeconds = value / 1024.0;
                        offset += 2;

                        rrIntervalList.Add(intervalLengthInSeconds);
                    }
                }
                //---------------------------------------------------------------------------------

                // The Heart Rate value in BPM is the second byte
                int hr_measurement = e.value[1];

                // Display the Heart rate and RR interval values here.
                string msg = "Heart rate: " + hr_measurement + Environment.NewLine + "CountRR: " + countRR + Environment.NewLine;
                for (int k = 0; k < countRR; k++)
                    msg += rrIntervalList[k] + " seconds" + Environment.NewLine;
                msg += Environment.NewLine;

                ThreadSafeDelegate(delegate { txtLog.AppendText(msg);});

                //ThreadSafeDelegate(delegate { txtLog.AppendText(
                //    String.Format("Heart rate: {0} bpm", hr_measurement) + Environment.NewLine); });
            }
        }

        /* ================================================================ */
        /*                 END MAIN EVENT-DRIVEN APP LOGIC                  */
        /* ================================================================ */

        //-------------------------------------------------------------------------------------------------------------
        // Thread-safe operations from event handlers.
        // "method" is specified as: delegate { // Your GUI modifying code goes here... }
        // See a few lines above for an example.
        // I love StackOverflow: http://stackoverflow.com/q/782274
        public void ThreadSafeDelegate(MethodInvoker method)
        {
            if (InvokeRequired)
                BeginInvoke(method);
            else
                method.Invoke();
        }

        //-------------------------------------------------------------------------------------------------------------
        // A utility function to convert a byte array containing hex-like values to a "00 11 22 33 44 55 " string.
        public string ByteArrayToHexString(Byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2); // Because each element of ba contains two values.

            foreach (byte b in ba)
                hex.AppendFormat("{0:x2} ", b);  // Convert hex to string here.

            return hex.ToString();
        }

        //-------------------------------------------------------------------------------------------------------------
        // Serial port event handler for a nice event-driven architecture
        private void DataReceivedHandler(
                                object sender,
                                System.IO.Ports.SerialDataReceivedEventArgs e)
        {
            System.IO.Ports.SerialPort sp = (System.IO.Ports.SerialPort)sender;
            Byte[] inData = new Byte[sp.BytesToRead];

            // Read all available bytes from serial port in one chunk
            sp.Read(inData, 0, sp.BytesToRead);

            // DEBUG: display bytes read
            ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("<= RX ({0}) [ {1}]", inData.Length, ByteArrayToHexString(inData)) + Environment.NewLine); });

            // Parse all bytes read through BGLib parser - This automatically triggers other events.
            for (int i = 0; i < inData.Length; i++)
            {
                bglib.Parse(inData[i]);
            }
        }

        //-------------------------------------------------------------------------------------------------------------
        public Form1()
        {
            InitializeComponent();
        }

        //-------------------------------------------------------------------------------------------------------------
        private void Form1_Load(object sender, EventArgs e)
        {
            // Initialize list of ports
            btnRefresh_Click(sender, e);

            // Initialize COM port combobox with list of ports
            comboPorts.DataSource = new BindingSource(portDict, null);
            comboPorts.DisplayMember = "Value";
            comboPorts.ValueMember = "Key";

            // Initialize serial port with all of the normal values (should work with BLED112 on USB)
            serialAPI.Handshake = System.IO.Ports.Handshake.RequestToSend;
            serialAPI.BaudRate = 115200;
            serialAPI.DataBits = 8;
            serialAPI.StopBits = System.IO.Ports.StopBits.One;
            serialAPI.Parity = System.IO.Ports.Parity.None;
            serialAPI.DataReceived += new System.IO.Ports.SerialDataReceivedEventHandler(DataReceivedHandler);

            // Initialize BGLib events we'll need for this script
            bglib.BLEEventGAPScanResponse += new Bluegiga.BLE.Events.GAP.ScanResponseEventHandler(this.GAPScanResponseEvent);
            bglib.BLEEventConnectionStatus += new Bluegiga.BLE.Events.Connection.StatusEventHandler(this.ConnectionStatusEvent);
            bglib.BLEEventATTClientGroupFound += new Bluegiga.BLE.Events.ATTClient.GroupFoundEventHandler(this.ATTClientGroupFoundEvent);
            bglib.BLEEventATTClientFindInformationFound += new Bluegiga.BLE.Events.ATTClient.FindInformationFoundEventHandler(this.ATTClientFindInformationFoundEvent);
            bglib.BLEEventATTClientProcedureCompleted += new Bluegiga.BLE.Events.ATTClient.ProcedureCompletedEventHandler(this.ATTClientProcedureCompletedEvent);
            bglib.BLEEventATTClientAttributeValue += new Bluegiga.BLE.Events.ATTClient.AttributeValueEventHandler(this.ATTClientAttributeValueEvent);
        }

        //-------------------------------------------------------------------------------------------------------------
        private void btnRefresh_Click(object sender, EventArgs e)
        {
            // Create a list of all available ports on the system
            portDict.Clear();
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_SerialPort");

                foreach (ManagementObject queryObj in searcher.Get())
                {
                    portDict.Add(String.Format("{0}", queryObj["DeviceID"]), String.Format("{0} - {1}", queryObj["DeviceID"], queryObj["Caption"]));
                }
            }
            catch (ManagementException ex)
            {
                portDict.Add("0", "Error " + ex.Message);
            }
        }

        //-------------------------------------------------------------------------------------------------------------
        private void btnAttach_Click(object sender, EventArgs e)
        {
            if (!isAttached)
            {
                txtLog.AppendText("Opening serial port '" + comboPorts.SelectedValue.ToString() + "'..." + Environment.NewLine);
                serialAPI.PortName = comboPorts.SelectedValue.ToString();
                serialAPI.Open();
                txtLog.AppendText("Port opened" + Environment.NewLine);
                isAttached = true;
                btnAttach.Text = "Detach";
                btnGo.Enabled = true;
                btnReset.Enabled = true;
            }
            else
            {
                txtLog.AppendText("Closing serial port..." + Environment.NewLine);
                serialAPI.Close();
                txtLog.AppendText("Port closed" + Environment.NewLine);
                isAttached = false;
                btnAttach.Text = "Attach";
                btnGo.Enabled = false;
                btnReset.Enabled = false;
            }
        }

        //-------------------------------------------------------------------------------------------------------------
        private void btnGo_Click(object sender, EventArgs e)
        {
            // Start the scan/connect process now.

            // Declare an array to hold the command bytes.
            Byte[] cmd;

            // Set the scan parameters.
            cmd = bglib.BLECommandGAPSetScanParameters(0xC8, 0xC8, 1); // 125ms interval, 125ms window, active scanning
            // DEBUG: display bytes read
            ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("=> TX ({0}) [ {1}]", cmd.Length, ByteArrayToHexString(cmd)) + Environment.NewLine); });

            // Send the command.
            bglib.SendCommand(serialAPI, cmd);

            // Begin scanning for BLE peripherals
            cmd = bglib.BLECommandGAPDiscover(1); // generic discovery mode
            // DEBUG: display bytes read
            ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("=> TX ({0}) [ {1}]", cmd.Length, ByteArrayToHexString(cmd)) + Environment.NewLine); });

            // Send the command.
            bglib.SendCommand(serialAPI, cmd);

            // Update the application state.
            app_state = STATE_SCANNING;

            // Disable the "GO" button since we already started, and 
            // sending the same commands again sill not work right.
            btnGo.Enabled = false;
        }

        //-------------------------------------------------------------------------------------------------------------
        private void btnReset_Click(object sender, EventArgs e)
        {
            // Stop everything we're doing, if possible.

            // Declare an array to hold the command bytes.
            Byte[] cmd;

            // Disconnect if connected
            cmd = bglib.BLECommandConnectionDisconnect(0);
            // DEBUG: display bytes read
            ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("=> TX ({0}) [ {1}]", cmd.Length, ByteArrayToHexString(cmd)) + Environment.NewLine); });

            // Send the command
            bglib.SendCommand(serialAPI, cmd);

            // Stop scanning if we are scanning.
            cmd = bglib.BLECommandGAPEndProcedure();
            // DEBUG: display bytes read
            ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("=> TX ({0}) [ {1}]", cmd.Length, ByteArrayToHexString(cmd)) + Environment.NewLine); });

            // Send the command.
            bglib.SendCommand(serialAPI, cmd);

            // Stop advertising if we are advertising.
            cmd = bglib.BLECommandGAPSetMode(0, 0);
            // DEBUG: display bytes read
            ThreadSafeDelegate(delegate { txtLog.AppendText(String.Format("=> TX ({0}) [ {1}]", cmd.Length, ByteArrayToHexString(cmd)) + Environment.NewLine); });

            // Send the command.
            bglib.SendCommand(serialAPI, cmd);

            // Enable the "GO" button to allow the user to start again.
            btnGo.Enabled = true;

            // Update the application state.
            app_state = STATE_STANDBY;
        }
    }
}