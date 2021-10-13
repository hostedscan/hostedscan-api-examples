# Write Open Ports to CSV - nodejs

This example uses the GET /risks API to efficiently fetch all open ports found from nmap TCP and UDP scans - `https://api.hostedscan.com/v1/risks?filters={"status": ["OPEN"],"risk_definition.scan_type": ["NMAP","NMAP_UDP"]}`. The data is written into a file called open_ports.csv. This example shows how to use filtering and pagination features of the HostedScan APIs.

To run the example:
1. Install the dependencies: `npm i`
2. Run the code with your HostedScan API key environment variable: `HOSTEDSCAN_API_KEY=<key> npm run start`
