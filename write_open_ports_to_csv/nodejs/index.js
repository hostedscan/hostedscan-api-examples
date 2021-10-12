const axios = require('axios');
const fs = require('fs');

const csv_filename = 'open_ports.csv';
const key = process.env.HOSTEDSCAN_API_KEY;

if (!key) {
  throw Error('HOSTEDSCAN_API_KEY environment variable must be defined!');
}

const hostedscan = 'https://api.hostedscan.com/v1';
const headers = { 'x-hostedscan-api-key': key };

async function list_open_ports(page_token) {
  const params = { page_token: page_token, filters: { 'risk_definition.scan_type': ['NMAP', 'NMAP_UDP'], status: ['OPEN'] } };
  return await axios.get(`${hostedscan}/risks`, { params: params, headers: headers })
  .then((res) => {
    return res.data;
  })
  .catch((err) => {
    console.log({ status: err.response.status, ...err.response.data });
  });
}

async function main() {
  fs.writeFileSync(csv_filename, 'target,port\n');
  const stream = fs.createWriteStream(csv_filename, { flags: 'a' });

  let next_page_token = undefined;
  do {
    open_ports = await list_open_ports(next_page_token);
    open_ports.data.forEach(port => {
      stream.write(`${port.target},${port.risk_definition.title}\n`);
    });
    next_page_token = open_ports.next_page_token;
  } while (next_page_token)

  stream.end();
}
main();